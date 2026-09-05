//! Explicit, role-scoped files or environment keys. Errors never echo material.
use crate::http::Origin;
use biscuit_auth::{Algorithm, KeyPair, PrivateKey, PublicKey};
use gnap_crypto::Ps256Signer;
use rsa::pkcs8::EncodePrivateKey;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};
type Error = Box<dyn std::error::Error>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    As,
    Rs,
    Client,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Origins,
    Keys,
}
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Origins => "invalid or incomplete origin configuration",
            Self::Keys => "invalid, ambiguous or incomplete key configuration",
        })
    }
}
impl std::error::Error for ConfigError {}
const MATERIALS: &[(Role, &str, &str)] = &[
    (Role::As, "BISCUIT_AS_ROOT_PRIVATE_KEY_HEX", "root.key"),
    (Role::As, "BISCUIT_AS_CLIENT_PUBLIC_JWK", "client.jwk"),
    (Role::As, "BISCUIT_AS_RS_PUBLIC_JWK", "rs.jwk"),
    (Role::Rs, "BISCUIT_RS_PRIVATE_KEY_PEM", "rs.pem"),
    (Role::Rs, "BISCUIT_RS_ROOT_PUBLIC_KEY_HEX", "root.pub"),
    (Role::Client, "BISCUIT_CLIENT_PRIVATE_KEY_PEM", "client.pem"),
    (
        Role::Client,
        "BISCUIT_CLIENT_ROOT_PUBLIC_KEY_HEX",
        "root.pub",
    ),
];
const MAX_KEY_BYTES: usize = 65536;
pub struct Config {
    pub as_origin: Origin,
    pub rs_origin: Origin,
    pub client_origin: Origin,
    keys: BTreeMap<String, String>,
}
impl Config {
    pub fn load(role: Role) -> Result<Self, ConfigError> {
        Self::load_with(
            role,
            |name| std::env::var(name).ok(),
            |name| std::env::var_os(name).is_some(),
            |path| {
                let mut value = String::new();
                fs::File::open(path)
                    .map_err(|_| ConfigError::Keys)?
                    .take((MAX_KEY_BYTES + 1) as u64)
                    .read_to_string(&mut value)
                    .map_err(|_| ConfigError::Keys)?;
                Ok(value)
            },
        )
    }
    /// Presence is queried separately: foreign-role variables are rejected before
    /// material lookup or crypto parsing. Tests never mutate process env state.
    pub fn load_with(
        role: Role,
        mut lookup: impl FnMut(&str) -> Option<String>,
        mut present: impl FnMut(&str) -> bool,
        mut read_file: impl FnMut(&Path) -> Result<String, ConfigError>,
    ) -> Result<Self, ConfigError> {
        if MATERIALS
            .iter()
            .any(|(owner, name, _)| *owner != role && present(name))
        {
            return Err(ConfigError::Keys);
        }
        let source = match lookup("KEY_SOURCE") {
            Some(source) => source,
            None if present("KEY_SOURCE") => return Err(ConfigError::Keys),
            None => "directory".into(),
        };
        let directory = lookup("KEY_DIRECTORY");
        let mut keys = BTreeMap::new();
        match source.as_str() {
            "environment" => {
                if present("KEY_DIRECTORY") {
                    return Err(ConfigError::Keys);
                }
                for (_, name, file) in MATERIALS.iter().filter(|(owner, _, _)| *owner == role) {
                    keys.insert((*file).into(), lookup(name).ok_or(ConfigError::Keys)?);
                }
            }
            "directory" => {
                if MATERIALS.iter().any(|(_, name, _)| present(name)) {
                    return Err(ConfigError::Keys);
                }
                let directory = directory
                    .filter(|d| !d.trim().is_empty())
                    .ok_or(ConfigError::Keys)?;
                for (_, _, file) in MATERIALS.iter().filter(|(owner, _, _)| *owner == role) {
                    keys.insert(
                        (*file).into(),
                        read_file(&Path::new(&directory).join(file))?,
                    );
                }
            }
            _ => return Err(ConfigError::Keys),
        }
        if keys
            .values()
            .any(|value| value.trim().is_empty() || value.len() > MAX_KEY_BYTES)
        {
            return Err(ConfigError::Keys);
        }
        let config = Self {
            as_origin: Origin::parse(&lookup("AS_ORIGIN").ok_or(ConfigError::Origins)?)
                .map_err(|_| ConfigError::Origins)?,
            rs_origin: Origin::parse(&lookup("RS_ORIGIN").ok_or(ConfigError::Origins)?)
                .map_err(|_| ConfigError::Origins)?,
            client_origin: Origin::parse(&lookup("CLIENT_ORIGIN").ok_or(ConfigError::Origins)?)
                .map_err(|_| ConfigError::Origins)?,
            keys,
        };
        if config.as_origin.value == config.rs_origin.value
            || config.as_origin.value == config.client_origin.value
            || config.rs_origin.value == config.client_origin.value
        {
            return Err(ConfigError::Origins);
        }
        match role {
            Role::As => {
                config.root()?;
                let client = config.public_jwk("client")?;
                let rs = config.public_jwk("rs")?;
                if crate::replay::key_identity(&client) == crate::replay::key_identity(&rs) {
                    return Err(ConfigError::Keys);
                }
            }
            Role::Rs => {
                config.signer("rs")?;
                config.roots()?;
            }
            Role::Client => {
                config.signer("client")?;
                config.roots()?;
            }
        }
        Ok(config)
    }
    pub fn signer(&self, role: &str) -> Result<Ps256Signer, ConfigError> {
        Ps256Signer::from_pkcs8_pem(
            self.keys
                .get(&format!("{role}.pem"))
                .ok_or(ConfigError::Keys)?,
            format!("files-{role}"),
        )
        .map_err(|_| ConfigError::Keys)
    }
    pub fn public_jwk(
        &self,
        role: &str,
    ) -> Result<serde_json::Map<String, serde_json::Value>, ConfigError> {
        let key = serde_json::from_str(
            self.keys
                .get(&format!("{role}.jwk"))
                .ok_or(ConfigError::Keys)?,
        )
        .map_err(|_| ConfigError::Keys)?;
        gnap_crypto::Ps256Verifier::from_public_jwk(&key).map_err(|_| ConfigError::Keys)?;
        Ok(key)
    }
    pub fn root(&self) -> Result<KeyPair, ConfigError> {
        Ok(KeyPair::from(
            &PrivateKey::from_bytes_hex(
                self.keys.get("root.key").ok_or(ConfigError::Keys)?.trim(),
                Algorithm::Ed25519,
            )
            .map_err(|_| ConfigError::Keys)?,
        ))
    }
    pub fn roots(&self) -> Result<BTreeMap<u32, PublicKey>, ConfigError> {
        Ok(BTreeMap::from([(
            1,
            PublicKey::from_bytes_hex(
                self.keys.get("root.pub").ok_or(ConfigError::Keys)?.trim(),
                Algorithm::Ed25519,
            )
            .map_err(|_| ConfigError::Keys)?,
        )]))
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    Ok(())
}
/// Refuses an existing directory and never overwrites key material.
pub fn initialize(path: &Path) -> Result<(), Error> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    for role in ["client", "rs"] {
        let private = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)?;
        let pem = private.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)?;
        let signer = Ps256Signer::from_pkcs8_pem(&pem, format!("files-{role}"))?;
        write_new(&path.join(format!("{role}.pem")), pem.as_bytes())?;
        write_new(
            &path.join(format!("{role}.jwk")),
            &serde_json::to_vec(&signer.public_jwk()?)?,
        )?;
    }
    let root = KeyPair::new();
    write_new(
        &path.join("root.key"),
        root.private().to_bytes_hex().as_bytes(),
    )?;
    write_new(
        &path.join("root.pub"),
        root.public().to_bytes_hex().as_bytes(),
    )?;
    Ok(())
}
pub async fn serve(router: axum::Router) -> Result<(), Error> {
    let port = std::env::var("PORT")
        .map_err(|_| "invalid or missing PORT")?
        .parse::<u16>()
        .map_err(|_| "invalid or missing PORT")?;
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .map_err(|_| "HTTP listener unavailable")?;
    println!("Biscuit files process listening; credential logging is disabled.");
    axum::serve(listener, router)
        .await
        .map_err(|_| "HTTP service failed")?;
    Ok(())
}
