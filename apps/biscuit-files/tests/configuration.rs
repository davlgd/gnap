use biscuit_auth::KeyPair;
use gnap_biscuit_files::config::{Config, ConfigError, Role};
use rsa::pkcs8::{EncodePrivateKey, LineEnding};
use std::{cell::RefCell, collections::BTreeMap, sync::OnceLock};

fn materials() -> &'static BTreeMap<String, String> {
    static MATERIALS: OnceLock<BTreeMap<String, String>> = OnceLock::new();
    MATERIALS.get_or_init(|| {
        let root = KeyPair::new();
        let mut values = BTreeMap::from([
            ("root.key".into(), root.private().to_bytes_hex()),
            ("root.pub".into(), root.public().to_bytes_hex()),
        ]);
        for role in ["client", "rs"] {
            let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).unwrap();
            let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap().to_string();
            let signer =
                gnap_crypto::Ps256Signer::from_pkcs8_pem(&pem, format!("files-{role}")).unwrap();
            values.insert(format!("{role}.pem"), pem);
            values.insert(
                format!("{role}.jwk"),
                serde_json::to_string(&signer.public_jwk().unwrap()).unwrap(),
            );
        }
        values
    })
}
fn role_materials(role: Role) -> Vec<(&'static str, &'static str)> {
    match role {
        Role::As => vec![
            ("BISCUIT_AS_ROOT_PRIVATE_KEY_HEX", "root.key"),
            ("BISCUIT_AS_CLIENT_PUBLIC_JWK", "client.jwk"),
            ("BISCUIT_AS_RS_PUBLIC_JWK", "rs.jwk"),
        ],
        Role::Rs => vec![
            ("BISCUIT_RS_PRIVATE_KEY_PEM", "rs.pem"),
            ("BISCUIT_RS_ROOT_PUBLIC_KEY_HEX", "root.pub"),
        ],
        Role::Client => vec![
            ("BISCUIT_CLIENT_PRIVATE_KEY_PEM", "client.pem"),
            ("BISCUIT_CLIENT_ROOT_PUBLIC_KEY_HEX", "root.pub"),
        ],
    }
}
fn origins() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("AS_ORIGIN".into(), "https://as.example".into()),
        ("RS_ORIGIN".into(), "https://rs.example".into()),
        ("CLIENT_ORIGIN".into(), "https://client.example".into()),
    ])
}
fn environment(role: Role) -> BTreeMap<String, String> {
    let mut values = origins();
    values.insert("KEY_SOURCE".into(), "environment".into());
    for (name, file) in role_materials(role) {
        values.insert(name.into(), materials()[file].clone());
    }
    values
}
fn load_environment(role: Role, values: &BTreeMap<String, String>) -> Result<Config, ConfigError> {
    Config::load_with(
        role,
        |name| values.get(name).cloned(),
        |name| values.contains_key(name),
        |_| panic!("environment configuration accessed disk"),
    )
}

#[test]
fn complete_environment_configuration_loads_only_its_role_and_never_uses_disk() {
    for role in [Role::As, Role::Rs, Role::Client] {
        let values = environment(role);
        let read = RefCell::new(Vec::new());
        let config = Config::load_with(
            role,
            |name| {
                read.borrow_mut().push(name.to_owned());
                values.get(name).cloned()
            },
            |name| values.contains_key(name),
            |_| panic!("environment mode read a file"),
        )
        .unwrap();
        for name in read
            .borrow()
            .iter()
            .filter(|name| name.starts_with("BISCUIT_"))
        {
            assert!(role_materials(role)
                .iter()
                .any(|(expected, _)| expected == name));
        }
        match role {
            Role::As => {
                assert!(config.root().is_ok());
                assert!(config.public_jwk("client").is_ok());
                assert!(config.signer("client").is_err());
            }
            Role::Rs => {
                assert!(config.signer("rs").is_ok());
                assert!(config.signer("client").is_err());
                assert!(config.root().is_err());
            }
            Role::Client => {
                assert!(config.signer("client").is_ok());
                assert!(config.signer("rs").is_err());
                assert!(config.root().is_err());
            }
        }
    }
}

#[test]
fn listener_selection_uses_each_roles_origin_in_mixed_configurations() {
    for role in [Role::As, Role::Rs, Role::Client] {
        for (origin, expected) in [
            ("http://127.0.0.1:18080", "127.0.0.1"),
            ("http://localhost:18080", "127.0.0.1"),
            ("http://[::1]:18080", "::1"),
            ("https://role.example", "0.0.0.0"),
        ] {
            let mut values = environment(role);
            // The other roles deliberately use a different listener policy.
            if origin.starts_with("https:") {
                for (name, port) in [
                    ("AS_ORIGIN", 18081),
                    ("RS_ORIGIN", 18082),
                    ("CLIENT_ORIGIN", 18083),
                ] {
                    values.insert(name.into(), format!("http://127.0.0.1:{port}"));
                }
            }
            let name = match role {
                Role::As => "AS_ORIGIN",
                Role::Rs => "RS_ORIGIN",
                Role::Client => "CLIENT_ORIGIN",
            };
            values.insert(name.into(), origin.into());
            let config = load_environment(role, &values).unwrap();
            let origin = match role {
                Role::As => config.as_origin,
                Role::Rs => config.rs_origin,
                Role::Client => config.client_origin,
            };
            assert_eq!(
                origin.listener_ip(),
                expected.parse::<std::net::IpAddr>().unwrap()
            );
        }
    }
}
#[test]
fn directory_mode_reads_only_required_files_and_has_no_secret_environment_fallback() {
    for role in [Role::As, Role::Rs, Role::Client] {
        let mut values = origins();
        values.insert("KEY_DIRECTORY".into(), "/unused-test-directory".into());
        let reads = RefCell::new(Vec::new());
        Config::load_with(
            role,
            |name| values.get(name).cloned(),
            |name| values.contains_key(name),
            |path| {
                let file = path.file_name().unwrap().to_str().unwrap();
                reads.borrow_mut().push(file.to_owned());
                Ok(materials()[file].clone())
            },
        )
        .unwrap();
        assert_eq!(reads.borrow().len(), role_materials(role).len());
        for file in reads.borrow().iter() {
            assert!(role_materials(role)
                .iter()
                .any(|(_, expected)| expected == file));
        }
        let missing = Config::load_with(
            role,
            |name| values.get(name).cloned(),
            |name| values.contains_key(name),
            |_| Err(ConfigError::Keys),
        );
        assert!(matches!(missing, Err(ConfigError::Keys)));
        values.insert(role_materials(role)[0].0.into(), "secret-marker".into());
        assert!(matches!(
            Config::load_with(
                role,
                |name| values.get(name).cloned(),
                |name| values.contains_key(name),
                |_| panic!("ambiguous directory configuration read files")
            ),
            Err(ConfigError::Keys)
        ));
    }
}
#[test]
fn missing_ambiguous_or_malformed_material_is_rejected_with_one_redacted_error() {
    for role in [Role::As, Role::Rs, Role::Client] {
        for (name, _) in role_materials(role) {
            for bad in [None, Some(""), Some("secret-marker-invalid-PEM-JWK-hex")] {
                let mut values = environment(role);
                if let Some(bad) = bad {
                    values.insert(name.into(), bad.into());
                } else {
                    values.remove(name);
                }
                let error = match load_environment(role, &values) {
                    Err(e) => e,
                    Ok(_) => panic!("invalid key configuration accepted"),
                };
                assert_eq!(error, ConfigError::Keys);
                assert_eq!(
                    error.to_string(),
                    "invalid, ambiguous or incomplete key configuration"
                );
                assert!(!format!("{error:?}").contains("secret-marker"));
            }
        }
        let mut values = environment(role);
        values.insert("KEY_DIRECTORY".into(), "secret-marker-directory".into());
        assert!(matches!(
            load_environment(role, &values),
            Err(ConfigError::Keys)
        ));
        let mut values = environment(role);
        values.insert("KEY_SOURCE".into(), "secret-marker-unknown-mode".into());
        assert!(matches!(
            load_environment(role, &values),
            Err(ConfigError::Keys)
        ));
    }
}
#[test]
fn foreign_role_variables_are_rejected_by_presence_without_loading_their_values() {
    for role in [Role::As, Role::Rs, Role::Client] {
        for other in [Role::As, Role::Rs, Role::Client]
            .into_iter()
            .filter(|other| *other != role)
        {
            let values = environment(role);
            let foreign = role_materials(other)[0].0;
            let result = Config::load_with(
                role,
                |name| {
                    assert_ne!(name, foreign, "foreign secret was read");
                    values.get(name).cloned()
                },
                |name| name == foreign || values.contains_key(name),
                |_| panic!("foreign-role configuration read disk"),
            );
            assert!(matches!(result, Err(ConfigError::Keys)));
        }
    }
}
#[test]
fn as_rejects_the_same_client_and_rs_key_even_with_different_kids() {
    let mut values = environment(Role::As);
    let mut key: serde_json::Value =
        serde_json::from_str(&values["BISCUIT_AS_CLIENT_PUBLIC_JWK"]).unwrap();
    key["kid"] = serde_json::json!("different-label");
    values.insert("BISCUIT_AS_RS_PUBLIC_JWK".into(), key.to_string());
    assert!(matches!(
        load_environment(Role::As, &values),
        Err(ConfigError::Keys)
    ));
}
