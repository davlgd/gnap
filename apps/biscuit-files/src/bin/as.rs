use gnap_biscuit_files::{
    authorization::{self, App, Store},
    config::{self, Config},
    resource_check::{CheckService, Nonces},
};
use std::sync::Arc;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() == 3 && args[1] == "--init-config" {
        config::initialize(std::path::Path::new(&args[2]))
            .map_err(|_| "key initialization failed")?;
        println!("Role keys created; distribute only each role's required files.");
        return Ok(());
    }
    let c = Config::load(config::Role::As)?;
    let client_key = c.public_jwk("client")?;
    let rs_key = c.public_jwk("rs")?;
    let store = Arc::new(Store::default());
    let engine = authorization::engine(
        &c.as_origin,
        &c.rs_origin,
        c.root()?,
        client_key,
        store.clone(),
    )?;
    let check = CheckService {
        endpoint: format!("{}/resource-check", c.as_origin.value),
        key: gnap_crypto::Ps256Verifier::from_public_jwk(&rs_key)
            .map_err(|_| "RS public key unavailable")?,
        store,
        nonces: Nonces::default(),
    };
    let origin = c.as_origin;
    config::serve(
        authorization::router(App::new(origin.clone(), engine, check)),
        origin,
    )
    .await
}
