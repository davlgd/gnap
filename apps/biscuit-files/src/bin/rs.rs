use gnap_biscuit_files::{
    config::{self, Config},
    resource::{self, App, Resources},
    resource_check::LiveCheck,
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let c = Config::load(config::Role::Rs)?;
    let resources = Resources::new(
        c.rs_origin.clone(),
        format!("{}/gnap", c.as_origin.value),
        c.roots()?,
    );
    // reqwest's blocking client is created and dropped outside Tokio's runtime.
    let check = std::thread::spawn(move || {
        LiveCheck::new(
            c.as_origin.clone(),
            c.signer("rs").map_err(|_| "RS key unavailable")?,
        )
    })
    .join()
    .map_err(|_| "resource-check transport initialization failed")??;
    config::serve(resource::router(App::new(resources, check))).await
}
