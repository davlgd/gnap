use gnap_biscuit_files::{
    client,
    config::{self, Config},
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let c = Config::load(config::Role::Client)?;
    let origin = c.client_origin.clone();
    let app = client::app(c)?;
    config::serve(client::router(app), origin).await
}
