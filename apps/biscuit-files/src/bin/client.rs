use gnap_biscuit_files::{
    client,
    config::{self, Config},
};
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = client::app(Config::load(config::Role::Client)?)?;
    config::serve(client::router(app)).await
}
