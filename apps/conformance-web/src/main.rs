#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".into())
        .parse()?;
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::UNSPECIFIED, port)).await?;
    let probes = gnap_conformance_web::probe::Probes::from_json(
        &std::env::var("GNAP_TEST_TARGETS").unwrap_or_else(|_| "[]".into()),
    )?
    .with_resource_targets(
        &std::env::var("GNAP_RS_TEST_TARGETS").unwrap_or_else(|_| "[]".into()),
    )?;
    eprintln!("GNAP diagnostics listening on port {port}; no request/body logging; only explicitly configured probe targets");
    axum::serve(listener, gnap_conformance_web::app_with_probes(probes))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
