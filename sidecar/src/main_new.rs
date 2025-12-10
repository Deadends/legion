use legion_sidecar::SidecarServer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "legion_sidecar=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("═══════════════════════════════════════════════════════");
    tracing::info!("  Legion Protocol - Production Sidecar");
    tracing::info!("  Version: {}", env!("CARGO_PKG_VERSION"));
    tracing::info!("═══════════════════════════════════════════════════════");

    // Initialize and run sidecar server
    let server = SidecarServer::new().await?;
    server.run().await
}
