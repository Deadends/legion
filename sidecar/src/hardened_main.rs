use std::net::SocketAddr;
use legion_sidecar::hardened_server::HardenedServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], 8444));
    let server = HardenedServer::new(addr);
    server.run().await
}