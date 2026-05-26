pub mod config;
pub mod logging;
pub mod server;

pub use config::AppConfig;

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    server::ProxyServer::new(config)?.run().await
}
