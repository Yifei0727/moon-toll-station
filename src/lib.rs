pub mod config;
pub mod logging;
pub mod server;
pub mod upgrade;

pub use config::AppConfig;

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    if let Some(ref interval_str) = config.auto_upgrade {
        let interval = match upgrade::parse_interval(interval_str) {
            Ok(d) => d,
            Err(e) => {
                tracing::error!("Invalid auto-upgrade interval '{}': {}", interval_str, e);
                anyhow::bail!("Invalid auto-upgrade interval: {}", e);
            }
        };
        tokio::spawn(async move {
            upgrade::run_upgrade_loop(interval, config.pre_release).await;
        });
    }

    server::ProxyServer::new(config)?.run().await
}
