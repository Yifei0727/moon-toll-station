pub mod capsule;
pub mod config;
pub mod logging;
pub mod masque;
pub mod server;
pub mod service;
pub mod tun;
pub mod upgrade;

pub use config::{AppConfig, Cli, Command, DisableProtocol, EnableProtocol};

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    // Validate before spawning or binding anything: a config that leaves the
    // process serving nothing must fail immediately, not start and exit.
    config.validate()?;

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

    match config.enable {
        // HTTP/3 MASQUE runs *alongside* the existing TCP SOCKS/HTTP proxy.
        Some(EnableProtocol::H3) => {
            // Defensive runtime check: the flags above only apply when --enable
            // h3; if somehow the (clap-enforced) requirements are missing, bail
            // with a clear message rather than failing obscurely at handshake.
            if config.key.is_none() || config.cert_chain.is_none() || config.auth_token.is_none() {
                anyhow::bail!(
                    "--enable h3 requires --key, --cert-chain and --auth-token to be set"
                );
            }
            let masque = masque::MasqueServer::new(config.clone())?;
            if config.run_tcp_proxy() {
                let tcp = server::ProxyServer::new(config)?;
                // Run both concurrently; if either stops with an error, surface it.
                tokio::try_join!(tcp.run(), masque.run())?;
            } else {
                // --disable http: the TCP --listen port is never bound; MASQUE
                // is the only listener.
                masque.run().await?;
            }
            Ok(())
        }
        // `--disable http` never reaches here: `validate()` rejected it.
        None => server::ProxyServer::new(config)?.run().await,
    }
}
