pub mod acme;
pub mod capsule;
pub mod config;
pub mod logging;
pub mod masque;
pub mod server;
pub mod service;
pub mod shutdown;
// CONNECT-IP (tun/NAT) is Linux-only: it uses the Linux TUNSETIFF ioctl and
// `libc::Ioctl` (defined only on linux_like targets). Windows/macOS builds
// compile and serve the other protocols; see `masque::handle_connection`.
#[cfg(target_os = "linux")]
pub mod tun;
pub mod upgrade;

pub use config::{AppConfig, Cli, Command, DisableProtocol, EnableProtocol};

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    // Validate before spawning or binding anything: a config that leaves the
    // process serving nothing must fail immediately, not start and exit.
    config.validate()?;

    // Graceful-shutdown wiring: catch SIGTERM/SIGINT (and Ctrl-C) so the
    // process unwinds and per-session `Drop` cleanup (notably CONNECT-IP's
    // tun/iptables teardown) actually runs, then stop accepting and drain the
    // live CONNECT-IP sessions (bounded) before returning.
    let shutdown = shutdown::Shutdown::new();
    shutdown::spawn_signal_handlers(shutdown.clone())?;

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
            // Defensive runtime check: config.validate() ensures --auth-token
            // is set and either --key/--cert-chain or --acme-ip is configured.
            config.validate()?;
            let masque = masque::MasqueServer::new(config.clone())?;
            // On shutdown the select arms drop the server future(s), which
            // stops accepting (QUIC endpoint / TCP listener); the spawned
            // CONNECT-IP session tasks observe the same trigger, tear their
            // tunnels down, and are waited for by the drain below.
            let result = if config.run_tcp_proxy() {
                let tcp = server::ProxyServer::new(config)?;
                tokio::select! {
                    res = async {
                        tokio::try_join!(tcp.run(), masque.run(shutdown.clone()))
                    } => res.map(|_| ()),
                    _ = shutdown.wait() => Ok(()),
                }
            } else {
                // --disable http: the TCP --listen port is never bound; MASQUE
                // is the only listener.
                tokio::select! {
                    res = masque.run(shutdown.clone()) => res,
                    _ = shutdown.wait() => Ok(()),
                }
            };
            // Bounded wait for live CONNECT-IP sessions to run their `TunDevice`
            // teardown (interface delete, iptables rule removal, ip_forward
            // restore) before the process exits.
            shutdown.drain(shutdown::SESSION_DRAIN_TIMEOUT).await;
            result
        }
        // `--disable http` never reaches here: `validate()` rejected it.
        None => {
            let proxy = server::ProxyServer::new(config)?;
            let result = tokio::select! {
                res = proxy.run() => res,
                _ = shutdown.wait() => Ok(()),
            };
            shutdown.drain(shutdown::SESSION_DRAIN_TIMEOUT).await;
            result
        }
    }
}
