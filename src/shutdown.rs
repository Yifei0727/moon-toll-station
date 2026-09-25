//! Cooperative shutdown: top-level signal handling plus tracking of live
//! CONNECT-IP sessions so the process waits for their teardown before exiting.
//!
//! A CONNECT-IP session's `TunDevice` performs the host-side cleanup (interface
//! delete, iptables rule removal, `ip_forward` restore) in its `Drop`, which
//! only runs when the owning session task returns. The default SIGTERM
//! disposition kills the process without unwinding, so every `Drop` is skipped
//! and the interface/rules leak. This module fixes that: SIGTERM/SIGINT (and
//! Ctrl-C) fire a trigger, the listeners stop accepting, each session task
//! observes the trigger and tears its tunnel down, and `run()` drains the
//! active-session count (bounded — a wedged session must not hang the exit)
//! before returning.
//!
//! Session tracking only matters on Linux (the only platform with the
//! CONNECT-IP tun/NAT data plane); elsewhere `drain` is a no-op.

use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::{
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

#[cfg(unix)]
use anyhow::Context;
#[cfg(target_os = "linux")]
use tokio::sync::mpsc;
use tokio::sync::watch;
#[cfg(target_os = "linux")]
use tracing::warn;
use tracing::info;

/// Bounded grace period after a shutdown signal for live CONNECT-IP sessions
/// to finish their teardown before the process exits anyway. (On platforms
/// without the CONNECT-IP data plane `drain` is a no-op and this is unused.)
pub(crate) const SESSION_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

struct Inner {
    flag: watch::Sender<bool>,
    /// Number of live CONNECT-IP sessions (sessions whose `TunDevice` has not
    /// been dropped yet).
    #[cfg(target_os = "linux")]
    active: AtomicUsize,
    /// Each finished session sends one `()`; `drain` counts them out. Buffered
    /// (unbounded) so a session that finishes before `drain` starts is not lost.
    #[cfg(target_os = "linux")]
    done_tx: mpsc::UnboundedSender<()>,
    #[cfg(target_os = "linux")]
    done_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<()>>,
}

/// Cloneable handle coordinating graceful shutdown.
#[derive(Clone)]
pub struct Shutdown {
    inner: Arc<Inner>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    pub fn new() -> Self {
        let (flag, _) = watch::channel(false);
        #[cfg(target_os = "linux")]
        let (done_tx, done_rx) = mpsc::unbounded_channel();
        Self {
            inner: Arc::new(Inner {
                flag,
                #[cfg(target_os = "linux")]
                active: AtomicUsize::new(0),
                #[cfg(target_os = "linux")]
                done_tx,
                #[cfg(target_os = "linux")]
                done_rx: tokio::sync::Mutex::new(done_rx),
            }),
        }
    }

    /// Fire the shutdown trigger (idempotent).
    pub fn trigger(&self) {
        self.inner.flag.send_if_modified(|v| {
            if *v {
                false
            } else {
                *v = true;
                true
            }
        });
    }

    /// Resolves once `trigger` has fired (also immediately if it already has).
    pub async fn wait(&self) {
        let mut rx = self.inner.flag.subscribe();
        while !*rx.borrow_and_update() {
            if rx.changed().await.is_err() {
                // Sender gone: process teardown in progress; treat as triggered.
                return;
            }
        }
    }

    /// Mark one CONNECT-IP session as live until the returned guard drops. The
    /// guard must outlive the session's `TunDevice` so the device's `Drop`
    /// (the actual host cleanup) runs before the session is counted as done.
    #[cfg(target_os = "linux")]
    pub(crate) fn register_session(&self) -> SessionGuard {
        self.inner.active.fetch_add(1, Ordering::AcqRel);
        SessionGuard {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Wait (bounded by `timeout`) for every registered session to finish its
    /// teardown, then log the outcome. Sessions are counted down by
    /// `SessionGuard::drop`, so this is race-free against sessions finishing
    /// while we wait.
    #[cfg(target_os = "linux")]
    pub(crate) async fn drain(&self, timeout: Duration) {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut done_rx = self.inner.done_rx.lock().await;
        while self.inner.active.load(Ordering::Acquire) > 0 {
            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
                warn!(
                    active = self.inner.active.load(Ordering::Acquire),
                    timeout = ?timeout,
                    "grace period expired with CONNECT-IP sessions still live; exiting anyway"
                );
                return;
            };
            match tokio::time::timeout(remaining, done_rx.recv()).await {
                Ok(Some(())) => {}
                // All senders gone (Shutdown dropped) — cannot outlive self.
                Ok(None) => return,
                Err(_elapsed) => {
                    if self.inner.active.load(Ordering::Acquire) > 0 {
                        warn!(
                            active = self.inner.active.load(Ordering::Acquire),
                            timeout = ?timeout,
                            "timed out waiting for CONNECT-IP session teardown; exiting anyway"
                        );
                    }
                    return;
                }
            }
        }
        info!("all CONNECT-IP sessions torn down; exiting");
    }

    /// No CONNECT-IP data plane off Linux: nothing to drain.
    #[cfg(not(target_os = "linux"))]
    pub(crate) async fn drain(&self, _timeout: std::time::Duration) {}
}

/// RAII marker for one live CONNECT-IP session. Dropping it counts the session
/// as finished and releases `drain`.
#[cfg(target_os = "linux")]
pub(crate) struct SessionGuard {
    inner: Arc<Inner>,
}

#[cfg(target_os = "linux")]
impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.inner.active.fetch_sub(1, Ordering::AcqRel);
        let _ = self.inner.done_tx.send(());
    }
}

/// Install signal handlers that fire `shutdown`. On unix both SIGTERM and
/// SIGINT are caught (SIGINT covers Ctrl-C there); on other platforms only
/// Ctrl-C via the cross-platform `ctrl_c()` helper.
pub fn spawn_signal_handlers(shutdown: Shutdown) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm =
            signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
        let mut sigint = signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
        tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => info!(signal = "SIGTERM", "shutting down"),
                _ = sigint.recv() => info!(signal = "SIGINT", "shutting down"),
            }
            shutdown.trigger();
        });
    }
    #[cfg(not(unix))]
    {
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                info!("Ctrl-C received; shutting down");
            }
            shutdown.trigger();
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn wait_resolves_immediately_when_already_triggered() {
        let s = Shutdown::new();
        s.trigger();
        // Second trigger is a no-op.
        s.trigger();
        tokio::time::timeout(Duration::from_millis(100), s.wait())
            .await
            .expect("wait should resolve immediately after trigger");
    }

    #[tokio::test]
    async fn wait_resolves_on_trigger() {
        let s = Shutdown::new();
        let s2 = s.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            s2.trigger();
        });
        tokio::time::timeout(Duration::from_secs(1), s.wait())
            .await
            .expect("wait should resolve after trigger");
    }

    #[cfg(target_os = "linux")]
    mod sessions {
        use super::*;

        #[tokio::test]
        async fn drain_returns_once_all_sessions_drop() {
            let s = Shutdown::new();
            let g = s.register_session();
            let waiter = tokio::spawn({
                let s = s.clone();
                async move { s.drain(Duration::from_secs(5)).await }
            });
            // Drain must still be waiting while the guard is alive.
            tokio::time::sleep(Duration::from_millis(50)).await;
            assert!(!waiter.is_finished());
            drop(g);
            tokio::time::timeout(Duration::from_secs(1), waiter)
                .await
                .expect("drain should finish after the session guard drops")
                .unwrap();
        }

        #[tokio::test]
        async fn drain_times_out_with_live_session() {
            let s = Shutdown::new();
            let _g = s.register_session();
            // 20ms grace: drain must give up (with the warning path), not hang.
            tokio::time::timeout(
                Duration::from_secs(1),
                s.drain(Duration::from_millis(20)),
            )
            .await
            .expect("drain should respect the timeout");
        }

        #[tokio::test]
        async fn drain_counts_multiple_sessions() {
            let s = Shutdown::new();
            let g1 = s.register_session();
            let g2 = s.register_session();
            drop(g1);
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(g2);
            tokio::time::timeout(Duration::from_secs(1), s.drain(Duration::from_secs(5)))
                .await
                .expect("drain should finish once both guards drop");
        }
    }
}
