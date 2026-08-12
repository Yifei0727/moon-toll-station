//! System service management for Linux.
//!
//! Supports systemd as the primary init system and falls back to OpenRC or a
//! classic SysV `init.d` script on other distributions. The subcommands never
//! start the server process directly — they delegate start/stop/enable to the
//! distribution's service manager.

#[cfg(target_os = "linux")]
mod imp {
    use std::{
        io::Write,
        path::{Path, PathBuf},
        process::Command,
    };

    use anyhow::{bail, Context};
    use crate::config::ServiceAction;

    const SERVICE_NAME: &str = "auto-server";
    const SYSTEMD_UNIT_PATH: &str = "/etc/systemd/system/auto-server.service";
    const SYSV_SCRIPT_PATH: &str = "/etc/init.d/auto-server";

    pub fn run(cmd: ServiceAction) -> anyhow::Result<()> {
        ensure_root()?;
        match cmd {
            ServiceAction::Install { args, bin_path } => install(&args, &bin_path),
            ServiceAction::Enable => enable(),
            ServiceAction::Start => start(),
            ServiceAction::Stop => stop(),
            ServiceAction::Uninstall => uninstall(),
        }
    }

    fn ensure_root() -> anyhow::Result<()> {
        if !is_root() {
            bail!("This command must be run as root (e.g. `sudo auto-server service ...`).");
        }
        Ok(())
    }

    fn is_root() -> bool {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Uid:"))
                    .and_then(|l| {
                        l.split_whitespace()
                            .nth(1)
                            .and_then(|u| u.parse::<u32>().ok())
                    })
            })
            .map(|uid| uid == 0)
            .unwrap_or(false)
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum InitSystem {
        Systemd,
        OpenRc,
        SysV,
    }

    fn detect_init() -> anyhow::Result<InitSystem> {
        if Path::new("/run/systemd/system").exists() {
            return Ok(InitSystem::Systemd);
        }
        if command_exists("rc-update") || Path::new("/sbin/openrc").exists() {
            return Ok(InitSystem::OpenRc);
        }
        if Path::new("/etc/init.d").is_dir() {
            return Ok(InitSystem::SysV);
        }
        bail!("Could not detect a supported init system (systemd, OpenRC, or SysV init).");
    }

    fn command_exists(name: &str) -> bool {
        if let Ok(path) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path) {
                if dir.join(name).is_file() {
                    return true;
                }
            }
        }
        false
    }

    fn binary_path() -> anyhow::Result<PathBuf> {
        let exe = std::env::current_exe().context("failed to determine current executable path")?;
        std::fs::canonicalize(&exe)
            .with_context(|| format!("failed to resolve executable path {}", exe.display()))
    }

    fn run_cmd(program: &str, args: &[&str]) -> anyhow::Result<()> {
        let status = Command::new(program)
            .args(args)
            .status()
            .with_context(|| format!("failed to execute `{program}` (is it installed?)"))?;
        if !status.success() {
            bail!("`{} {}` failed", program, args.join(" "));
        }
        Ok(())
    }

    fn run_cmd_ignore(program: &str, args: &[&str]) {
        let _ = Command::new(program).args(args).status();
    }

    fn write_file(path: &str, content: &str, mode: u32) -> anyhow::Result<()> {
        let mut f =
            std::fs::File::create(path).with_context(|| format!("failed to create {path}"))?;
        f.write_all(content.as_bytes())
            .with_context(|| format!("failed to write {path}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .with_context(|| format!("failed to set permissions on {path}"))?;
        }
        Ok(())
    }

    fn remove_if_exists(path: &str) -> anyhow::Result<()> {
        if Path::new(path).exists() {
            std::fs::remove_file(path).with_context(|| format!("failed to remove {path}"))?;
        }
        Ok(())
    }

    fn systemd_unit(bin: &str, args: &[String]) -> String {
        format!(
            r#"[Unit]
Description=auto-server SOCKS + HTTP CONNECT proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exec}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"#,
            exec = systemd_exec(bin, args)
        )
    }

    /// Quote a single token for systemd's ExecStart parsing (double-quote
    /// aware, with backslash escaping).
    fn systemd_quote(s: &str) -> String {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }

    fn systemd_exec(bin: &str, args: &[String]) -> String {
        let mut parts = vec![systemd_quote(bin)];
        for a in args {
            parts.push(systemd_quote(a));
        }
        parts.join(" ")
    }

    /// A portable POSIX init script that works with both OpenRC (`rc-service`)
    /// and SysV (`service`). It detaches the daemon with `setsid` and tracks a
    /// pidfile so stop/status work without `start-stop-daemon`.
    fn init_script(bin: &str, args: &[String]) -> String {
        format!(
            r#"#!/bin/sh
### BEGIN INIT INFO
# Provides:          auto-server
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: auto-server SOCKS + HTTP CONNECT proxy
# Description:       auto-server proxy server
### END INIT INFO

NAME=auto-server
DAEMON="{bin}"
DAEMON_ARGS="{args}"
PIDFILE=/var/run/auto-server.pid
LOGFILE=/var/log/auto-server.log

start() {{
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "$NAME is already running"
        return 0
    fi
    echo "Starting $NAME..."
    setsid "$DAEMON" $DAEMON_ARGS >"$LOGFILE" 2>&1 < /dev/null &
    echo $! > "$PIDFILE"
    return 0
}}

stop() {{
    if [ ! -f "$PIDFILE" ] || ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "$NAME is not running"
        return 0
    fi
    echo "Stopping $NAME..."
    kill "$(cat "$PIDFILE")" 2>/dev/null
    rm -f "$PIDFILE"
    return 0
}}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    status)
        if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
            echo "$NAME is running (pid $(cat "$PIDFILE"))"; exit 0
        else
            echo "$NAME is not running"; exit 3
        fi
        ;;
    *) echo "Usage: $0 {{start|stop|restart|status}}"; exit 1 ;;
esac
exit 0
"#,
            args = sh_quote_join(args)
        )
    }

    /// Single-quote a token for shell (POSIX) usage, escaping embedded quotes.
    fn sh_quote(s: &str) -> String {
        format!("'{}'", s.replace('\'', "'\\''"))
    }

    fn sh_quote_join(args: &[String]) -> String {
        args.iter().map(|a| sh_quote(a)).collect::<Vec<_>>().join(" ")
    }

    fn install(args: &[String], bin_path: &Option<String>) -> anyhow::Result<()> {
        let bin = match bin_path {
            Some(dest) => {
                let src = binary_path()?;
                copy_binary(&src, dest)?;
                dest.clone()
            }
            None => binary_path()?.display().to_string(),
        };
        match detect_init()? {
            InitSystem::Systemd => {
                write_file(SYSTEMD_UNIT_PATH, &systemd_unit(&bin, args), 0o644)
                    .context("failed to write systemd unit file")?;
                run_cmd("systemctl", &["daemon-reload"]).context("failed to reload systemd")?;
                println!("Installed systemd unit at {SYSTEMD_UNIT_PATH}");
                println!("ExecStart uses binary: {bin}");
                if args.is_empty() {
                    println!("Next: `auto-server service enable` then `auto-server service start`");
                } else {
                    println!(
                        "Forwarded args: {}",
                        args.join(" ")
                    );
                    println!("Next: `auto-server service enable` then `auto-server service start`");
                }
            }
            InitSystem::OpenRc => {
                write_file(SYSV_SCRIPT_PATH, &init_script(&bin, args), 0o755)
                    .context("failed to write OpenRC init script")?;
                println!("Installed OpenRC init script at {SYSV_SCRIPT_PATH}");
                println!("DAEMON uses binary: {bin}");
            }
            InitSystem::SysV => {
                write_file(SYSV_SCRIPT_PATH, &init_script(&bin, args), 0o755)
                    .context("failed to write SysV init script")?;
                println!("Installed SysV init script at {SYSV_SCRIPT_PATH}");
                println!("DAEMON uses binary: {bin}");
            }
        }
        Ok(())
    }

    /// Copy the running binary to `dest` (creating parent dirs if needed,
    /// ensuring it is executable) and return the destination path.
    fn copy_binary(src: &Path, dest: &str) -> anyhow::Result<()> {
        let dest = if Path::new(dest).is_absolute() {
            PathBuf::from(dest)
        } else {
            std::env::current_dir()
                .with_context(|| "failed to determine current directory")?
                .join(dest)
        };
        if let Some(parent) = dest.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create directory {}", parent.display()))?;
            }
        }
        std::fs::copy(src, &dest)
            .with_context(|| format!("failed to copy {} to {}", src.display(), dest.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
                .with_context(|| format!("failed to set permissions on {}", dest.display()))?;
        }
        println!("Copied binary from {} to {}", src.display(), dest.display());
        Ok(())
    }

    fn enable() -> anyhow::Result<()> {
        match detect_init()? {
            InitSystem::Systemd => {
                run_cmd("systemctl", &["enable", SERVICE_NAME])?;
                println!("Enabled {SERVICE_NAME} (starts at boot)");
            }
            InitSystem::OpenRc => {
                run_cmd("rc-update", &["add", SERVICE_NAME, "default"])?;
                println!("Enabled {SERVICE_NAME} (rc-update add default)");
            }
            InitSystem::SysV => {
                if command_exists("update-rc.d") {
                    run_cmd("update-rc.d", &[SERVICE_NAME, "defaults"])?;
                } else if command_exists("chkconfig") {
                    run_cmd("chkconfig", &["--add", SERVICE_NAME])?;
                    run_cmd("chkconfig", &[SERVICE_NAME, "on"])?;
                } else {
                    bail!("Could not find `update-rc.d` or `chkconfig` to enable the service.");
                }
                println!("Enabled {SERVICE_NAME}");
            }
        }
        Ok(())
    }

    fn start() -> anyhow::Result<()> {
        match detect_init()? {
            InitSystem::Systemd => run_cmd("systemctl", &["start", SERVICE_NAME])?,
            InitSystem::OpenRc => run_cmd("rc-service", &[SERVICE_NAME, "start"])?,
            InitSystem::SysV => run_cmd("service", &[SERVICE_NAME, "start"])?,
        }
        println!("Started {SERVICE_NAME}");
        Ok(())
    }

    fn stop() -> anyhow::Result<()> {
        match detect_init()? {
            InitSystem::Systemd => run_cmd("systemctl", &["stop", SERVICE_NAME])?,
            InitSystem::OpenRc => run_cmd("rc-service", &[SERVICE_NAME, "stop"])?,
            InitSystem::SysV => run_cmd("service", &[SERVICE_NAME, "stop"])?,
        }
        println!("Stopped {SERVICE_NAME}");
        Ok(())
    }

    fn uninstall() -> anyhow::Result<()> {
        match detect_init()? {
            InitSystem::Systemd => {
                run_cmd_ignore("systemctl", &["stop", SERVICE_NAME]);
                run_cmd_ignore("systemctl", &["disable", SERVICE_NAME]);
                remove_if_exists(SYSTEMD_UNIT_PATH)?;
                run_cmd("systemctl", &["daemon-reload"]).context("failed to reload systemd")?;
                println!("Removed systemd unit at {SYSTEMD_UNIT_PATH}");
            }
            InitSystem::OpenRc => {
                run_cmd_ignore("rc-service", &[SERVICE_NAME, "stop"]);
                run_cmd_ignore("rc-update", &["del", SERVICE_NAME]);
                remove_if_exists(SYSV_SCRIPT_PATH)?;
                println!("Removed OpenRC init script at {SYSV_SCRIPT_PATH}");
            }
            InitSystem::SysV => {
                run_cmd_ignore("service", &[SERVICE_NAME, "stop"]);
                if command_exists("update-rc.d") {
                    run_cmd_ignore("update-rc.d", &["-f", SERVICE_NAME, "remove"]);
                } else if command_exists("chkconfig") {
                    run_cmd_ignore("chkconfig", &[SERVICE_NAME, "off"]);
                    run_cmd_ignore("chkconfig", &["--del", SERVICE_NAME]);
                }
                remove_if_exists(SYSV_SCRIPT_PATH)?;
                println!("Removed SysV init script at {SYSV_SCRIPT_PATH}");
            }
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn systemd_unit_contains_exec_start() {
            let unit = systemd_unit("/opt/bin/auto-server", &[]);
            assert!(unit.contains(r#"ExecStart="/opt/bin/auto-server""#));
            assert!(unit.contains("WantedBy=multi-user.target"));
        }

        #[test]
        fn systemd_unit_forwards_args() {
            let unit = systemd_unit(
                "/opt/bin/auto-server",
                &["--listen".into(), "0.0.0.0:9999".into(), "--acl-no-rfc6890".into()],
            );
            assert!(unit.contains(
                r#"ExecStart="/opt/bin/auto-server" "--listen" "0.0.0.0:9999" "--acl-no-rfc6890""#
            ));
        }

        #[test]
        fn init_script_is_valid_sh_with_braces() {
            let script = init_script("/opt/bin/auto-server", &[]);
            // The Usage line must keep its literal braces (not a format arg).
            assert!(script.contains("Usage: $0 {start|stop|restart|status}"));
            assert!(script.contains(r#"DAEMON="/opt/bin/auto-server""#));
            assert!(script.contains("setsid"));
        }

        #[test]
        fn init_script_forwards_args() {
            let script = init_script(
                "/opt/bin/auto-server",
                &["--listen".into(), "0.0.0.0:9999".into()],
            );
            assert!(script.contains(r#"DAEMON_ARGS="'--listen' '0.0.0.0:9999'"#));
            // Unquoted expansion of DAEMON_ARGS splits into the forwarded args.
            assert!(script.contains(r#"setsid "$DAEMON" $DAEMON_ARGS >"$LOGFILE""#));
        }

        #[test]
        fn copy_binary_writes_destination() {
            let src = binary_path().unwrap();
            let dest = std::env::temp_dir().join("auto-server-copy-test-bin");
            copy_binary(&src, dest.to_str().unwrap()).unwrap();
            assert!(dest.exists());
            let _ = std::fs::remove_file(&dest);
        }
    }
}

#[cfg(target_os = "linux")]
pub use imp::run;

#[cfg(not(target_os = "linux"))]
use crate::config::ServiceAction;

#[cfg(not(target_os = "linux"))]
pub fn run(_cmd: ServiceAction) -> anyhow::Result<()> {
    anyhow::bail!("System service management is only supported on Linux.");
}
