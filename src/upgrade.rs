use std::io::Cursor;
use std::time::Duration;
use serde::Deserialize;
use tracing::{info, error, warn};

#[derive(Deserialize, Debug)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(Deserialize, Debug)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// Parse interval string like "1h", "3d", "1w", "1m" into `Duration`.
/// Supporting "h" as hours, "d" as days, "w" as weeks, and "m" as months.
/// The minimum supported interval is 1h.
pub fn parse_interval(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty interval".to_string());
    }

    let last_char = s.chars().last().ok_or("empty interval")?;
    let val_str = &s[..s.len() - last_char.len_utf8()];
    let val: u64 = val_str.parse().map_err(|_| "invalid number".to_string())?;

    let duration = match last_char {
        'h' => Duration::from_secs(val * 3600),
        'd' => Duration::from_secs(val * 86400),
        'w' => Duration::from_secs(val * 7 * 86400),
        'm' => Duration::from_secs(val * 30 * 86400), // m means month
        _ => return Err(format!("unknown time unit '{}'. Supported units are h (hours), d (days), w (weeks), m (months).", last_char)),
    };

    if duration < Duration::from_secs(3600) {
        return Err("minimum auto-upgrade interval is 1h".to_string());
    }

    Ok(duration)
}

/// Helper to get target artifact name based on compile-time configuration.
fn get_target_artifact_name() -> Option<&'static str> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")) {
        Some("auto-server-linux-x86_64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64", target_env = "musl")) {
        Some("auto-server-linux-x86_64-unknown-linux-musl")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64", target_env = "gnu")) {
        Some("auto-server-linux-aarch64-unknown-linux-gnu")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64", target_env = "musl")) {
        Some("auto-server-linux-aarch64-unknown-linux-musl")
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("auto-server-macos-aarch64-apple-darwin")
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some("auto-server-windows-x86_64-pc-windows-msvc")
    } else {
        None
    }
}

fn split_version(v: &str) -> (&str, Option<&str>) {
    let v = v.trim_start_matches('v');
    if let Some(idx) = v.find('-') {
        (&v[..idx], Some(&v[idx + 1..]))
    } else {
        (v, None)
    }
}

/// Compare two semver strings (including pre-releases like beta, rc).
/// Returns true if `latest` is newer than `current`.
fn is_newer_version(current: &str, latest: &str) -> bool {
    let (cur_main, cur_pre) = split_version(current);
    let (lat_main, lat_pre) = split_version(latest);

    let cur_parts: Vec<&str> = cur_main.split('.').collect();
    let lat_parts: Vec<&str> = lat_main.split('.').collect();

    for i in 0..std::cmp::max(cur_parts.len(), lat_parts.len()) {
        let cur_val: u32 = cur_parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
        let lat_val: u32 = lat_parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0);
        if lat_val > cur_val {
            return true;
        } else if lat_val < cur_val {
            return false;
        }
    }

    // If main versions are equal, compare pre-releases.
    match (cur_pre, lat_pre) {
        (None, None) => false, // Both are stable and equal
        (Some(_), None) => true, // Latest is stable, current is pre-release -> latest is newer
        (None, Some(_)) => false, // Latest is pre-release, current is stable -> latest is older
        (Some(p1), Some(p2)) => {
            // Both are pre-releases. Compare alphabetically (e.g. "beta1" vs "rc1").
            p2 > p1
        }
    }
}

/// Detects systemd slice/unit name of current process and calls `systemctl restart --no-block`.
fn restart_via_systemd() -> anyhow::Result<()> {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let mut unit_name = None;
    let mut is_user_service = false;

    for line in cgroup.lines() {
        if line.contains(".service") {
            if let Some(last_service) = line.split('/').filter(|s| s.ends_with(".service")).last() {
                unit_name = Some(last_service.to_string());
            }
            if line.contains("/user.slice/") {
                is_user_service = true;
            }
            break;
        }
    }

    if let Some(unit) = unit_name {
        info!("Detected systemd unit: {} (user service: {})", unit, is_user_service);

        let mut cmd = std::process::Command::new("systemctl");
        if is_user_service {
            cmd.arg("--user");
        }
        cmd.args(["restart", "--no-block", &unit]);

        info!("Executing systemd restart command: {:?}", cmd);
        let status = cmd.status()?;
        if status.success() {
            info!("Systemd restart command issued successfully.");
            return Ok(());
        } else {
            anyhow::bail!("systemctl restart failed with exit status: {:?}", status.code());
        }
    } else {
        anyhow::bail!("Not running under systemd or unit name not found in cgroup");
    }
}

/// Checks GitHub for newer versions, downloads and replaces the current binary,
/// and restarts via systemd if possible.
/// Returns Ok(true) if upgraded successfully, Ok(false) if already up-to-date.
pub async fn check_and_perform_upgrade(pre_release: bool) -> anyhow::Result<bool> {
    let target_artifact_name = match get_target_artifact_name() {
        Some(name) => name,
        None => {
            anyhow::bail!("Current platform architecture is not supported for auto-upgrade");
        }
    };

    let current_version = env!("CARGO_PKG_VERSION");
    info!("Checking for updates... Current version: v{}", current_version);

    // Setup reqwest client with User-Agent required by GitHub API
    let client = reqwest::Client::builder()
        .user_agent("auto-server-updater")
        .timeout(Duration::from_secs(30))
        .build()?;

    let release: Release = if pre_release {
        let url = "https://api.github.com/repos/Yifei0727/moon-toll-station/releases";
        let releases: Vec<Release> = client.get(url).send().await?.json().await?;
        releases.into_iter().next().ok_or_else(|| anyhow::anyhow!("No releases found on GitHub"))?
    } else {
        let url = "https://api.github.com/repos/Yifei0727/moon-toll-station/releases/latest";
        client.get(url).send().await?.json().await?
    };

    info!("Latest version available on GitHub (pre_release={}): {}", pre_release, release.tag_name);

    if !is_newer_version(current_version, &release.tag_name) {
        info!("Application is already up-to-date (v{}).", current_version);
        return Ok(false);
    }

    info!("New version {} detected. Preparing to upgrade...", release.tag_name);

    // Find the matching asset (we expect format: <artifact-name>.tar.gz)
    let expected_asset_name = format!("{}.tar.gz", target_artifact_name);
    let asset = release.assets.iter().find(|a| a.name == expected_asset_name)
        .ok_or_else(|| anyhow::anyhow!("Could not find expected release asset '{}' in the latest release", expected_asset_name))?;

    info!("Downloading release asset from: {}", asset.browser_download_url);
    let response_bytes = client.get(&asset.browser_download_url).send().await?.bytes().await?;

    info!("Extracting binary archive...");
    let tar_gz = flate2::read::GzDecoder::new(Cursor::new(response_bytes));
    let mut archive = tar::Archive::new(tar_gz);

    let mut binary_bytes = None;
    for entry in archive.entries()? {
        let mut file = entry?;
        let path = file.path()?.to_path_buf();
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name == target_artifact_name {
                let mut buffer = Vec::new();
                std::io::copy(&mut file, &mut buffer)?;
                binary_bytes = Some(buffer);
                break;
            }
        }
    }

    let binary_bytes = binary_bytes.ok_or_else(|| anyhow::anyhow!("Binary file '{}' not found in downloaded archive", target_artifact_name))?;

    let current_exe = std::env::current_exe()?;
    let exe_dir = current_exe.parent().map(|p| p.to_path_buf()).unwrap_or_else(std::env::temp_dir);

    info!("Writing new binary to temporary file in execution directory...");
    let mut temp_file = tempfile::NamedTempFile::new_in(&exe_dir)?;
    std::io::copy(&mut Cursor::new(binary_bytes), &mut temp_file)?;

    // Make the temporary file executable
    #[cfg(unix)]
    {
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp_file.path(), Permissions::from_mode(0o755))?;
    }

    info!("Replacing current binary atomically...");
    let (_file, temp_path) = temp_file.keep()?;
    if let Err(e) = std::fs::rename(&temp_path, &current_exe) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e.into());
    }

    info!("Binary replaced successfully! Attempting systemd restart...");
    match restart_via_systemd() {
        Ok(_) => {
            info!("Systemd restart triggered successfully.");
        }
        Err(e) => {
            warn!("Failed to restart via systemd: {}. The new version will be used upon next manual/system startup.", e);
        }
    }

    Ok(true)
}

/// Runs the background upgrade loop.
pub async fn run_upgrade_loop(interval: Duration, pre_release: bool) {
    info!("Auto-upgrade loop started with checking interval: {:?}, pre_release: {}", interval, pre_release);
    
    // We check immediately on startup, and then tick at the specified interval
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        match check_and_perform_upgrade(pre_release).await {
            Ok(upgraded) => {
                if upgraded {
                    info!("Upgrade successful. Terminating process to allow systemd or external orchestrator to restart.");
                    // Flush logging and exit.
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    std::process::exit(0);
                }
            }
            Err(e) => {
                error!("Auto-upgrade check error: {:?}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_interval() {
        assert_eq!(parse_interval("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_interval("24h").unwrap(), Duration::from_secs(24 * 3600));
        assert_eq!(parse_interval("3d").unwrap(), Duration::from_secs(3 * 86400));
        assert_eq!(parse_interval("1w").unwrap(), Duration::from_secs(7 * 86400));
        assert_eq!(parse_interval("1m").unwrap(), Duration::from_secs(30 * 86400)); // m = month
        assert_eq!(parse_interval("2m").unwrap(), Duration::from_secs(60 * 86400));

        assert_eq!(parse_interval("30m").unwrap(), Duration::from_secs(30 * 30 * 86400)); // 30 months
        assert!(parse_interval("0h").is_err()); // less than 1h is an error
    }

    #[test]
    fn test_is_newer_version() {
        assert!(is_newer_version("0.1.0", "0.1.1"));
        assert!(is_newer_version("0.1.0", "1.0.0"));
        assert!(is_newer_version("v0.1.0", "v0.2.0"));
        assert!(is_newer_version("v0.1.0", "0.1.1"));
        assert!(!is_newer_version("0.1.1", "0.1.1"));
        assert!(!is_newer_version("0.1.1", "0.1.0"));
        assert!(!is_newer_version("v1.0.0", "v0.9.9"));

        // Pre-release version tests
        assert!(is_newer_version("0.1.0-beta1", "0.1.0-rc1"));
        assert!(is_newer_version("0.1.0-beta1", "0.1.0"));
        assert!(!is_newer_version("0.1.0", "0.1.0-beta1"));
        assert!(is_newer_version("0.1.0-rc1", "0.1.1-beta1"));
        assert!(!is_newer_version("0.1.1-beta1", "0.1.0-rc1"));
    }
}
