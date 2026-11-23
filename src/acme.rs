//! Native ACME v2 (RFC 8555) client for automatic public IP TLS certificates.
//!
//! Uses Let's Encrypt's `shortlived` ACME profile (`draft-ietf-acme-profiles`)
//! and IP identifier validation (RFC 8738) over `http-01` (temporarily binding
//! `--acme-http-bind`, default `0.0.0.0:80`, only during validation) with an
//! automatic fallback to `tls-alpn-01` (RFC 8737 + RFC 8738 §6 on TCP port 443)
//! if HTTP-01 cannot bind. Supports dual-stack (IPv4 + IPv6) multi-SAN certs.

use std::{
    collections::HashMap,
    io::{Cursor, Write as _},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, anyhow, bail};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD as BASE64_URL},
};
use reqwest::header::HeaderMap;
use ring::{
    digest,
    rand::SystemRandom,
    signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair,
    },
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{RwLock, oneshot},
};
use tracing::{debug, info, warn};

use crate::{
    config::AppConfig,
    masque::build_quic_server_config,
    server::is_rfc6890_special,
    shutdown::Shutdown,
};

pub const LETSENCRYPT_PROD_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";
const SHORTLIVED_PROFILE: &str = "shortlived";
const MIN_VALIDITY_ON_STARTUP: Duration = Duration::from_secs(48 * 3600);
const RENEW_THRESHOLD: Duration = Duration::from_secs(72 * 3600);
const RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 3600);
const RENEW_RETRY_INTERVAL: Duration = Duration::from_secs(15 * 60);
const PUBLIC_IP_DETECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACME_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CHALLENGE_MAX_READ: usize = 8192;

const PUBLIC_IP_ENDPOINTS: &[&str] = &[
    "https://ifconfig.io/ip",
    "https://ifconfig.io",
    "https://api.ipify.org",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
];

// ASN.1 DER OID encodings (tag 0x06 + length + value).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_PKCS9_EXTENSION_REQUEST: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E,
];
const OID_COMMON_NAME: &[u8] = &[0x06, 0x03, 0x55, 0x04, 0x03]; // 2.5.4.3
const OID_SUBJECT_ALT_NAME_VALUE: &[u8] = &[0x55, 0x1D, 0x11]; // 2.5.29.17
const OID_BASIC_CONSTRAINTS_VALUE: &[u8] = &[0x55, 0x1D, 0x13]; // 2.5.29.19
const OID_PE_ACME_IDENTIFIER_VALUE: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1F]; // 1.3.6.1.5.5.7.1.31

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AcmeMeta {
    ip: String,
    directory_url: String,
    account_url: String,
    issued_at_unix: u64,
    not_after_unix: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AcmeDirectory {
    new_nonce: String,
    new_account: String,
    new_order: String,
    #[serde(default)]
    meta: Option<DirectoryMeta>,
}

#[derive(Debug, Deserialize)]
struct DirectoryMeta {
    #[serde(default)]
    profiles: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct OrderResponse {
    status: String,
    #[serde(default)]
    authorizations: Vec<String>,
    finalize: String,
    #[serde(default)]
    certificate: Option<String>,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationResponse {
    status: String,
    #[serde(default)]
    identifier: Option<AuthzIdentifier>,
    #[serde(default)]
    challenges: Vec<ChallengeResponse>,
}

#[derive(Debug, Deserialize)]
struct AuthzIdentifier {
    value: String,
}

#[derive(Debug, Deserialize)]
struct ChallengeResponse {
    #[serde(rename = "type")]
    challenge_type: String,
    url: String,
    token: String,
    status: String,
    #[serde(default)]
    error: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ProblemDocument {
    #[serde(rename = "type", default)]
    problem_type: String,
    #[serde(default)]
    detail: Option<String>,
}

/// Coordinates ACME IP certificate provisioning at startup and periodic
/// background renewal with in-process QUIC certificate hot-swapping.
#[derive(Debug, Clone)]
pub struct AcmeManager {
    acme_ip_spec: String,
    acme_dir: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    http_bind: SocketAddr,
    directory_url: String,
    last_requested_ips: Vec<IpAddr>,
    active_ips: Vec<IpAddr>,
}

impl AcmeManager {
    pub fn cert_path_str(&self) -> String {
        self.cert_path.to_string_lossy().into_owned()
    }

    pub fn key_path_str(&self) -> String {
        self.key_path.to_string_lossy().into_owned()
    }

    /// Ensures a valid certificate and private key for the configured IP(s)
    /// exist on disk before the QUIC listener binds, issuing a fresh
    /// certificate if missing, mismatched, or nearing expiry (< 48h remaining).
    pub async fn prepare(config: &AppConfig) -> anyhow::Result<Self> {
        let acme_ip_spec = config
            .acme_ip
            .as_deref()
            .ok_or_else(|| anyhow!("AcmeManager::prepare called without --acme-ip"))?
            .trim()
            .to_string();
        let acme_dir = PathBuf::from(&config.acme_dir);
        let cert_path = config
            .cert_chain
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| acme_dir.join("fullchain.pem"));
        let key_path = config
            .key
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(|| acme_dir.join("key.pem"));

        let target_ips = resolve_target_ips(&acme_ip_spec, &config.acme_directory_url).await?;

        let mut mgr = Self {
            acme_ip_spec,
            acme_dir,
            cert_path,
            key_path,
            http_bind: config.acme_http_bind,
            directory_url: config.acme_directory_url.clone(),
            last_requested_ips: target_ips.clone(),
            active_ips: target_ips.clone(),
        };

        match mgr.inspect_cached_cert(&target_ips).await {
            Ok(Some(remaining)) if remaining >= MIN_VALIDITY_ON_STARTUP => {
                info!(
                    ips = ?target_ips,
                    cert = %mgr.cert_path.display(),
                    remaining_hours = remaining.as_secs() / 3600,
                    "reusing cached ACME IP certificate"
                );
                return Ok(mgr);
            }
            Ok(Some(remaining)) => {
                info!(
                    ips = ?target_ips,
                    remaining_hours = remaining.as_secs() / 3600,
                    "cached ACME IP certificate is near expiry; renewing before startup"
                );
            }
            Ok(None) => {
                info!(
                    ips = ?target_ips,
                    cert = %mgr.cert_path.display(),
                    "no reusable cached ACME IP certificate found; issuing new certificate"
                );
            }
            Err(e) => {
                warn!(
                    ips = ?target_ips,
                    error = %e,
                    "failed to inspect cached ACME IP certificate; issuing new certificate"
                );
            }
        }

        mgr.issue_and_store(&target_ips).await?;
        Ok(mgr)
    }

    /// Spawns a background renewal loop that periodically checks the cached
    /// certificate's remaining lifetime (and re-checks public IPs when in
    /// `auto` mode), renews when `< 72h` remain, writes the updated PEMs, and
    /// hot-swaps the live `quinn::Endpoint` TLS configuration.
    pub fn spawn_renewal_loop(
        mut self,
        endpoint: quinn::Endpoint,
        max_mtu: Option<u16>,
        shutdown: Shutdown,
    ) {
        tokio::spawn(async move {
            let mut next_delay = RENEW_CHECK_INTERVAL;
            loop {
                tokio::select! {
                    _ = shutdown.wait() => {
                        debug!("ACME renewal loop stopping due to shutdown");
                        break;
                    }
                    _ = tokio::time::sleep(next_delay) => {}
                }

                match self.check_and_renew_once(&endpoint, max_mtu).await {
                    Ok(()) => next_delay = RENEW_CHECK_INTERVAL,
                    Err(e) => {
                        warn!(
                            ips = ?self.active_ips,
                            error = %e,
                            retry_secs = RENEW_RETRY_INTERVAL.as_secs(),
                            "ACME renewal check failed; will retry"
                        );
                        next_delay = RENEW_RETRY_INTERVAL;
                    }
                }
            }
        });
    }

    async fn check_and_renew_once(
        &mut self,
        endpoint: &quinn::Endpoint,
        max_mtu: Option<u16>,
    ) -> anyhow::Result<()> {
        let target_ips = resolve_target_ips(&self.acme_ip_spec, &self.directory_url).await?;
        let ip_changed = target_ips != self.last_requested_ips;
        let check_ips = if ip_changed {
            &target_ips
        } else {
            &self.active_ips
        };
        let remaining = self.inspect_cached_cert(check_ips).await?.unwrap_or_default();

        if !ip_changed && remaining >= RENEW_THRESHOLD {
            debug!(
                ips = ?self.active_ips,
                remaining_hours = remaining.as_secs() / 3600,
                "ACME IP certificate still valid above renewal threshold"
            );
            return Ok(());
        }

        info!(
            ips = ?target_ips,
            ip_changed,
            remaining_hours = remaining.as_secs() / 3600,
            "renewing ACME IP certificate"
        );
        self.issue_and_store(&target_ips).await?;

        let cert_str = self.cert_path_str();
        let key_str = self.key_path_str();
        let (server_cfg, _endpoint_cfg) =
            build_quic_server_config(&cert_str, &key_str, max_mtu).await?;
        endpoint.set_server_config(Some(server_cfg));
        info!(
            ips = ?self.active_ips,
            cert = %cert_str,
            "hot-swapped QUIC TLS certificate after ACME renewal"
        );
        Ok(())
    }

    async fn inspect_cached_cert(&self, expected_ips: &[IpAddr]) -> anyhow::Result<Option<Duration>> {
        let cert_bytes = match tokio::fs::read(&self.cert_path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("reading cached ACME cert"),
        };
        let key_bytes = match tokio::fs::read(&self.key_path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("reading cached ACME key"),
        };

        let mut cert_reader = std::io::BufReader::new(Cursor::new(&cert_bytes));
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .context("parsing cached certificate PEM")?;
        let Some(leaf) = certs.first() else {
            return Ok(None);
        };

        let mut key_reader = std::io::BufReader::new(Cursor::new(&key_bytes));
        let Some(key) =
            rustls_pemfile::private_key(&mut key_reader).context("parsing cached private key PEM")?
        else {
            return Ok(None);
        };

        // Ensure rustls actually accepts the cert + key pair together before relying on it.
        if rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .is_err()
        {
            return Ok(None);
        }

        if !cert_has_all_ip_sans(leaf.as_ref(), expected_ips) {
            return Ok(None);
        }

        let not_after = parse_x509_not_after_unix(leaf.as_ref())?;
        let now = now_unix()?;
        Ok(Some(Duration::from_secs(not_after.saturating_sub(now))))
    }

    async fn issue_and_store(&mut self, ips: &[IpAddr]) -> anyhow::Result<()> {
        let (issued, actual_ips) = match issue_ip_certificate(
            &self.directory_url,
            &self.acme_dir,
            self.http_bind,
            ips,
        )
        .await
        {
            Ok(issued) => (issued, ips.to_vec()),
            Err(multi_err) if ips.len() > 1 => {
                warn!(
                    ips = ?ips,
                    error = %multi_err,
                    "multi-IP ACME issuance failed; falling back to single-IP issuance"
                );
                let mut chosen: Option<(IssuedCertificate, Vec<IpAddr>)> = None;
                let mut last_err = multi_err;
                for &single_ip in ips {
                    match issue_ip_certificate(
                        &self.directory_url,
                        &self.acme_dir,
                        self.http_bind,
                        &[single_ip],
                    )
                    .await
                    {
                        Ok(issued) => {
                            chosen = Some((issued, vec![single_ip]));
                            break;
                        }
                        Err(e) => {
                            warn!(ip = %single_ip, error = %e, "single-IP fallback issuance failed");
                            last_err = e;
                        }
                    }
                }
                chosen.ok_or(last_err)?
            }
            Err(e) => return Err(e),
        };

        self.last_requested_ips = ips.to_vec();
        self.active_ips = actual_ips.clone();

        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        let meta_path = self.acme_dir.join("meta.json");
        let meta_json = serde_json::to_vec_pretty(&issued.meta)?;

        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            write_atomic(&key_path, issued.leaf_key_pem.as_bytes(), true)?;
            write_atomic(&cert_path, issued.fullchain_pem.as_bytes(), false)?;
            write_atomic(&meta_path, &meta_json, false)?;
            Ok(())
        })
        .await
        .context("cert persistence task panicked")??;

        info!(
            ips = ?actual_ips,
            cert = %self.cert_path.display(),
            key = %self.key_path.display(),
            not_after_unix = issued.meta.not_after_unix,
            "issued and persisted ACME IP certificate"
        );
        Ok(())
    }
}

struct IssuedCertificate {
    fullchain_pem: String,
    leaf_key_pem: String,
    meta: AcmeMeta,
}

/// Resolves one or more explicit IP literals (comma-separated) or auto-detects
/// public IPv4/IPv6 addresses from local interfaces (or `ifconfig.io` when behind NAT).
pub async fn resolve_target_ips(spec: &str, directory_url: &str) -> anyhow::Result<Vec<IpAddr>> {
    let trimmed = spec.trim();
    if !trimmed.eq_ignore_ascii_case("auto") {
        let mut ips = Vec::new();
        for part in trimmed.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            let ip: IpAddr = part
                .parse()
                .with_context(|| format!("--acme-ip: {part:?} is not a valid IPv4/IPv6 address"))?;
            ensure_public_for_letsencrypt(ip, directory_url)?;
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        if ips.is_empty() {
            bail!("--acme-ip did not contain any valid IP addresses");
        }
        return Ok(ips);
    }

    let local_ips = detect_local_interface_public_ips();
    if !local_ips.is_empty() {
        info!(
            ips = ?local_ips,
            source = "local-interface",
            "detected public IP(s) from local network interface for ACME"
        );
        return Ok(local_ips);
    }

    let client = reqwest::Client::builder()
        .user_agent("auto-server-acme")
        .timeout(PUBLIC_IP_DETECT_TIMEOUT)
        .build()?;

    let mut errors = Vec::new();
    for url in PUBLIC_IP_ENDPOINTS {
        match fetch_ip_from(&client, url).await {
            Ok(ip) => {
                if let Err(e) = ensure_public_for_letsencrypt(ip, directory_url) {
                    errors.push(format!("{url}: {e}"));
                    continue;
                }
                info!(ip = %ip, source = url, "detected public IP for ACME");
                return Ok(vec![ip]);
            }
            Err(e) => {
                errors.push(format!("{url}: {e}"));
            }
        }
    }

    bail!(
        "failed to auto-detect public IP from local interfaces or HTTP endpoints ({})",
        errors.join("; ")
    )
}

#[allow(dead_code)]
pub async fn resolve_target_ip(spec: &str, directory_url: &str) -> anyhow::Result<IpAddr> {
    resolve_target_ips(spec, directory_url)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no target IP resolved"))
}

/// Inspects local network interfaces and default outbound route source IPs,
/// returning up to one non-RFC-6890 public IPv4 and one non-RFC-6890 public IPv6.
pub fn detect_local_interface_public_ips() -> Vec<IpAddr> {
    select_public_interface_ips(collect_local_interface_ips())
}

#[allow(dead_code)]
pub fn detect_local_interface_public_ip() -> Option<IpAddr> {
    select_public_interface_ip(collect_local_interface_ips())
}

fn select_public_interface_ips(candidates: impl IntoIterator<Item = IpAddr>) -> Vec<IpAddr> {
    let mut first_v4: Option<IpAddr> = None;
    let mut first_v6: Option<IpAddr> = None;
    for ip in candidates {
        if is_rfc6890_special(ip) {
            continue;
        }
        match ip {
            IpAddr::V4(_) if first_v4.is_none() => first_v4 = Some(ip),
            IpAddr::V6(_) if first_v6.is_none() => first_v6 = Some(ip),
            _ => {}
        }
        if first_v4.is_some() && first_v6.is_some() {
            break;
        }
    }
    let mut out = Vec::with_capacity(2);
    if let Some(v4) = first_v4 {
        out.push(v4);
    }
    if let Some(v6) = first_v6 {
        out.push(v6);
    }
    out
}

#[cfg_attr(not(test), allow(dead_code))]
fn select_public_interface_ip(candidates: impl IntoIterator<Item = IpAddr>) -> Option<IpAddr> {
    select_public_interface_ips(candidates).into_iter().next()
}

fn collect_local_interface_ips() -> Vec<IpAddr> {
    let mut ips = Vec::new();

    // Probe the kernel's default outbound route source IP (no packets are sent).
    for probe in ["1.1.1.1:80", "8.8.8.8:53"] {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0")
            && sock.connect(probe).is_ok()
            && let Ok(local) = sock.local_addr()
        {
            ips.push(local.ip());
            break;
        }
    }
    if let Ok(sock) = std::net::UdpSocket::bind("[::]:0")
        && sock.connect("[2606:4700:4700::1111]:80").is_ok()
        && let Ok(local) = sock.local_addr()
    {
        ips.push(local.ip());
    }

    #[cfg(unix)]
    collect_unix_getifaddrs_ips(&mut ips);

    ips
}

#[cfg(unix)]
fn collect_unix_getifaddrs_ips(out: &mut Vec<IpAddr>) {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `getifaddrs` initializes `ifap` on return 0, and we free it with `freeifaddrs`.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 || ifap.is_null() {
        return;
    }

    let up_mask = libc::IFF_UP as libc::c_uint;
    let loopback_mask = libc::IFF_LOOPBACK as libc::c_uint;

    let mut cur = ifap;
    while !cur.is_null() {
        // SAFETY: linked list nodes returned by `getifaddrs` remain valid until `freeifaddrs`.
        let ifa = unsafe { &*cur };
        if (ifa.ifa_flags & up_mask) != 0
            && (ifa.ifa_flags & loopback_mask) == 0
            && !ifa.ifa_addr.is_null()
        {
            let family = unsafe { i32::from((*ifa.ifa_addr).sa_family) };
            if family == libc::AF_INET {
                let addr_in =
                    unsafe { std::ptr::read_unaligned(ifa.ifa_addr as *const libc::sockaddr_in) };
                out.push(IpAddr::V4(Ipv4Addr::from(addr_in.sin_addr.s_addr.to_ne_bytes())));
            } else if family == libc::AF_INET6 {
                let addr_in6 =
                    unsafe { std::ptr::read_unaligned(ifa.ifa_addr as *const libc::sockaddr_in6) };
                out.push(IpAddr::V6(Ipv6Addr::from(addr_in6.sin6_addr.s6_addr)));
            }
        }
        cur = ifa.ifa_next;
    }

    // SAFETY: `ifap` was allocated by `getifaddrs`.
    unsafe { libc::freeifaddrs(ifap) };
}

async fn fetch_ip_from(client: &reqwest::Client, url: &str) -> anyhow::Result<IpAddr> {
    let resp = client
        .get(url)
        .header("accept", "text/plain")
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        bail!("HTTP {status}");
    }
    let body = resp.text().await?;
    let ip: IpAddr = body
        .trim()
        .parse()
        .with_context(|| format!("invalid IP body {:?}", body.trim()))?;
    Ok(ip)
}

fn ensure_public_for_letsencrypt(ip: IpAddr, directory_url: &str) -> anyhow::Result<()> {
    if directory_url.to_ascii_lowercase().contains("letsencrypt.org") && is_rfc6890_special(ip) {
        bail!(
            "{ip} is a special-purpose/private/loopback (RFC 6890) address; \
             Let's Encrypt only issues certificates for publicly routable IP addresses"
        );
    }
    Ok(())
}

async fn issue_ip_certificate(
    directory_url: &str,
    acme_dir: &Path,
    http_bind: SocketAddr,
    ips: &[IpAddr],
) -> anyhow::Result<IssuedCertificate> {
    if ips.is_empty() {
        bail!("issue_ip_certificate requires at least one IP address");
    }
    let rng = SystemRandom::new();
    let account_key = load_or_create_account_key(&acme_dir.join("account.pem"), &rng).await?;

    let mut client = AcmeClient::connect(directory_url).await?;
    let account_url = client.ensure_account(&account_key).await?;

    if client
        .directory
        .meta
        .as_ref()
        .and_then(|m| m.profiles.as_ref())
        .is_some_and(|profiles| !profiles.contains_key(SHORTLIVED_PROFILE))
    {
        warn!(
            directory = directory_url,
            profile = SHORTLIVED_PROFILE,
            "ACME directory metadata does not advertise the 'shortlived' profile; proceeding anyway"
        );
    }

    let identifiers: Vec<_> = ips
        .iter()
        .map(|ip| serde_json::json!({ "type": "ip", "value": ip.to_string() }))
        .collect();
    let order_payload = serde_json::json!({
        "identifiers": identifiers,
        "profile": SHORTLIVED_PROFILE,
    });
    let (order_url, mut order) = client
        .new_order(&account_key, &account_url, &order_payload)
        .await?;

    if order.status == "pending" {
        for (idx, authz_url) in order.authorizations.iter().enumerate() {
            let fallback_ip = ips.get(idx).copied().or_else(|| ips.first().copied());
            complete_authorization(
                &mut client,
                &account_key,
                &account_url,
                authz_url,
                http_bind,
                fallback_ip,
            )
            .await?;
        }
    }

    // Wait briefly for order readiness if authorizations just became valid.
    for _ in 0..10 {
        if order.status == "ready" || order.status == "valid" {
            break;
        }
        if order.status == "invalid" {
            bail!("ACME order became invalid: {:?}", order.error);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        order = client
            .post_as_get_json(&account_key, &account_url, &order_url)
            .await?;
    }

    if order.status == "pending" {
        bail!("ACME order stayed pending after all authorizations succeeded");
    }

    // Generate leaf key and multi-SAN IP CSR.
    let leaf_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
        .map_err(|_| anyhow!("failed to generate ECDSA P-256 leaf key"))?;
    let leaf_key_pem = encode_pem("PRIVATE KEY", leaf_pkcs8.as_ref());
    let csr_der = build_ips_csr_der(ips, leaf_pkcs8.as_ref())?;

    if order.status == "ready" {
        let finalize_payload = serde_json::json!({
            "csr": BASE64_URL.encode(&csr_der),
        });
        order = client
            .post_json(&account_key, Some(&account_url), &order.finalize, Some(&finalize_payload))
            .await?
            .json()?;
    }

    for attempt in 0..30 {
        if order.status == "valid" {
            break;
        }
        if order.status == "invalid" {
            bail!("ACME order finalization failed: {:?}", order.error);
        }
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        order = client
            .post_as_get_json(&account_key, &account_url, &order_url)
            .await?;
    }

    if order.status != "valid" {
        bail!("timed out waiting for ACME order to become valid (status={})", order.status);
    }

    let cert_url = order
        .certificate
        .ok_or_else(|| anyhow!("valid ACME order did not include a certificate URL"))?;
    let fullchain_pem = client
        .post_as_get_text(
            &account_key,
            &account_url,
            &cert_url,
            Some("application/pem-certificate-chain"),
        )
        .await?;

    // Validate the returned certificate chain + leaf key locally before writing.
    let mut cert_reader = std::io::BufReader::new(Cursor::new(fullchain_pem.as_bytes()));
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse issued ACME certificate PEM")?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow!("ACME server returned empty certificate chain"))?;

    if !cert_has_all_ip_sans(leaf.as_ref(), ips) {
        bail!("issued certificate does not contain all expected IP SANs {ips:?}");
    }
    let not_after_unix = parse_x509_not_after_unix(leaf.as_ref())?;

    let mut key_reader = std::io::BufReader::new(Cursor::new(leaf_key_pem.as_bytes()));
    let leaf_priv = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow!("failed to re-parse generated leaf private key"))?;
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, leaf_priv)
        .context("issued certificate does not match generated private key")?;

    let ip_joined = ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
    let meta = AcmeMeta {
        ip: ip_joined,
        directory_url: directory_url.to_string(),
        account_url,
        issued_at_unix: now_unix()?,
        not_after_unix,
    };

    Ok(IssuedCertificate {
        fullchain_pem,
        leaf_key_pem,
        meta,
    })
}

async fn complete_authorization(
    client: &mut AcmeClient,
    account_key: &AccountKey,
    account_url: &str,
    authz_url: &str,
    http_bind: SocketAddr,
    fallback_ip: Option<IpAddr>,
) -> anyhow::Result<()> {
    let authz: AuthorizationResponse = client
        .post_as_get_json(account_key, account_url, authz_url)
        .await?;
    if authz.status == "valid" {
        return Ok(());
    }
    if authz.status != "pending" {
        bail!("ACME authorization {authz_url} has unexpected status {:?}", authz.status);
    }

    let authz_ip = if let Some(ref ident) = authz.identifier {
        ident
            .value
            .parse::<IpAddr>()
            .with_context(|| format!("invalid ACME authorization IP identifier {:?}", ident.value))?
    } else {
        fallback_ip.ok_or_else(|| anyhow!("ACME authorization {authz_url} missing identifier"))?
    };

    let http_chall = authz
        .challenges
        .iter()
        .find(|c| c.challenge_type == "http-01")
        .map(|c| (c.url.clone(), c.token.clone(), c.status.clone()));
    let alpn_chall = authz
        .challenges
        .iter()
        .find(|c| c.challenge_type == "tls-alpn-01")
        .map(|c| (c.url.clone(), c.token.clone(), c.status.clone()));

    if let Some((chall_url, token, status)) = http_chall {
        if status == "valid" {
            return Ok(());
        }
        let key_auth = account_key.key_authorization(&token);
        match Http01Server::bind_with_fallback(http_bind, authz_ip).await {
            Ok(http_server) => {
                http_server.register_token(token, key_auth).await;
                let res = trigger_and_poll_authorization(
                    client,
                    account_key,
                    account_url,
                    authz_url,
                    &chall_url,
                    "http-01",
                )
                .await;
                http_server.shutdown().await;
                return res;
            }
            Err(http_err) => {
                if let Some((alpn_url, alpn_token, alpn_status)) = alpn_chall {
                    info!(
                        ip = %authz_ip,
                        http_bind = %http_bind,
                        error = %http_err,
                        "HTTP-01 listener unavailable; falling back to TLS-ALPN-01 on TCP port 443"
                    );
                    if alpn_status == "valid" {
                        return Ok(());
                    }
                    let alpn_key_auth = account_key.key_authorization(&alpn_token);
                    let alpn_server = TlsAlpn01Server::bind_for_ip(authz_ip, &alpn_key_auth)
                        .await
                        .with_context(|| {
                            format!("HTTP-01 failed ({http_err}) and TLS-ALPN-01 fallback failed")
                        })?;
                    let res = trigger_and_poll_authorization(
                        client,
                        account_key,
                        account_url,
                        authz_url,
                        &alpn_url,
                        "tls-alpn-01",
                    )
                    .await;
                    alpn_server.shutdown().await;
                    return res;
                }
                return Err(http_err);
            }
        }
    }

    if let Some((alpn_url, alpn_token, alpn_status)) = alpn_chall {
        if alpn_status == "valid" {
            return Ok(());
        }
        let alpn_key_auth = account_key.key_authorization(&alpn_token);
        let alpn_server = TlsAlpn01Server::bind_for_ip(authz_ip, &alpn_key_auth).await?;
        let res = trigger_and_poll_authorization(
            client,
            account_key,
            account_url,
            authz_url,
            &alpn_url,
            "tls-alpn-01",
        )
        .await;
        alpn_server.shutdown().await;
        return res;
    }

    bail!("ACME server offered neither http-01 nor tls-alpn-01 challenge for {authz_url}")
}

async fn trigger_and_poll_authorization(
    client: &mut AcmeClient,
    account_key: &AccountKey,
    account_url: &str,
    authz_url: &str,
    challenge_url: &str,
    challenge_type: &str,
) -> anyhow::Result<()> {
    let empty_obj = serde_json::json!({});
    let _trigger: serde_json::Value = client
        .post_json(account_key, Some(account_url), challenge_url, Some(&empty_obj))
        .await?
        .json()?;

    for _ in 0..45 {
        let resp = client
            .post_as_get_raw(account_key, account_url, authz_url, None)
            .await?;
        let retry_after = parse_retry_after(&resp.headers).unwrap_or(Duration::from_secs(2));
        let authz: AuthorizationResponse = serde_json::from_slice(&resp.body)
            .context("decoding ACME authorization poll response")?;

        match authz.status.as_str() {
            "valid" => return Ok(()),
            "invalid" => {
                let err_detail = authz
                    .challenges
                    .into_iter()
                    .find(|c| c.challenge_type == challenge_type)
                    .and_then(|c| c.error);
                bail!("ACME {challenge_type} challenge failed: {err_detail:?}");
            }
            "pending" | "processing" => {
                tokio::time::sleep(
                    retry_after.clamp(Duration::from_millis(50), Duration::from_secs(10)),
                )
                .await;
            }
            other => bail!("unexpected ACME authorization status {other:?}"),
        }
    }

    bail!("timed out polling ACME {challenge_type} authorization {authz_url}")
}

fn parse_retry_after(headers: &HeaderMap) -> Option<Duration> {
    let val = headers.get("retry-after")?.to_str().ok()?.trim();
    let secs: u64 = val.parse().ok()?;
    Some(Duration::from_secs(secs))
}

struct AcmeClient {
    http: reqwest::Client,
    directory: AcmeDirectory,
    nonce: Option<String>,
}

struct RawResponse {
    headers: HeaderMap,
    body: Vec<u8>,
}

impl RawResponse {
    fn json<T: for<'de> Deserialize<'de>>(&self) -> anyhow::Result<T> {
        serde_json::from_slice(&self.body).context("decoding ACME JSON response")
    }
}

impl AcmeClient {
    async fn connect(directory_url: &str) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent("auto-server-acme")
            .timeout(ACME_HTTP_TIMEOUT)
            .build()?;
        let resp = http
            .get(directory_url)
            .send()
            .await
            .with_context(|| format!("fetching ACME directory {directory_url}"))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("ACME directory request failed ({status}): {body}");
        }
        let directory: AcmeDirectory = resp
            .json()
            .await
            .context("parsing ACME directory JSON")?;
        Ok(Self {
            http,
            directory,
            nonce: None,
        })
    }

    async fn fetch_nonce(&mut self) -> anyhow::Result<String> {
        if let Some(n) = self.nonce.take() {
            return Ok(n);
        }
        let resp = self
            .http
            .head(&self.directory.new_nonce)
            .send()
            .await
            .context("fetching ACME newNonce")?;
        if let Some(n) = extract_nonce(resp.headers()) {
            return Ok(n);
        }
        let resp = self.http.get(&self.directory.new_nonce).send().await?;
        extract_nonce(resp.headers())
            .ok_or_else(|| anyhow!("ACME newNonce response lacked Replay-Nonce header"))
    }

    async fn ensure_account(&mut self, account_key: &AccountKey) -> anyhow::Result<String> {
        let payload = serde_json::json!({ "termsOfServiceAgreed": true });
        let resp = self
            .post_json(account_key, None, &self.directory.new_account.clone(), Some(&payload))
            .await?;
        let location = resp
            .headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow!("ACME newAccount response missing Location header"))?;
        Ok(location.to_string())
    }

    async fn new_order(
        &mut self,
        account_key: &AccountKey,
        account_url: &str,
        payload: &serde_json::Value,
    ) -> anyhow::Result<(String, OrderResponse)> {
        let resp = self
            .post_json(
                account_key,
                Some(account_url),
                &self.directory.new_order.clone(),
                Some(payload),
            )
            .await?;
        let order_url = resp
            .headers
            .get("location")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow!("ACME newOrder response missing Location header"))?
            .to_string();
        let order: OrderResponse = resp.json()?;
        Ok((order_url, order))
    }

    async fn post_as_get_json<T: for<'de> Deserialize<'de>>(
        &mut self,
        account_key: &AccountKey,
        account_url: &str,
        url: &str,
    ) -> anyhow::Result<T> {
        let raw = self
            .post_as_get_raw(account_key, account_url, url, None)
            .await?;
        raw.json()
    }

    async fn post_as_get_text(
        &mut self,
        account_key: &AccountKey,
        account_url: &str,
        url: &str,
        accept: Option<&str>,
    ) -> anyhow::Result<String> {
        let raw = self
            .post_as_get_raw(account_key, account_url, url, accept)
            .await?;
        String::from_utf8(raw.body).context("ACME text response was not valid UTF-8")
    }

    async fn post_as_get_raw(
        &mut self,
        account_key: &AccountKey,
        account_url: &str,
        url: &str,
        accept: Option<&str>,
    ) -> anyhow::Result<RawResponse> {
        self.post_inner(account_key, Some(account_url), url, None, accept)
            .await
    }

    async fn post_json(
        &mut self,
        account_key: &AccountKey,
        kid: Option<&str>,
        url: &str,
        payload: Option<&serde_json::Value>,
    ) -> anyhow::Result<RawResponse> {
        self.post_inner(account_key, kid, url, payload, None).await
    }

    async fn post_inner(
        &mut self,
        account_key: &AccountKey,
        kid: Option<&str>,
        url: &str,
        payload: Option<&serde_json::Value>,
        accept: Option<&str>,
    ) -> anyhow::Result<RawResponse> {
        for attempt in 0..3 {
            let nonce = self.fetch_nonce().await?;
            let jws_body = account_key.sign_jws(url, &nonce, kid, payload)?;
            let mut req = self
                .http
                .post(url)
                .header("content-type", "application/jose+json");
            if let Some(accept_val) = accept {
                req = req.header("accept", accept_val);
            }
            let resp = req.json(&jws_body).send().await?;
            let status = resp.status();
            let headers = resp.headers().clone();
            if let Some(next_nonce) = extract_nonce(&headers) {
                self.nonce = Some(next_nonce);
            }
            let body = resp.bytes().await?.to_vec();

            if status.is_success() {
                return Ok(RawResponse { headers, body });
            }

            if let Ok(problem) = serde_json::from_slice::<ProblemDocument>(&body)
                && problem.problem_type.ends_with("badNonce")
                && attempt < 2
            {
                debug!(url, attempt, "ACME badNonce; retrying with fresh nonce");
                continue;
            }

            let msg = if let Ok(problem) = serde_json::from_slice::<ProblemDocument>(&body) {
                format!(
                    "{} ({})",
                    problem.problem_type,
                    problem.detail.as_deref().unwrap_or("no detail")
                )
            } else {
                String::from_utf8_lossy(&body).into_owned()
            };
            bail!("ACME request to {url} failed with {status}: {msg}");
        }
        unreachable!("loop returns on success or final error")
    }
}

fn extract_nonce(headers: &HeaderMap) -> Option<String> {
    headers
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Account signing key (ES256 / P-256) with RFC 7638 JWK thumbprint and JWS support.
struct AccountKey {
    pair: EcdsaKeyPair,
    x_b64: String,
    y_b64: String,
    thumbprint: String,
}

impl AccountKey {
    fn from_pkcs8(der: &[u8], rng: &SystemRandom) -> anyhow::Result<Self> {
        let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, rng)
            .map_err(|e| anyhow!("invalid P-256 PKCS#8 account key: {e}"))?;
        let pub_bytes = pair.public_key().as_ref();
        if pub_bytes.len() != 65 || pub_bytes[0] != 0x04 {
            bail!("unexpected P-256 uncompressed public key length {}", pub_bytes.len());
        }
        let x_b64 = BASE64_URL.encode(&pub_bytes[1..33]);
        let y_b64 = BASE64_URL.encode(&pub_bytes[33..65]);
        // RFC 7638 canonical JWK JSON (lexicographical keys, zero whitespace).
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{x_b64}","y":"{y_b64}"}}"#
        );
        let hash = digest::digest(&digest::SHA256, canonical.as_bytes());
        let thumbprint = BASE64_URL.encode(hash.as_ref());
        Ok(Self {
            pair,
            x_b64,
            y_b64,
            thumbprint,
        })
    }

    fn jwk_json(&self) -> serde_json::Value {
        serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": self.x_b64,
            "y": self.y_b64,
        })
    }

    fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint)
    }

    fn sign_jws(
        &self,
        url: &str,
        nonce: &str,
        kid: Option<&str>,
        payload: Option<&serde_json::Value>,
    ) -> anyhow::Result<serde_json::Value> {
        let protected = match kid {
            Some(kid) => serde_json::json!({
                "alg": "ES256",
                "kid": kid,
                "nonce": nonce,
                "url": url,
            }),
            None => serde_json::json!({
                "alg": "ES256",
                "jwk": self.jwk_json(),
                "nonce": nonce,
                "url": url,
            }),
        };
        let protected_b64 = BASE64_URL.encode(serde_json::to_vec(&protected)?);
        let payload_b64 = match payload {
            Some(val) => BASE64_URL.encode(serde_json::to_vec(val)?),
            None => String::new(),
        };
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let rng = SystemRandom::new();
        let sig = self
            .pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|_| anyhow!("ECDSA JWS signing failed"))?;
        Ok(serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": BASE64_URL.encode(sig.as_ref()),
        }))
    }
}

async fn load_or_create_account_key(
    path: &Path,
    rng: &SystemRandom,
) -> anyhow::Result<AccountKey> {
    if let Ok(bytes) = tokio::fs::read(path).await {
        let mut reader = std::io::BufReader::new(Cursor::new(&bytes));
        let key = rustls_pemfile::private_key(&mut reader)
            .with_context(|| format!("parsing ACME account key {}", path.display()))?
            .ok_or_else(|| anyhow!("no private key in {}", path.display()))?;
        let pkcs8_der = match &key {
            rustls::pki_types::PrivateKeyDer::Pkcs8(k) => k.secret_pkcs8_der(),
            _ => bail!("ACME account key {} must be PKCS#8 PEM", path.display()),
        };
        return AccountKey::from_pkcs8(pkcs8_der, rng);
    }

    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng)
        .map_err(|_| anyhow!("failed to generate ACME account key"))?;
    let pem = encode_pem("PRIVATE KEY", pkcs8.as_ref());
    let path_owned = path.to_path_buf();
    let pem_bytes = pem.into_bytes();
    tokio::task::spawn_blocking(move || write_atomic(&path_owned, &pem_bytes, true))
        .await
        .context("account key persistence task panicked")??;
    AccountKey::from_pkcs8(pkcs8.as_ref(), rng)
}

/// Temporary HTTP-01 challenge responder bound only during validation.
struct Http01Server {
    tokens: Arc<RwLock<HashMap<String, String>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Http01Server {
    async fn bind_with_fallback(bind_addr: SocketAddr, target_ip: IpAddr) -> anyhow::Result<Self> {
        match Self::bind(bind_addr).await {
            Ok(srv) => Ok(srv),
            Err(first_err)
                if bind_addr.ip().is_unspecified() && !target_ip.is_unspecified() =>
            {
                let specific = SocketAddr::new(target_ip, bind_addr.port());
                match Self::bind(specific).await {
                    Ok(srv) => Ok(srv),
                    Err(_) => Err(first_err),
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn bind(bind_addr: SocketAddr) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("failed to bind ACME HTTP-01 listener on {bind_addr}"))?;
        let local_addr = listener.local_addr()?;
        info!(listen = %local_addr, "started temporary ACME HTTP-01 listener");

        let tokens: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
        let tokens_clone = Arc::clone(&tokens);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, _peer)) => {
                                let tokens = Arc::clone(&tokens_clone);
                                tokio::spawn(async move {
                                    let _ = serve_http01_conn(stream, tokens).await;
                                });
                            }
                            Err(e) => {
                                warn!(error = %e, "ACME HTTP-01 accept error");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            tokens,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        })
    }

    async fn register_token(&self, token: String, key_auth: String) {
        self.tokens.write().await.insert(token, key_auth);
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
        debug!("stopped temporary ACME HTTP-01 listener");
    }
}

impl Drop for Http01Server {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Temporary TLS-ALPN-01 (RFC 8737 + RFC 8738 §6) responder bound on TCP port 443.
struct TlsAlpn01Server {
    shutdown_tx: Option<oneshot::Sender<()>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

/// Builds a TLS-ALPN-01 (`acme-tls/1`) `ServerConfig` for a self-signed challenge certificate.
///
/// Uses `CertifiedKey::new` + `SingleCertAndKey` rather than `.with_single_cert()` because
/// `.with_single_cert()` validates the end-entity certificate via `webpki`, which rejects
/// RFC 8737's critical `id-pe-acmeIdentifier` extension (`1.3.6.1.5.5.7.1.31`).
fn build_tls_alpn_01_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> anyhow::Result<rustls::ServerConfig> {
    let signing_key = rustls::crypto::ring::sign::any_ecdsa_type(&key)
        .map_err(|e| anyhow!("failed to load TLS-ALPN-01 ECDSA key: {e}"))?;
    let certified_key = rustls::sign::CertifiedKey::new(vec![cert], signing_key);
    let resolver = rustls::sign::SingleCertAndKey::from(certified_key);
    let mut tls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    tls_cfg.alpn_protocols = vec![b"acme-tls/1".to_vec()];
    Ok(tls_cfg)
}

impl TlsAlpn01Server {
    async fn bind_for_ip(ip: IpAddr, key_auth: &str) -> anyhow::Result<Self> {
        let rng = SystemRandom::new();
        let leaf_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|_| anyhow!("failed to generate TLS-ALPN-01 ephemeral P-256 key"))?;
        let cert_der = build_tls_alpn_01_cert_der(ip, key_auth, leaf_pkcs8.as_ref())?;
        let cert = CertificateDer::from(cert_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_pkcs8.as_ref().to_vec()));

        let tls_cfg = Arc::new(build_tls_alpn_01_server_config(cert, key)?);

        Self::bind_with_tls(ip, 443, tls_cfg).await
    }

    async fn bind_with_tls(
        ip: IpAddr,
        port: u16,
        tls_cfg: Arc<rustls::ServerConfig>,
    ) -> anyhow::Result<Self> {
        let specific = SocketAddr::new(ip, port);
        let listener = match TcpListener::bind(specific).await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrNotAvailable => {
                let fallback_ip = match ip {
                    IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                };
                let wildcard = SocketAddr::new(fallback_ip, port);
                TcpListener::bind(wildcard).await.with_context(|| {
                    format!("failed to bind ACME TLS-ALPN-01 listener on {specific} or {wildcard}")
                })?
            }
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to bind ACME TLS-ALPN-01 listener on {specific}"));
            }
        };

        let local_addr = listener.local_addr()?;
        info!(listen = %local_addr, ip = %ip, "started temporary ACME TLS-ALPN-01 listener");

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept_res = listener.accept() => {
                        match accept_res {
                            Ok((stream, _peer)) => {
                                let cfg = Arc::clone(&tls_cfg);
                                tokio::spawn(async move {
                                    let _ = serve_tls_alpn01_conn(stream, cfg).await;
                                });
                            }
                            Err(e) => {
                                warn!(error = %e, "ACME TLS-ALPN-01 accept error");
                                break;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        })
    }

    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            let _ = h.await;
        }
        debug!("stopped temporary ACME TLS-ALPN-01 listener");
    }
}

impl Drop for TlsAlpn01Server {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

async fn serve_tls_alpn01_conn(
    mut stream: tokio::net::TcpStream,
    tls_cfg: Arc<rustls::ServerConfig>,
) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut conn = rustls::ServerConnection::new(tls_cfg)?;
        let mut rd_buf = [0u8; 4096];
        let mut wr_buf = Vec::with_capacity(4096);

        while conn.is_handshaking() {
            while conn.wants_write() {
                wr_buf.clear();
                conn.write_tls(&mut wr_buf)?;
                if !wr_buf.is_empty() {
                    stream.write_all(&wr_buf).await?;
                    stream.flush().await?;
                }
            }
            if !conn.is_handshaking() {
                break;
            }
            if conn.wants_read() {
                let n = stream.read(&mut rd_buf).await?;
                if n == 0 {
                    break;
                }
                let mut pos = 0usize;
                while pos < n {
                    let mut cursor = Cursor::new(&rd_buf[pos..n]);
                    let read = conn.read_tls(&mut cursor)?;
                    pos += read;
                    conn.process_new_packets()?;
                    if read == 0 {
                        break;
                    }
                }
            }
        }

        while conn.wants_write() {
            wr_buf.clear();
            conn.write_tls(&mut wr_buf)?;
            if !wr_buf.is_empty() {
                stream.write_all(&wr_buf).await?;
            }
        }
        conn.send_close_notify();
        while conn.wants_write() {
            wr_buf.clear();
            conn.write_tls(&mut wr_buf)?;
            if !wr_buf.is_empty() {
                stream.write_all(&wr_buf).await?;
            }
        }
        let _ = stream.flush().await;
        let _ = stream.shutdown().await;
        Ok::<(), anyhow::Error>(())
    })
    .await
    .context("TLS-ALPN-01 handshake timed out")??;
    Ok(())
}

async fn serve_http01_conn(
    mut stream: tokio::net::TcpStream,
    tokens: Arc<RwLock<HashMap<String, String>>>,
) -> anyhow::Result<()> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let read_res = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= CHALLENGE_MAX_READ {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    })
    .await;
    if read_res.is_err() {
        return Ok(());
    }

    let req_str = String::from_utf8_lossy(&buf);
    let first_line = req_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_target = parts.next().unwrap_or("");
    let path = raw_target.split('?').next().unwrap_or(raw_target);

    if (method == "GET" || method == "HEAD")
        && let Some(token) = path.strip_prefix("/.well-known/acme-challenge/")
        && let Some(key_auth) = tokens.read().await.get(token).cloned()
    {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            key_auth.len()
        );
        stream.write_all(header.as_bytes()).await?;
        if method == "GET" {
            stream.write_all(key_auth.as_bytes()).await?;
        }
        let _ = stream.flush().await;
        return Ok(());
    }

    stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    let _ = stream.flush().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// File persistence & PEM helpers
// ---------------------------------------------------------------------------

fn encode_pem(label: &str, der: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(der);
    let mut out = String::with_capacity(b64.len() + label.len() * 2 + 64);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

fn write_atomic(dest: &Path, content: &[u8], secret: bool) -> anyhow::Result<()> {
    let parent = dest
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temp file in {}", parent.display()))?;
    tmp.write_all(content)?;
    tmp.as_file().sync_all()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if secret { 0o600 } else { 0o644 };
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting mode {:o} on {}", mode, dest.display()))?;
    }
    #[cfg(not(unix))]
    let _ = secret;

    tmp.persist(dest)
        .map_err(|e| anyhow!("failed to persist {}: {}", dest.display(), e.error))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal pure-Rust ASN.1 DER builder (CSR) & reader (X.509 notAfter + IP SAN)
// ---------------------------------------------------------------------------

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 128 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first_nz = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
        let slice = &bytes[first_nz..];
        out.push(0x80 | (slice.len() as u8));
        out.extend_from_slice(slice);
    }
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 5 + content.len());
    out.push(tag);
    der_len(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

fn der_seq(content: &[u8]) -> Vec<u8> {
    der_tlv(0x30, content)
}

fn der_set(content: &[u8]) -> Vec<u8> {
    der_tlv(0x31, content)
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(1 + bytes.len());
    content.push(0x00);
    content.extend_from_slice(bytes);
    der_tlv(0x03, &content)
}

fn ec_p256_spki_der(pub_bytes: &[u8]) -> Vec<u8> {
    let mut spki_alg_inner = Vec::new();
    spki_alg_inner.extend_from_slice(OID_EC_PUBLIC_KEY);
    spki_alg_inner.extend_from_slice(OID_PRIME256V1);
    let mut spki_inner = der_seq(&spki_alg_inner);
    spki_inner.extend_from_slice(&der_bit_string(pub_bytes));
    der_seq(&spki_inner)
}

fn ip_general_names_der(ips: &[IpAddr]) -> Vec<u8> {
    let mut gns_inner = Vec::new();
    for ip in ips {
        let ip_octets: &[u8] = match ip {
            IpAddr::V4(v4) => &v4.octets(),
            IpAddr::V6(v6) => &v6.octets(),
        };
        gns_inner.extend_from_slice(&der_tlv(0x87, ip_octets));
    }
    der_seq(&gns_inner)
}

/// Builds a PKCS#10 DER CSR with an empty Subject Name and a critical
/// `subjectAltName` IPAddress extension containing all given IPs (RFC 5280 §4.1.2.6 / RFC 8738).
pub fn build_ips_csr_der(ips: &[IpAddr], pkcs8_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    if ips.is_empty() {
        bail!("build_ips_csr_der requires at least one IP address");
    }
    let rng = SystemRandom::new();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_der, &rng)
        .map_err(|e| anyhow!("invalid P-256 PKCS#8 leaf key for CSR: {e}"))?;
    let spki = ec_p256_spki_der(pair.public_key().as_ref());
    let general_names = ip_general_names_der(ips);

    // Extension: subjectAltName (critical = TRUE, since subject is empty)
    let mut san_ext_inner = der_tlv(0x06, OID_SUBJECT_ALT_NAME_VALUE);
    san_ext_inner.extend_from_slice(&[0x01, 0x01, 0xFF]); // BOOLEAN TRUE
    san_ext_inner.extend_from_slice(&der_tlv(0x04, &general_names));
    let san_ext = der_seq(&san_ext_inner);
    let extensions = der_seq(&san_ext);

    // Attribute: extensionRequest (1.2.840.113549.1.9.14)
    let mut attr_inner = OID_PKCS9_EXTENSION_REQUEST.to_vec();
    attr_inner.extend_from_slice(&der_set(&extensions));
    let ext_req_attr = der_seq(&attr_inner);
    let attributes = der_tlv(0xA0, &ext_req_attr);

    // CertificationRequestInfo
    let mut cri_inner = Vec::new();
    cri_inner.extend_from_slice(&[0x02, 0x01, 0x00]); // version 0
    cri_inner.extend_from_slice(&[0x30, 0x00]); // empty subject Name
    cri_inner.extend_from_slice(&spki);
    cri_inner.extend_from_slice(&attributes);
    let cri = der_seq(&cri_inner);

    // Signature
    let sig = pair
        .sign(&rng, &cri)
        .map_err(|_| anyhow!("CSR signing failed"))?;
    let sig_alg = der_seq(OID_ECDSA_WITH_SHA256);
    let sig_bits = der_bit_string(sig.as_ref());

    let mut csr_inner = cri;
    csr_inner.extend_from_slice(&sig_alg);
    csr_inner.extend_from_slice(&sig_bits);
    Ok(der_seq(&csr_inner))
}

/// Convenience wrapper for building a single-IP CSR.
#[allow(dead_code)]
pub fn build_ip_csr_der(ip: IpAddr, pkcs8_der: &[u8]) -> anyhow::Result<Vec<u8>> {
    build_ips_csr_der(&[ip], pkcs8_der)
}

/// Builds a self-signed X.509 v3 TLS-ALPN-01 validation certificate
/// (RFC 8737 + RFC 8738 §6) with a single `iPAddress` SAN and critical
/// `id-pe-acmeIdentifier` extension wrapping `SHA256(key_auth)`.
pub fn build_tls_alpn_01_cert_der(
    ip: IpAddr,
    key_auth: &str,
    pkcs8_der: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let rng = SystemRandom::new();
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_der, &rng)
        .map_err(|e| anyhow!("invalid P-256 PKCS#8 key for TLS-ALPN-01 cert: {e}"))?;
    let spki = ec_p256_spki_der(pair.public_key().as_ref());

    let now = now_unix()?;
    let not_before = unix_to_utctime(now.saturating_sub(3600));
    let not_after = unix_to_utctime(now + 86_400);
    let mut validity_inner = der_tlv(0x17, not_before.as_bytes());
    validity_inner.extend_from_slice(&der_tlv(0x17, not_after.as_bytes()));
    let validity = der_seq(&validity_inner);

    let mut atv_inner = OID_COMMON_NAME.to_vec();
    atv_inner.extend_from_slice(&der_tlv(0x0C, b"acme-tls-alpn"));
    let name = der_seq(&der_set(&der_seq(&atv_inner)));

    // Extension 1: basicConstraints (CA=FALSE, critical=TRUE)
    let mut bc_ext = der_tlv(0x06, OID_BASIC_CONSTRAINTS_VALUE);
    bc_ext.extend_from_slice(&[0x01, 0x01, 0xFF]);
    bc_ext.extend_from_slice(&der_tlv(0x04, &der_seq(&[])));

    // Extension 2: subjectAltName (single iPAddress [7], critical=TRUE)
    let general_names = ip_general_names_der(&[ip]);
    let mut san_ext = der_tlv(0x06, OID_SUBJECT_ALT_NAME_VALUE);
    san_ext.extend_from_slice(&[0x01, 0x01, 0xFF]);
    san_ext.extend_from_slice(&der_tlv(0x04, &general_names));

    // Extension 3: id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31, critical=TRUE)
    let key_auth_sha256 = digest::digest(&digest::SHA256, key_auth.as_bytes());
    let inner_octet = der_tlv(0x04, key_auth_sha256.as_ref());
    let mut acme_ext = der_tlv(0x06, OID_PE_ACME_IDENTIFIER_VALUE);
    acme_ext.extend_from_slice(&[0x01, 0x01, 0xFF]);
    acme_ext.extend_from_slice(&der_tlv(0x04, &inner_octet));

    let mut exts_inner = der_seq(&bc_ext);
    exts_inner.extend_from_slice(&der_seq(&san_ext));
    exts_inner.extend_from_slice(&der_seq(&acme_ext));
    let extensions = der_tlv(0xA3, &der_seq(&exts_inner));

    let sig_alg = der_seq(OID_ECDSA_WITH_SHA256);

    let mut tbs_inner = Vec::new();
    tbs_inner.extend_from_slice(&der_tlv(0xA0, &[0x02, 0x01, 0x02])); // v3
    tbs_inner.extend_from_slice(&[0x02, 0x01, 0x01]); // serial 1
    tbs_inner.extend_from_slice(&sig_alg);
    tbs_inner.extend_from_slice(&name); // issuer
    tbs_inner.extend_from_slice(&validity);
    tbs_inner.extend_from_slice(&name); // subject
    tbs_inner.extend_from_slice(&spki);
    tbs_inner.extend_from_slice(&extensions);
    let tbs = der_seq(&tbs_inner);

    let sig = pair
        .sign(&rng, &tbs)
        .map_err(|_| anyhow!("TLS-ALPN-01 cert signing failed"))?;
    let mut cert_inner = tbs;
    cert_inner.extend_from_slice(&sig_alg);
    cert_inner.extend_from_slice(&der_bit_string(sig.as_ref()));
    Ok(der_seq(&cert_inner))
}

struct DerTlv<'a> {
    tag: u8,
    #[cfg_attr(not(test), allow(dead_code))]
    raw: &'a [u8],
    value: &'a [u8],
}

fn read_der_tlv<'a>(input: &mut &'a [u8]) -> anyhow::Result<DerTlv<'a>> {
    let start = *input;
    if start.is_empty() {
        bail!("unexpected end of DER input");
    }
    let tag = start[0];
    // High-tag-number form not expected in X.509 standard structures we inspect.
    if tag & 0x1F == 0x1F {
        bail!("unsupported high-tag-number DER tag 0x{tag:02x}");
    }
    let len_byte = *start.get(1).ok_or_else(|| anyhow!("truncated DER length"))?;
    let (header_len, len) = if len_byte & 0x80 == 0 {
        (2usize, len_byte as usize)
    } else {
        let n = (len_byte & 0x7F) as usize;
        if n == 0 || n > std::mem::size_of::<usize>() {
            bail!("invalid DER length octets count {n}");
        }
        if start.len() < 2 + n {
            bail!("truncated DER multi-byte length");
        }
        let mut val = 0usize;
        for &b in &start[2..2 + n] {
            val = (val << 8) | (b as usize);
        }
        (2 + n, val)
    };
    let end = header_len
        .checked_add(len)
        .ok_or_else(|| anyhow!("DER length overflow"))?;
    if start.len() < end {
        bail!("truncated DER value: need {end} bytes, have {}", start.len());
    }
    let raw = &start[..end];
    let value = &start[header_len..end];
    *input = &start[end..];
    Ok(DerTlv { tag, raw, value })
}

fn expect_der_seq<'a>(input: &mut &'a [u8]) -> anyhow::Result<&'a [u8]> {
    let tlv = read_der_tlv(input)?;
    if tlv.tag != 0x30 {
        bail!("expected DER SEQUENCE (0x30), got 0x{:02x}", tlv.tag);
    }
    Ok(tlv.value)
}

/// Parses `TBSCertificate.validity.notAfter` from an X.509 DER certificate and
/// returns the expiration instant as Unix epoch seconds.
pub fn parse_x509_not_after_unix(cert_der: &[u8]) -> anyhow::Result<u64> {
    let mut cert_cur = cert_der;
    let mut outer = expect_der_seq(&mut cert_cur)?;
    let mut tbs = expect_der_seq(&mut outer)?;

    // Optional explicit [0] version
    if tbs.first().copied() == Some(0xA0) {
        let _ = read_der_tlv(&mut tbs)?;
    }
    let serial = read_der_tlv(&mut tbs)?;
    if serial.tag != 0x02 {
        bail!("expected serialNumber INTEGER, got 0x{:02x}", serial.tag);
    }
    let _sig_alg = expect_der_seq(&mut tbs)?;
    let _issuer = expect_der_seq(&mut tbs)?;
    let mut validity = expect_der_seq(&mut tbs)?;
    let _not_before = read_der_tlv(&mut validity)?;
    let not_after = read_der_tlv(&mut validity)?;
    parse_asn1_time_unix(not_after.tag, not_after.value)
}

/// Checks whether an X.509 DER certificate's `subjectAltName` extension
/// contains an `iPAddress` (`[7]`) entry equal to `expected_ip`.
pub fn cert_has_ip_san(cert_der: &[u8], expected_ip: IpAddr) -> bool {
    let expected_bytes: &[u8] = match &expected_ip {
        IpAddr::V4(v4) => &v4.octets(),
        IpAddr::V6(v6) => &v6.octets(),
    };
    let Ok(has) = (|| -> anyhow::Result<bool> {
        let mut cert_cur = cert_der;
        let mut outer = expect_der_seq(&mut cert_cur)?;
        let mut tbs = expect_der_seq(&mut outer)?;

        if tbs.first().copied() == Some(0xA0) {
            let _ = read_der_tlv(&mut tbs)?;
        }
        let _serial = read_der_tlv(&mut tbs)?;
        let _sig_alg = expect_der_seq(&mut tbs)?;
        let _issuer = expect_der_seq(&mut tbs)?;
        let _validity = expect_der_seq(&mut tbs)?;
        let _subject = expect_der_seq(&mut tbs)?;
        let _spki = expect_der_seq(&mut tbs)?;

        while !tbs.is_empty() {
            let field = read_der_tlv(&mut tbs)?;
            if field.tag == 0xA3 {
                let mut exts_cur = field.value;
                let mut exts = expect_der_seq(&mut exts_cur)?;
                while !exts.is_empty() {
                    let mut ext = expect_der_seq(&mut exts)?;
                    let oid = read_der_tlv(&mut ext)?;
                    if oid.tag != 0x06 {
                        continue;
                    }
                    let mut next = read_der_tlv(&mut ext)?;
                    if next.tag == 0x01 {
                        // Optional BOOLEAN critical
                        next = read_der_tlv(&mut ext)?;
                    }
                    if oid.value == OID_SUBJECT_ALT_NAME_VALUE && next.tag == 0x04 {
                        let mut gns_cur = next.value;
                        let mut gns = expect_der_seq(&mut gns_cur)?;
                        while !gns.is_empty() {
                            let gn = read_der_tlv(&mut gns)?;
                            if gn.tag == 0x87 && gn.value == expected_bytes {
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    })() else {
        return false;
    };
    has
}

/// Checks whether an X.509 DER certificate contains every expected IP SAN.
pub fn cert_has_all_ip_sans(cert_der: &[u8], expected_ips: &[IpAddr]) -> bool {
    !expected_ips.is_empty() && expected_ips.iter().all(|&ip| cert_has_ip_san(cert_der, ip))
}

fn parse_asn1_time_unix(tag: u8, bytes: &[u8]) -> anyhow::Result<u64> {
    let s = std::str::from_utf8(bytes).context("ASN.1 time is not UTF-8")?;
    let (year, rest) = match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ
            if s.len() != 13 || !s.ends_with('Z') {
                bail!("unsupported UTCTime format {s:?}");
            }
            let yy: i64 = s[0..2].parse().context("invalid UTCTime year")?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &s[2..12])
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ
            if s.len() != 15 || !s.ends_with('Z') {
                bail!("unsupported GeneralizedTime format {s:?}");
            }
            let year: i64 = s[0..4].parse().context("invalid GeneralizedTime year")?;
            (year, &s[4..14])
        }
        other => bail!("expected UTCTime (0x17) or GeneralizedTime (0x18), got 0x{other:02x}"),
    };

    let month: i64 = rest[0..2].parse().context("invalid month")?;
    let day: i64 = rest[2..4].parse().context("invalid day")?;
    let hour: i64 = rest[4..6].parse().context("invalid hour")?;
    let min: i64 = rest[6..8].parse().context("invalid minute")?;
    let sec: i64 = rest[8..10].parse().context("invalid second")?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&min)
        || !(0..=60).contains(&sec)
    {
        bail!("out-of-range ASN.1 timestamp components in {s:?}");
    }

    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3_600 + min * 60 + sec.min(59);
    u64::try_from(secs).context("certificate expiry predates Unix epoch")
}

/// Howard Hinnant's civil-to-days algorithm (days since 1970-01-01).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn now_unix() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before Unix epoch")?
        .as_secs())
}

fn unix_to_utctime(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let rem = unix % 86_400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    // Howard Hinnant civil_from_days
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year % 100,
        month,
        d,
        h,
        m,
        s
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use ring::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use tokio::sync::Mutex;

    #[test]
    fn csr_generation_ipv4_and_ipv6_verifies_signature_and_san() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();

        for ip in [
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            IpAddr::V6("2001:db8::42".parse::<Ipv6Addr>().unwrap()),
        ] {
            let csr_der = build_ip_csr_der(ip, pkcs8.as_ref()).expect("CSR builds");

            // Outer SEQUENCE: CertificationRequestInfo + signatureAlgorithm + signature
            let mut cur = csr_der.as_slice();
            let mut outer = expect_der_seq(&mut cur).expect("outer seq");
            assert!(cur.is_empty());

            let cri = read_der_tlv(&mut outer).expect("cri");
            assert_eq!(cri.tag, 0x30);
            let _sig_alg = expect_der_seq(&mut outer).expect("sig alg");
            let sig_bits = read_der_tlv(&mut outer).expect("sig bits");
            assert_eq!(sig_bits.tag, 0x03);
            assert_eq!(sig_bits.value[0], 0x00);

            // Verify cryptographic signature over CertificationRequestInfo
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pair.public_key().as_ref())
                .verify(cri.raw, &sig_bits.value[1..])
                .expect("CSR signature must verify");

            // Check empty subject and IP SAN presence inside CertificationRequestInfo
            let mut cri_cur = cri.value;
            let version = read_der_tlv(&mut cri_cur).expect("version");
            assert_eq!(version.raw, &[0x02, 0x01, 0x00]);
            let subject = read_der_tlv(&mut cri_cur).expect("subject");
            assert_eq!(subject.raw, &[0x30, 0x00], "IP CSR subject must be empty");
            let _spki = expect_der_seq(&mut cri_cur).expect("spki");
            let attrs = read_der_tlv(&mut cri_cur).expect("attributes");
            assert_eq!(attrs.tag, 0xA0);

            let mut attr_cur = attrs.value;
            let mut attr = expect_der_seq(&mut attr_cur).expect("attr");
            let attr_oid = read_der_tlv(&mut attr).expect("attr oid");
            assert_eq!(attr_oid.raw, OID_PKCS9_EXTENSION_REQUEST);
            let set = read_der_tlv(&mut attr).expect("attr set");
            assert_eq!(set.tag, 0x31);
            let mut set_cur = set.value;
            let mut exts = expect_der_seq(&mut set_cur).expect("exts");
            let mut ext = expect_der_seq(&mut exts).expect("san ext");
            let san_oid = read_der_tlv(&mut ext).expect("san oid");
            assert_eq!(san_oid.value, OID_SUBJECT_ALT_NAME_VALUE);
            let critical = read_der_tlv(&mut ext).expect("critical");
            assert_eq!(critical.raw, &[0x01, 0x01, 0xFF]);
            let ext_val = read_der_tlv(&mut ext).expect("ext val");
            assert_eq!(ext_val.tag, 0x04);
            let mut gns_cur = ext_val.value;
            let mut gns = expect_der_seq(&mut gns_cur).expect("general names");
            let gn = read_der_tlv(&mut gns).expect("general name");
            assert_eq!(gn.tag, 0x87);
            match ip {
                IpAddr::V4(v4) => assert_eq!(gn.value, &v4.octets()),
                IpAddr::V6(v6) => assert_eq!(gn.value, &v6.octets()),
            }
        }
    }

    #[test]
    fn account_key_jwk_thumbprint_and_jws_verify() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let ak = AccountKey::from_pkcs8(pkcs8.as_ref(), &rng).unwrap();

        // Thumbprint must be 43 base64url chars (32-byte SHA-256).
        assert_eq!(ak.thumbprint.len(), 43);
        let ka = ak.key_authorization("tok-123");
        assert!(ka.starts_with("tok-123."));
        assert_eq!(ka.len(), "tok-123.".len() + 43);

        // Sign a POST-as-GET and a JSON-payload JWS and verify signatures.
        for payload in [None, Some(serde_json::json!({"hello": "world"}))] {
            let jws = ak
                .sign_jws(
                    "https://acme.example/new-order",
                    "nonce-abc",
                    Some("https://acme.example/acct/1"),
                    payload.as_ref(),
                )
                .unwrap();
            let prot = jws["protected"].as_str().unwrap();
            let pay = jws["payload"].as_str().unwrap();
            let sig = BASE64_URL
                .decode(jws["signature"].as_str().unwrap())
                .unwrap();
            assert_eq!(sig.len(), 64);
            if payload.is_none() {
                assert_eq!(pay, "");
            }
            let input = format!("{prot}.{pay}");
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, ak.pair.public_key().as_ref())
                .verify(input.as_bytes(), &sig)
                .expect("JWS signature verifies");
        }
    }

    #[test]
    fn asn1_time_and_days_from_civil_are_accurate() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        // 2026-11-23T00:00:00Z = 20780 * 86400 = 1795392000
        assert_eq!(
            parse_asn1_time_unix(0x17, b"261123000000Z").unwrap(),
            parse_asn1_time_unix(0x18, b"20261123000000Z").unwrap()
        );
        // 2024-03-01 vs 2024-02-29 (leap year) difference is exactly 86400s
        let feb29 = parse_asn1_time_unix(0x17, b"240229120000Z").unwrap();
        let mar01 = parse_asn1_time_unix(0x17, b"240301120000Z").unwrap();
        assert_eq!(mar01 - feb29, 86400);
    }

    /// Minimal self-contained X.509 v3 builder for tests (no openssl binary needed).
    fn build_test_ip_cert_der(
        ip: IpAddr,
        subject_spki_der: &[u8],
        ca_key: &EcdsaKeyPair,
        not_after_unix: u64,
    ) -> Vec<u8> {
        let not_before = b"250101000000Z";
        let not_after_str = unix_to_utctime(not_after_unix);

        let mut validity_inner = der_tlv(0x17, not_before);
        validity_inner.extend_from_slice(&der_tlv(0x17, not_after_str.as_bytes()));
        let validity = der_seq(&validity_inner);

        // Minimal non-empty issuer CN=test-ca
        let cn_oid = [0x06, 0x03, 0x55, 0x04, 0x03];
        let mut atv_inner = cn_oid.to_vec();
        atv_inner.extend_from_slice(&der_tlv(0x0C, b"test-ca"));
        let rdn = der_set(&der_seq(&atv_inner));
        let issuer = der_seq(&rdn);

        // Extensions: basicConstraints(CA=false), keyUsage(digitalSignature), extendedKeyUsage(serverAuth), SAN(IP)
        let ip_bytes: &[u8] = match &ip {
            IpAddr::V4(v4) => &v4.octets(),
            IpAddr::V6(v6) => &v6.octets(),
        };
        let gn = der_tlv(0x87, ip_bytes);
        let gns = der_seq(&gn);
        let mut san_ext = der_tlv(0x06, OID_SUBJECT_ALT_NAME_VALUE);
        san_ext.extend_from_slice(&[0x01, 0x01, 0xFF]);
        san_ext.extend_from_slice(&der_tlv(0x04, &gns));

        // basicConstraints (2.5.29.19) = SEQUENCE {} (CA=false)
        let mut bc_ext = der_tlv(0x06, &[0x55, 0x1D, 0x13]);
        bc_ext.extend_from_slice(&[0x01, 0x01, 0xFF]);
        bc_ext.extend_from_slice(&der_tlv(0x04, &der_seq(&[])));

        let mut exts_inner = der_seq(&bc_ext);
        exts_inner.extend_from_slice(&der_seq(&san_ext));
        let extensions = der_tlv(0xA3, &der_seq(&exts_inner));

        let sig_alg = der_seq(OID_ECDSA_WITH_SHA256);

        let mut tbs_inner = Vec::new();
        tbs_inner.extend_from_slice(&der_tlv(0xA0, &[0x02, 0x01, 0x02])); // v3
        tbs_inner.extend_from_slice(&[0x02, 0x01, 0x01]); // serial 1
        tbs_inner.extend_from_slice(&sig_alg);
        tbs_inner.extend_from_slice(&issuer);
        tbs_inner.extend_from_slice(&validity);
        tbs_inner.extend_from_slice(&[0x30, 0x00]); // empty subject
        tbs_inner.extend_from_slice(subject_spki_der);
        tbs_inner.extend_from_slice(&extensions);
        let tbs = der_seq(&tbs_inner);

        let rng = SystemRandom::new();
        let sig = ca_key.sign(&rng, &tbs).unwrap();
        let mut cert_inner = tbs;
        cert_inner.extend_from_slice(&sig_alg);
        cert_inner.extend_from_slice(&der_bit_string(sig.as_ref()));
        der_seq(&cert_inner)
    }

    fn extract_spki_from_csr(csr_der: &[u8]) -> Vec<u8> {
        let mut cur = csr_der;
        let mut outer = expect_der_seq(&mut cur).unwrap();
        let mut cri = expect_der_seq(&mut outer).unwrap();
        let _ver = read_der_tlv(&mut cri).unwrap();
        let _subj = read_der_tlv(&mut cri).unwrap();
        let spki = read_der_tlv(&mut cri).unwrap();
        spki.raw.to_vec()
    }

    #[test]
    fn x509_parser_extracts_not_after_and_ip_san() {
        let rng = SystemRandom::new();
        let leaf_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let ca_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let ca_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, ca_pkcs8.as_ref(), &rng)
                .unwrap();

        let ip: IpAddr = "203.0.113.77".parse().unwrap();
        let csr = build_ip_csr_der(ip, leaf_pkcs8.as_ref()).unwrap();
        let spki = extract_spki_from_csr(&csr);
        let target_expiry = now_unix().unwrap() + 160 * 3600;
        let cert_der = build_test_ip_cert_der(ip, &spki, &ca_pair, target_expiry);

        assert_eq!(parse_x509_not_after_unix(&cert_der).unwrap(), target_expiry);
        assert!(cert_has_ip_san(&cert_der, ip));
        assert!(!cert_has_ip_san(&cert_der, "1.1.1.1".parse().unwrap()));
    }

    #[derive(Default)]
    struct MockAcmeState {
        new_order_calls: usize,
        last_new_order_body: Option<serde_json::Value>,
        order_status: String,
        authz_status: String,
        issued_cert_pem: Option<String>,
        nonce_seq: u64,
    }

    fn decode_jws_body(raw: &[u8]) -> (serde_json::Value, Option<serde_json::Value>) {
        let v: serde_json::Value = serde_json::from_slice(raw).unwrap();
        let prot_bytes = BASE64_URL.decode(v["protected"].as_str().unwrap()).unwrap();
        let prot: serde_json::Value = serde_json::from_slice(&prot_bytes).unwrap();
        let pay_str = v["payload"].as_str().unwrap();
        let payload = if pay_str.is_empty() {
            None
        } else {
            let pay_bytes = BASE64_URL.decode(pay_str).unwrap();
            Some(serde_json::from_slice(&pay_bytes).unwrap())
        };
        (prot, payload)
    }

    /// End-to-end test against an in-process mock ACME v2 server verifying:
    /// 1. Directory discovery & `newAccount`
    /// 2. `newOrder` sends `identifiers: [{"type":"ip", ...}]` and `"profile": "shortlived"`
    /// 3. Live HTTP-01 challenge callback to `Http01Server` on `--acme-http-bind`
    /// 4. Finalization with CSR and PEM persistence (`fullchain.pem`, `key.pem`, `account.pem`, `meta.json`)
    /// 5. Second `AcmeManager::prepare` call reuses the cached certificate without hitting `newOrder` again
    #[tokio::test]
    async fn acme_e2e_mock_directory_issues_and_reuses_ip_cert() {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );

        let rng = SystemRandom::new();
        let ca_pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let ca_pair = Arc::new(
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, ca_pkcs8.as_ref(), &rng)
                .unwrap(),
        );

        // Pick an ephemeral port for the temporary HTTP-01 challenge server.
        let http_bind_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };

        let mock_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_addr = mock_listener.local_addr().unwrap();
        let base_url = format!("http://{mock_addr}");

        let state = Arc::new(Mutex::new(MockAcmeState {
            order_status: "pending".into(),
            authz_status: "pending".into(),
            ..Default::default()
        }));

        let state_srv = Arc::clone(&state);
        let base_srv = base_url.clone();
        let ca_srv = Arc::clone(&ca_pair);
        let mock_task = tokio::spawn(async move {
            while let Ok((mut sock, _)) = mock_listener.accept().await {
                let state = Arc::clone(&state_srv);
                let base = base_srv.clone();
                let ca = Arc::clone(&ca_srv);
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    let header_end;
                    loop {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            header_end = pos + 4;
                            break;
                        }
                    }
                    let (method, path, content_len) = {
                        let head = String::from_utf8_lossy(&buf[..header_end]);
                        let mut lines = head.lines();
                        let first = lines.next().unwrap_or("");
                        let mut parts = first.split_whitespace();
                        let method = parts.next().unwrap_or("").to_string();
                        let path = parts.next().unwrap_or("").to_string();
                        let content_len: usize = lines
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                if k.eq_ignore_ascii_case("content-length") {
                                    v.trim().parse().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        (method, path, content_len)
                    };
                    while buf.len() < header_end + content_len {
                        let n = sock.read(&mut tmp).await.unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                    }
                    let body = &buf[header_end..header_end + content_len];

                    let mut st = state.lock().await;
                    st.nonce_seq += 1;
                    let nonce = format!("nonce-{}", st.nonce_seq);

                    let (status_line, extra_headers, resp_body): (&str, String, String) =
                        match (method.as_str(), path.as_str()) {
                            ("GET", "/directory") => (
                                "200 OK",
                                "Content-Type: application/json\r\n".into(),
                                serde_json::json!({
                                    "newNonce": format!("{base}/new-nonce"),
                                    "newAccount": format!("{base}/new-acct"),
                                    "newOrder": format!("{base}/new-order"),
                                    "meta": { "profiles": { "shortlived": "Short-lived IP cert" } }
                                })
                                .to_string(),
                            ),
                            ("HEAD", "/new-nonce") | ("GET", "/new-nonce") => (
                                "200 OK",
                                format!("Replay-Nonce: {nonce}\r\n"),
                                String::new(),
                            ),
                            ("POST", "/new-acct") => (
                                "201 Created",
                                format!(
                                    "Replay-Nonce: {nonce}\r\nLocation: {base}/acct/1\r\nContent-Type: application/json\r\n"
                                ),
                                serde_json::json!({"status": "valid"}).to_string(),
                            ),
                            ("POST", "/new-order") => {
                                let (_prot, pay) = decode_jws_body(body);
                                st.new_order_calls += 1;
                                st.last_new_order_body = pay;
                                st.order_status = "pending".into();
                                st.authz_status = "pending".into();
                                (
                                    "201 Created",
                                    format!(
                                        "Replay-Nonce: {nonce}\r\nLocation: {base}/order/1\r\nContent-Type: application/json\r\n"
                                    ),
                                    serde_json::json!({
                                        "status": "pending",
                                        "authorizations": [format!("{base}/authz/1")],
                                        "finalize": format!("{base}/order/1/finalize"),
                                    })
                                    .to_string(),
                                )
                            }
                            ("POST", "/authz/1") => (
                                "200 OK",
                                format!("Replay-Nonce: {nonce}\r\nContent-Type: application/json\r\n"),
                                serde_json::json!({
                                    "status": st.authz_status,
                                    "challenges": [{
                                        "type": "http-01",
                                        "url": format!("{base}/chall/1"),
                                        "token": "mock-http01-token",
                                        "status": st.authz_status,
                                    }]
                                })
                                .to_string(),
                            ),
                            ("POST", "/chall/1") => {
                                drop(st);
                                // Perform a real HTTP GET against Http01Server!
                                let check_url = format!(
                                    "http://127.0.0.1:{http_bind_port}/.well-known/acme-challenge/mock-http01-token"
                                );
                                let chall_resp = reqwest::get(&check_url).await.unwrap();
                                assert_eq!(chall_resp.status(), reqwest::StatusCode::OK);
                                let chall_body = chall_resp.text().await.unwrap();
                                assert!(chall_body.starts_with("mock-http01-token."));

                                let mut st = state.lock().await;
                                st.nonce_seq += 1;
                                let n2 = format!("nonce-{}", st.nonce_seq);
                                st.authz_status = "valid".into();
                                st.order_status = "ready".into();
                                (
                                    "200 OK",
                                    format!("Replay-Nonce: {n2}\r\nContent-Type: application/json\r\n"),
                                    serde_json::json!({
                                        "type": "http-01",
                                        "url": format!("{base}/chall/1"),
                                        "token": "mock-http01-token",
                                        "status": "valid"
                                    })
                                    .to_string(),
                                )
                            }
                            ("POST", "/order/1") => (
                                "200 OK",
                                format!("Replay-Nonce: {nonce}\r\nContent-Type: application/json\r\n"),
                                serde_json::json!({
                                    "status": st.order_status,
                                    "authorizations": [format!("{base}/authz/1")],
                                    "finalize": format!("{base}/order/1/finalize"),
                                    "certificate": if st.order_status == "valid" {
                                        Some(format!("{base}/cert/1"))
                                    } else {
                                        None
                                    }
                                })
                                .to_string(),
                            ),
                            ("POST", "/order/1/finalize") => {
                                let (_prot, pay) = decode_jws_body(body);
                                let csr_b64 = pay.unwrap()["csr"].as_str().unwrap().to_string();
                                let csr_der = BASE64_URL.decode(csr_b64).unwrap();
                                let spki = extract_spki_from_csr(&csr_der);
                                let ip: IpAddr = "127.0.0.1".parse().unwrap();
                                let not_after = now_unix().unwrap() + 160 * 3600;
                                let leaf_der = build_test_ip_cert_der(ip, &spki, &ca, not_after);
                                st.issued_cert_pem = Some(encode_pem("CERTIFICATE", &leaf_der));
                                st.order_status = "valid".into();
                                (
                                    "200 OK",
                                    format!("Replay-Nonce: {nonce}\r\nContent-Type: application/json\r\n"),
                                    serde_json::json!({
                                        "status": "valid",
                                        "authorizations": [format!("{base}/authz/1")],
                                        "finalize": format!("{base}/order/1/finalize"),
                                        "certificate": format!("{base}/cert/1"),
                                    })
                                    .to_string(),
                                )
                            }
                            ("POST", "/cert/1") => (
                                "200 OK",
                                format!(
                                    "Replay-Nonce: {nonce}\r\nContent-Type: application/pem-certificate-chain\r\n"
                                ),
                                st.issued_cert_pem.clone().unwrap(),
                            ),
                            _ => ("404 Not Found", String::new(), String::new()),
                        };

                    let resp = format!(
                        "HTTP/1.1 {status_line}\r\n{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });

        let tmp_dir = tempfile::tempdir().unwrap();
        let cli = crate::config::Cli::parse_from([
            "auto-server",
            "--enable",
            "h3",
            "--auth-token",
            "test-token",
            "--acme-ip",
            "127.0.0.1",
            "--acme-dir",
            tmp_dir.path().to_str().unwrap(),
            "--acme-http-bind",
            &format!("127.0.0.1:{http_bind_port}"),
            "--acme-directory-url",
            &format!("{base_url}/directory"),
        ]);

        // First prepare: issues fresh certificate via mock ACME server.
        let mgr1 = AcmeManager::prepare(&cli.config).await.expect("initial ACME prepare");
        assert!(tmp_dir.path().join("account.pem").exists());
        assert!(tmp_dir.path().join("fullchain.pem").exists());
        assert!(tmp_dir.path().join("key.pem").exists());
        assert!(tmp_dir.path().join("meta.json").exists());

        {
            let st = state.lock().await;
            assert_eq!(st.new_order_calls, 1);
            let order_req = st.last_new_order_body.as_ref().unwrap();
            assert_eq!(order_req["profile"], "shortlived");
            assert_eq!(order_req["identifiers"][0]["type"], "ip");
            assert_eq!(order_req["identifiers"][0]["value"], "127.0.0.1");
        }

        // Verify QUIC server config builds cleanly from the issued files.
        let _ = build_quic_server_config(&mgr1.cert_path_str(), &mgr1.key_path_str(), None)
            .await
            .expect("QUIC server config builds from issued ACME cert");

        // Second prepare: reuses cached cert without calling newOrder again.
        let _mgr2 = AcmeManager::prepare(&cli.config).await.expect("cached ACME prepare");
        assert_eq!(state.lock().await.new_order_calls, 1);

        mock_task.abort();
    }

    #[test]
    fn local_interface_ip_selection_filters_rfc6890_and_prefers_public_v4() {
        assert_eq!(PUBLIC_IP_ENDPOINTS[0], "https://ifconfig.io/ip");

        // All special/RFC 6890 addresses must be ignored.
        let special_only: Vec<IpAddr> = vec![
            "127.0.0.1".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
            "172.16.1.2".parse().unwrap(),
            "192.168.1.10".parse().unwrap(),
            "100.64.0.10".parse().unwrap(),
            "169.254.1.1".parse().unwrap(),
            "198.18.0.1".parse().unwrap(),
            "::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "fd00::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ];
        assert_eq!(select_public_interface_ip(special_only), None);

        // Public IPv4 wins over public IPv6 for single-IP preference, and dual-stack collects both.
        let mixed: Vec<IpAddr> = vec![
            "10.0.0.2".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
            "192.168.50.2".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
        ];
        assert_eq!(
            select_public_interface_ip(mixed.clone()),
            Some("1.1.1.1".parse().unwrap())
        );
        assert_eq!(
            select_public_interface_ips(mixed),
            vec![
                "1.1.1.1".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            ]
        );

        // Public IPv6 is selected when no public IPv4 is assigned.
        let v6_only: Vec<IpAddr> = vec![
            "127.0.0.1".parse().unwrap(),
            "192.168.1.2".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "2606:4700:4700::1111".parse().unwrap(),
        ];
        assert_eq!(
            select_public_interface_ip(v6_only),
            Some("2606:4700:4700::1111".parse().unwrap())
        );
    }

    #[test]
    fn multi_san_csr_and_tls_alpn_01_cert_parse_correctly() {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();

        // Multi-SAN CSR with both IPv4 and IPv6
        let v4: IpAddr = "203.0.113.10".parse().unwrap();
        let v6: IpAddr = "2001:db8::42".parse().unwrap();
        let csr_der = build_ips_csr_der(&[v4, v6], pkcs8.as_ref()).expect("multi-SAN CSR builds");

        let mut cur = csr_der.as_slice();
        let mut outer = expect_der_seq(&mut cur).unwrap();
        let cri = read_der_tlv(&mut outer).unwrap();
        let _sig_alg = expect_der_seq(&mut outer).unwrap();
        let sig_bits = read_der_tlv(&mut outer).unwrap();
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, pair.public_key().as_ref())
            .verify(cri.raw, &sig_bits.value[1..])
            .expect("multi-SAN CSR signature verifies");

        let mut cri_cur = cri.value;
        let _ver = read_der_tlv(&mut cri_cur).unwrap();
        let _subj = read_der_tlv(&mut cri_cur).unwrap();
        let _spki = expect_der_seq(&mut cri_cur).unwrap();
        let attrs = read_der_tlv(&mut cri_cur).unwrap();
        let mut attr_cur = attrs.value;
        let mut attr = expect_der_seq(&mut attr_cur).unwrap();
        let _oid = read_der_tlv(&mut attr).unwrap();
        let set = read_der_tlv(&mut attr).unwrap();
        let mut set_cur = set.value;
        let mut exts = expect_der_seq(&mut set_cur).unwrap();
        let mut ext = expect_der_seq(&mut exts).unwrap();
        let _san_oid = read_der_tlv(&mut ext).unwrap();
        let _crit = read_der_tlv(&mut ext).unwrap();
        let ext_val = read_der_tlv(&mut ext).unwrap();
        let mut gns_cur = ext_val.value;
        let mut gns = expect_der_seq(&mut gns_cur).unwrap();
        let gn1 = read_der_tlv(&mut gns).unwrap();
        let gn2 = read_der_tlv(&mut gns).unwrap();
        assert!(gns.is_empty());
        assert_eq!(gn1.tag, 0x87);
        assert_eq!(gn2.tag, 0x87);
        assert_eq!(gn1.value, &[203, 0, 113, 10]);
        assert_eq!(
            gn2.value,
            &"2001:db8::42".parse::<Ipv6Addr>().unwrap().octets()
        );

        // TLS-ALPN-01 cert builds, verifies in rustls, contains IP SAN and id-pe-acmeIdentifier
        let key_auth = "tok-xyz.thumbprint123";
        let alpn_cert_der =
            build_tls_alpn_01_cert_der(v4, key_auth, pkcs8.as_ref()).expect("ALPN cert builds");
        assert!(cert_has_ip_san(&alpn_cert_der, v4));

        // Verify id-pe-acmeIdentifier digest inside extensions
        let mut c = alpn_cert_der.as_slice();
        let mut o = expect_der_seq(&mut c).unwrap();
        let mut tbs = expect_der_seq(&mut o).unwrap();
        for _ in 0..7 {
            let _ = read_der_tlv(&mut tbs).unwrap();
        }
        let exts_wrap = read_der_tlv(&mut tbs).unwrap();
        assert_eq!(exts_wrap.tag, 0xA3);
        let mut exts_cur = exts_wrap.value;
        let mut exts_seq = expect_der_seq(&mut exts_cur).unwrap();
        let mut found_acme_ext = false;
        while !exts_seq.is_empty() {
            let mut ext = expect_der_seq(&mut exts_seq).unwrap();
            let oid = read_der_tlv(&mut ext).unwrap();
            let crit = read_der_tlv(&mut ext).unwrap();
            if oid.value == OID_PE_ACME_IDENTIFIER_VALUE {
                assert_eq!(crit.raw, &[0x01, 0x01, 0xFF]);
                let val = read_der_tlv(&mut ext).unwrap();
                let mut inner_cur = val.value;
                let inner_oct = read_der_tlv(&mut inner_cur).unwrap();
                assert_eq!(inner_oct.tag, 0x04);
                let expected_hash = digest::digest(&digest::SHA256, key_auth.as_bytes());
                assert_eq!(inner_oct.value, expected_hash.as_ref());
                found_acme_ext = true;
            }
        }
        assert!(found_acme_ext, "id-pe-acmeIdentifier extension missing");

        // Verify rustls ServerConfig accepts the TLS-ALPN-01 cert + key
        let cert = CertificateDer::from(alpn_cert_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_ref().to_vec()));
        let tls_cfg = build_tls_alpn_01_server_config(cert, key)
            .expect("rustls accepts TLS-ALPN-01 cert");
        assert_eq!(tls_cfg.alpn_protocols, vec![b"acme-tls/1".to_vec()]);
    }
}
