//! Layer-3 (`tun`) VPN gateway plumbing for CONNECT-IP.
//!
//! A CONNECT-IP session is a genuine IP tunnel: the proxy owns one end of a
//! `tun` interface, assigns the client an address, advertises routes, and NATs
//! the client's traffic out the node's egress. This module does the OS-side
//! work with the smallest dependency surface that stays correct on musl:
//!
//! * The `tun` device is created with the Linux `TUNSETIFF` ioctl directly
//!   (`libc`). We deliberately avoid pulling in the `tun`/`tokio-tun` crates:
//!   raw ioctls plus `tokio::io::unix::AsyncFd` work identically on gnu and
//!   musl x86_64, so there is no musl-specific risk.
//! * The interface is brought up and addressed, and the client prefix is
//!   MASQUERADEd, with `ip`/`iptables` via `std::process::Command`. This is the
//!   pragmatic, universally-available approach; a netlink crate (`rtnetlink`)
//!   would be tidier but heavier and was not required.
//!
//! Everything here needs `CAP_NET_ADMIN` (effectively root). The integration
//! test is `#[ignore]`d and bails unless `uid == 0` and the tools are present,
//! so a default `cargo test` never touches the host's network stack.

use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex as StdMutex;
use std::sync::Arc;
use std::task::Poll;

use anyhow::{Context, anyhow, bail};
use ipnet::IpNet;
use tokio::io::unix::AsyncFd;
use tracing::{debug, info, warn};

/// `TUNSETIFF` ioctl request code (`_IOW('T', 202, int)`). The numeric value is
/// identical on every Linux architecture we target (gnu + musl, x86_64 /
/// aarch64) — `int` is 4 bytes everywhere — but its *type* must match the
/// platform's `libc::ioctl` request parameter: glibc declares `libc::Ioctl` as
/// `c_ulong` (u64) while musl declares it as `c_int` (i32). Typing the constant
/// as `libc::Ioctl` (the value fits an i32) keeps the call site portable to
/// both without a cast at each use.
const TUNSETIFF: libc::Ioctl = 0x4004_54CA;
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
const IFNAMSIZ: usize = 16;

const IP_BIN: &str = "/usr/sbin/ip";
const IPTABLES: &str = "/usr/sbin/iptables";
const IP6TABLES: &str = "/usr/sbin/ip6tables";
const IP_FORWARD_PATH: &str = "/proc/sys/net/ipv4/ip_forward";

#[derive(Clone, Copy, PartialEq)]
enum Family {
    V4,
    V6,
}

/// Mirror of `struct ifreq` for `TUNSETIFF`: 16-byte name, the flags short that
/// is the first member of the union, and padding to the full 40-byte size.
#[repr(C)]
struct Ifreq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_flags: u16,
    ifr_pad: [u8; 22],
}

/// Owns the raw tun file descriptor; closes it on drop.
struct TunFd(RawFd);

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for TunFd {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

/// A live tunnel endpoint: a `tun` device + the firewall state we added for it.
/// Dropping it tears everything down (interface delete, iptables rule removal,
/// `ip_forward` restore) so the host is left exactly as we found it.
pub(crate) struct TunDevice {
    name: String,
    afd: Arc<AsyncFd<TunFd>>,
    family: Family,
    /// iptables/ip6tables argument vectors we added (each starts with `-A`), so
    /// `Drop` can delete them with `-D`.
    nat_rules: Vec<Vec<String>>,
    /// `true` if *this* device turned `ip_forward` on (vs finding it already on).
    managed_ip_forward: bool,
}

impl TunDevice {
    /// The kernel-assigned interface name (e.g. `tun0`).
    pub(crate) fn name(&self) -> &str {
        &self.name
    }
}

impl TunDevice {
    /// Create a layer-3 `tun` device, bring it up, assign `proxy` with `client`
    /// as the point-to-point peer, enable forwarding + NAT for the client, and
    /// return the handle. `mtu` (if `Some`) is applied to the interface; callers
    /// should pass a value that fits inside a QUIC DATAGRAM (see
    /// `handle_ip_stream`).
    ///
    /// `proxy` and `client` must be the same address family. Requires root.
    pub(crate) fn create(
        name_hint: &str,
        proxy: IpAddr,
        client: IpAddr,
        prefix: u8,
        mtu: Option<usize>,
    ) -> anyhow::Result<TunDevice> {
        if proxy.is_ipv4() != client.is_ipv4() {
            bail!("proxy and client addresses must be the same IP family");
        }
        let family = if proxy.is_ipv4() { Family::V4 } else { Family::V6 };

        // 1. Open /dev/net/tun and issue TUNSETIFF (layer-3, no extra PI header).
        let path = std::ffi::CString::new("/dev/net/tun")
            .map_err(|_| anyhow!("/dev/net/tun is not a valid path"))?;
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error())
                .context("opening /dev/net/tun (need CAP_NET_ADMIN / root)");
        }
        let mut ifr = Ifreq {
            ifr_name: [0u8; IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            ifr_pad: [0u8; 22],
        };
        let hint = name_hint.as_bytes();
        if hint.len() >= IFNAMSIZ {
            unsafe { libc::close(fd) };
            bail!("tun name hint '{}' is too long", name_hint);
        }
        ifr.ifr_name[..hint.len()].copy_from_slice(hint); // already NUL-terminated

        let rc = unsafe { libc::ioctl(fd, TUNSETIFF, &mut ifr as *mut Ifreq) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(e).context("TUNSETIFF ioctl failed (need CAP_NET_ADMIN / root)");
        }
        let name = cstr_to_string(&ifr.ifr_name);
        info!(tun = %name, proxy = %proxy, client = %client, prefix, "created tun device");

        let afd = Arc::new(AsyncFd::new(TunFd(fd)).context("wrapping tun fd in AsyncFd")?);
        let mut dev = TunDevice {
            name,
            afd,
            family,
            nat_rules: Vec::new(),
            managed_ip_forward: false,
        };

        // 2. Bring the interface up (and set MTU if requested).
        dev.run_ip(&["link", "set", &dev.name, "up"])?;
        if let Some(mtu) = mtu {
            dev.run_ip(&["link", "set", &dev.name, "mtu", &mtu.to_string()])?;
        }

        // 3. Point-to-point addressing: the proxy owns one end, the client the
        //    other. The kernel installs a host route for the peer automatically,
        //    so no explicit `ip route add` is needed.
        match family {
            Family::V4 => dev.run_ip(&[
                "addr", "add", &format!("{}/{prefix}", proxy), "peer", &client.to_string(), "dev",
                &dev.name,
            ])?,
            Family::V6 => dev.run_ip(&[
                "-6", "addr", "add", &format!("{}/128", proxy), "peer", &format!("{}/128", client),
                "dev", &dev.name,
            ])?,
        }

        // 4. Forwarding + NAT for the client's source address.
        dev.managed_ip_forward = ensure_ip_forward().context("enabling ip_forward")?;
        let client_str = client.to_string();
        dev.add_nat_rule(&[
            "-t", "nat", "-A", "POSTROUTING", "-s", &client_str, "-j", "MASQUERADE",
        ])?;
        dev.add_nat_rule(&["-A", "FORWARD", "-s", &client_str, "-j", "ACCEPT"])?;
        dev.add_nat_rule(&["-A", "FORWARD", "-d", &client_str, "-j", "ACCEPT"])?;

        Ok(dev)
    }

    fn run_ip(&self, args: &[&str]) -> anyhow::Result<()> {
        run_cmd(IP_BIN, args)
    }

    fn add_nat_rule(&mut self, args: &[&str]) -> anyhow::Result<()> {
        let prog = if self.family == Family::V4 { IPTABLES } else { IP6TABLES };
        run_cmd(prog, args).with_context(|| format!("adding firewall rule {:?}", args))?;
        self.nat_rules.push(args.iter().map(|s| s.to_string()).collect());
        Ok(())
    }

    /// Read one IP packet from the tun device.
    pub(crate) async fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        let afd = self.afd.clone();
        poll_fn(|cx| {
            let mut ready = match afd.poll_read_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            match ready.try_io(|permit| {
                let fd = permit.get_ref().as_raw_fd();
                let n = unsafe {
                    libc::read(
                        fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                // `try_io` returns `Ok(inner)` on a completed syscall, or `Err`
                // if the fd would block (the guard's readiness is cleared on
                // drop, so the next poll waits again).
                Ok(res) => Poll::Ready(res),
                Err(_would_block) => Poll::Pending,
            }
        })
        .await
    }

    /// Write one IP packet to the tun device.
    pub(crate) async fn write_packet(&self, pkt: &[u8]) -> io::Result<usize> {
        let afd = self.afd.clone();
        poll_fn(|cx| {
            let mut ready = match afd.poll_write_ready(cx) {
                Poll::Ready(Ok(g)) => g,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            match ready.try_io(|permit| {
                let fd = permit.get_ref().as_raw_fd();
                let n = unsafe {
                    libc::write(fd, pkt.as_ptr() as *const libc::c_void, pkt.len())
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(res) => Poll::Ready(res),
                Err(_would_block) => Poll::Pending,
            }
        })
        .await
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        let prog = if self.family == Family::V4 { IPTABLES } else { IP6TABLES };
        for rule in &self.nat_rules {
            // Replay the same arguments with `-A` swapped for `-D`.
            let mut del: Vec<String> = rule.clone();
            for tok in del.iter_mut() {
                if tok == "-A" {
                    *tok = "-D".to_string();
                }
            }
            let args: Vec<&str> = del.iter().map(String::as_str).collect();
            if let Err(e) = run_cmd(prog, &args) {
                warn!(tun = %self.name, error = %e, "failed to remove firewall rule during cleanup");
            }
        }
        if let Err(e) = run_cmd(IP_BIN, &["link", "del", &self.name]) {
            warn!(tun = %self.name, error = %e, "failed to delete tun device during cleanup");
        }
        if self.managed_ip_forward && let Err(e) = release_ip_forward() {
            warn!(error = %e, "failed to restore ip_forward during cleanup");
        }
        debug!(tun = %self.name, "tun device cleaned up");
    }
}

/// Run an external command, returning an error if it fails to spawn or exits non-zero.
fn run_cmd(prog: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = std::process::Command::new(prog)
        .args(args)
        .status()
        .with_context(|| format!("spawning {prog}"))?;
    if !status.success() {
        bail!("{prog} {:?} exited with status {status}", args);
    }
    Ok(())
}

fn cstr_to_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

// ---------------------------------------------------------------------------
// Global ip_forward refcount. Many sessions share one kernel forwarding flag; we
// only flip it off when the last session releases it, and we restore whatever
// value was present when the first session started.
// ---------------------------------------------------------------------------

static IP_FORWARD: StdMutex<(usize, u8)> = StdMutex::new((0, 1));

fn read_ip_forward() -> anyhow::Result<u8> {
    let s = std::fs::read_to_string(IP_FORWARD_PATH).context("reading ip_forward")?;
    let v = s.trim().parse::<u8>().context("parsing ip_forward")?;
    Ok(v.min(1))
}

fn set_ip_forward(v: u8) -> anyhow::Result<()> {
    std::fs::write(IP_FORWARD_PATH, v.to_string()).context("writing ip_forward")?;
    Ok(())
}

/// Ensure IPv4 forwarding is on. Returns `true` if this call turned it on (so the
/// caller should restore it on teardown).
fn ensure_ip_forward() -> anyhow::Result<bool> {
    let mut g = IP_FORWARD.lock().unwrap();
    if g.0 == 0 {
        let cur = read_ip_forward()?;
        g.1 = cur;
        if cur == 0 {
            set_ip_forward(1)?;
        }
    }
    g.0 += 1;
    Ok(g.1 == 0)
}

/// Release a reference to the forwarding flag; restores the original value when
/// the last reference is gone.
fn release_ip_forward() -> anyhow::Result<()> {
    let mut g = IP_FORWARD.lock().unwrap();
    if g.0 == 0 {
        return Ok(());
    }
    g.0 -= 1;
    if g.0 == 0 && g.1 == 0 {
        set_ip_forward(0)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Address pool. Hands out a small subnet per session from a configurable CIDR.
// IPv4 pools allocate /30 blocks (proxy = base+1, client = base+2); IPv6 pools
// allocate /64 blocks (proxy/client as /128 within). The pool is shared across
// sessions, so the allocator is mutable state owned by the caller.
// ---------------------------------------------------------------------------

pub(crate) struct IpPool {
    net: IpNet,
    v4_blocks: u64,
    v6_blocks: u64,
}

impl IpPool {
    pub(crate) fn new(cidr: &str) -> anyhow::Result<Self> {
        let net: IpNet = cidr
            .parse()
            .map_err(|e| anyhow!("invalid --ip-pool CIDR '{cidr}': {e}"))?;
        Ok(Self {
            net,
            v4_blocks: 0,
            v6_blocks: 0,
        })
    }

    /// Allocate `(proxy, client, prefix)` for one session, advancing the cursor.
    pub(crate) fn allocate(&mut self) -> anyhow::Result<(IpAddr, IpAddr, u8)> {
        match self.net {
            IpNet::V4(v4) => {
                let base_aligned = u32::from(v4.network()) & !3u32;
                let block = self.v4_blocks;
                let base = base_aligned.wrapping_add((block as u32) * 4);
                let broadcast = u32::from(v4.broadcast());
                if base + 3 > broadcast {
                    bail!(
                        "IPv4 pool {} exhausted (allocated {} /30 blocks)",
                        self.net,
                        block
                    );
                }
                self.v4_blocks += 1;
                let proxy = IpAddr::from(Ipv4Addr::from(base + 1));
                let client = IpAddr::from(Ipv4Addr::from(base + 2));
                Ok((proxy, client, 30))
            }
            IpNet::V6(v6) => {
                let prefix = v6.prefix_len();
                if prefix > 64 {
                    bail!(
                        "--ip-pool v6 prefix /{prefix} is smaller than the /64 allocated per client"
                    );
                }
                let n_blocks = 1u128 << (64 - prefix);
                let block = self.v6_blocks;
                if (block as u128) >= n_blocks {
                    bail!("IPv6 pool {} exhausted", self.net);
                }
                self.v6_blocks += 1;
                let net_u128 = u128::from(v6.network());
                let base = net_u128 + ((block as u128) << 64);
                let proxy = IpAddr::from(Ipv6Addr::from(base + 1));
                let client = IpAddr::from(Ipv6Addr::from(base + 2));
                Ok((proxy, client, 64))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn pool_allocates_distinct_v4_blocks() {
        let mut pool = IpPool::new("198.18.0.0/15").unwrap();
        let (p0, c0, pre0) = pool.allocate().unwrap();
        let (p1, c1, pre1) = pool.allocate().unwrap();
        assert_eq!(pre0, 30);
        assert_eq!(pre1, 30);
        assert_eq!(p0, IpAddr::from(Ipv4Addr::new(198, 18, 0, 1)));
        assert_eq!(c0, IpAddr::from(Ipv4Addr::new(198, 18, 0, 2)));
        assert_eq!(p1, IpAddr::from(Ipv4Addr::new(198, 18, 0, 5)));
        assert_eq!(c1, IpAddr::from(Ipv4Addr::new(198, 18, 0, 6)));
    }

    #[test]
    fn pool_v4_exhaustion() {
        // A /30 has exactly one block.
        let mut pool = IpPool::new("192.168.0.0/30").unwrap();
        let _ = pool.allocate().unwrap();
        assert!(pool.allocate().is_err());
    }

    #[test]
    fn pool_rejects_bad_cidr() {
        assert!(IpPool::new("not-a-cidr").is_err());
    }

    #[test]
    fn cstr_to_string_handles_null_termination() {
        let buf = &b"tun3\0rest"[..];
        assert_eq!(cstr_to_string(buf), "tun3");
    }

    /// Real tun + routing + NAT integration. Requires root and the `ip` /
    /// `iptables` binaries; skips gracefully otherwise so a default `cargo test`
    /// never touches the host network. Marked `#[ignore]` so it also does not run
    /// in CI by accident.
    #[tokio::test]
    #[ignore = "requires root + ip/iptables; run with: cargo test -- --ignored tun_integration"]
    async fn tun_integration() {
        // Skip unless we are root.
        if unsafe { libc::getuid() } != 0 {
            eprintln!("not root; skipping tun integration test");
            return;
        }
        if which(IP_BIN).is_none() || which(IPTABLES).is_none() {
            eprintln!("ip/iptables unavailable; skipping tun integration test");
            return;
        }

        // Allocate a throwaway address pair from a tiny pool.
        let mut pool = IpPool::new("198.18.255.0/30").unwrap();
        let (proxy, client, prefix) = pool.allocate().unwrap();

        let dev = TunDevice::create("auto%d", proxy, client, prefix, Some(1400))
            .expect("create tun (root)");
        let name = dev.name.clone();

        // The interface must now exist.
        assert!(interface_exists(&name), "tun {name} should exist after create");

        // Drop should remove it (and the iptables rules).
        drop(dev);
        assert!(!interface_exists(&name), "tun {name} should be gone after drop");
    }

    fn interface_exists(name: &str) -> bool {
        std::process::Command::new(IP_BIN)
            .args(["link", "show", name])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn which(prog: &str) -> Option<std::path::PathBuf> {
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {}", prog))
            .output()
            .ok()?;
        if out.status.success() {
            let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if p.is_empty() {
                None
            } else {
                Some(std::path::PathBuf::from(p))
            }
        } else {
            None
        }
    }
}
