//! RFC 9297 capsule protocol + RFC 9484 (CONNECT-IP) capsule types.
//!
//! Three distinct layers live here; keeping them apart is essential for wire
//! correctness:
//!
//! * **Capsule framing (RFC 9297 §3)** — a stream-oriented TLV:
//!   `Type (varint) + Length (varint) + Value (Length bytes)`, with QUIC
//!   variable-length integers (RFC 9000 §16). This framing is used **only on
//!   the HTTP request stream**: CONNECT-IP signalling capsules
//!   (ADDRESS_ASSIGN / ADDRESS_REQUEST / ROUTE_ADVERTISEMENT) travel there
//!   (RFC 9484 §4.7). It is **never** used on the datagram plane.
//!
//! * **HTTP datagram payloads (RFC 9297 §4)** — on the datagram plane, each
//!   HTTP Datagram payload is `Context ID (varint) + data`. The Quarter
//!   Stream ID is handled by `h3-datagram` and is *not* part of these bytes;
//!   the Context ID is entirely ours. We only use Context ID 0 — a single
//!   `0x00` byte — after which the data is the **raw** payload: the UDP
//!   payload for CONNECT-UDP (RFC 9298 §4.2) and the raw IP packet for
//!   CONNECT-IP (RFC 9484 §4.2) — no Type, no Length, no capsule TLV.
//!   Datagrams with a non-zero Context ID are dropped silently.
//!
//! * **CONNECT-IP capsule payloads (RFC 9484 §4.7)** — the structured fields
//!   inside the signalling capsules. These are *fixed-layout* binary
//!   structures, NOT nested TLVs:
//!   - Assigned/Requested Address: `Request ID (varint), IP Version (8),
//!     IP Address (32 or 128 bits), IP Prefix Length (8)`.
//!   - IP Address Range: `IP Version (8), Start IP Address (32/128),
//!     End IP Address (32/128), IP Protocol (8)`.
//!   - DNS/NAT64 configuration (`draft-ietf-masque-connect-ip-dns-06`): unlike
//!     the above these *are* nested and counted — see the `DNS_ASSIGN` and
//!     `PREF64` sections below.
//!
//! All of this is pure, allocation-light, and fully unit-testable without root
//! or a network device.
//!
//! The codec is **public** (the module is re-exported as `auto_server::capsule`)
//! so that external tooling — notably the `masque-client` binary in `src/bin`
//! — encodes and decodes exactly the same bytes rather than re-deriving the
//! format. Consequence worth remembering: a green `masque-client` round-trip
//! proves the *server* works end-to-end but is **not** an independent wire-format
//! conformance check (that role belongs to a third-party client such as
//! masque-go).

// The CONNECT-IP signalling encoders are only wired up on Linux (the tun/NAT
// data plane, see `lib.rs`); silence the dead-code warnings elsewhere.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, Bytes, BytesMut};

// ---------------------------------------------------------------------------
// Capsule type numbers (RFC 9484 §4.7 / IANA "HTTP Capsule Types")
// ---------------------------------------------------------------------------

/// `ADDRESS_ASSIGN` (0x01) — an endpoint assigns its peer IP addresses or
/// prefixes (RFC 9484 §4.7.1).
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;

/// `ADDRESS_REQUEST` (0x02) — an endpoint requests address assignment from its
/// peer (RFC 9484 §4.7.2).
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;

/// `ROUTE_ADVERTISEMENT` (0x03) — an endpoint advertises the IP address ranges
/// it is willing to route for its peer (RFC 9484 §4.7.3).
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

// Capsule type numbers below come from
// `draft-ietf-masque-connect-ip-dns-06` §6, NOT from the IANA registry: the
// draft is not approved, so the "HTTP Capsule Types" registry does not list
// these yet. §6 explicitly marks both values **provisional** ("will be replaced
// by a smaller one before publication"), so they are protocol-frozen only for
// this draft revision — a future revision can renumber them. `connect-ip-go`'s
// `capsule.go` (master) encodes exactly these values, which is our
// interoperability cross-check.

/// `DNS_ASSIGN` (0x1ACE79EC) — an endpoint sends DNS configuration to its peer
/// (`draft-ietf-masque-connect-ip-dns-06` §3.4).
///
/// There is deliberately **no** `DNS_REQUEST` here: that capsule existed up to
/// revision -03 (value 0x818F79F) and was removed in -04. See
/// [`CAPSULE_ADDRESS_REQUEST`] for the capsule this extension does not define.
pub const CAPSULE_DNS_ASSIGN: u64 = 0x1ACE_79EC;

/// `PREF64` (0x274C0FBC) — an endpoint communicates the IPv6 NAT64 prefixes to
/// use for IPv6/IPv4 address synthesis (`draft-ietf-masque-connect-ip-dns-06`
/// §4.1). Same provisional caveat as [`CAPSULE_DNS_ASSIGN`].
pub const CAPSULE_PREF64: u64 = 0x274C_0FBC;

// ---------------------------------------------------------------------------
// CONNECT-IP signalling structures (RFC 9484 §4.7)
// ---------------------------------------------------------------------------

/// One `Assigned Address` / `Requested Address` (RFC 9484 §4.7.1 Figure 8 /
/// §4.7.2 Figure 10). The prefix length is mandatory (`/32` for a single host
/// IPv4 assignment, `/128` for IPv6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddress {
    /// Echoed in the ADDRESS_ASSIGN response; 0 for unprompted assignments.
    pub request_id: u64,
    pub address: IpAddr,
    pub prefix_len: u8,
}

/// One `IP Address Range` (RFC 9484 §4.7.3 Figure 12): the inclusive range
/// `start..=end` for `ip_protocol` (`0` = all protocols; ICMP is always
/// allowed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpRange {
    pub start: IpAddr,
    pub end: IpAddr,
    pub ip_protocol: u8,
}

// ---------------------------------------------------------------------------
// Generic capsule TLV (RFC 9297 §3) — request-stream framing ONLY
// ---------------------------------------------------------------------------

/// Encode a capsule: `Type` (varint) + `Length` (varint) + `Value`.
pub fn encode_capsule(typ: u64, value: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(8 + value.len());
    put_varint(&mut buf, typ);
    put_varint(&mut buf, value.len() as u64);
    buf.extend_from_slice(value);
    buf.freeze()
}

/// Split the first capsule off the front of `bytes`, returning
/// `(Type, Value, consumed)` where `consumed` is the total number of bytes the
/// capsule occupied (so a stream reader can advance past it). Returns `None`
/// if the framing is incomplete or garbled (a partial varint, or a `Length`
/// claiming more bytes than remain) — the caller should wait for more bytes.
pub fn split_capsule(bytes: &[u8]) -> Option<(u64, &[u8], usize)> {
    let mut buf = bytes;
    let typ = get_varint(&mut buf)?;
    let len = get_varint(&mut buf)? as usize;
    if buf.len() < len {
        return None;
    }
    let value = &buf[..len];
    // Header (Type + Length varints) = bytes.len() - buf.len(); total = header + len.
    let consumed = bytes.len() - buf.len() + len;
    Some((typ, value, consumed))
}

/// Decode the first capsule, returning `(Type, Value)`. Returns `None` if the
/// framing is truncated or garbled.
pub fn decode_capsule(bytes: &[u8]) -> Option<(u64, Bytes)> {
    let (typ, value, _) = split_capsule(bytes)?;
    Some((typ, Bytes::copy_from_slice(value)))
}

/// Strip the HTTP-datagram `Context ID` (RFC 9297 §4) from the front of a
/// datagram payload (the Quarter Stream ID has already been removed by
/// `h3-datagram`). Returns the remainder **only** for Context ID 0 — the only
/// context we use. `None` means "drop this datagram silently": a non-zero
/// Context ID we did not negotiate, or a truncated varint. Dropping must not
/// error the tunnel (RFC 9298 §4.2 / RFC 9484 §4.2).
pub fn strip_context_id(dgram: &[u8]) -> Option<&[u8]> {
    let mut buf = dgram;
    let cid = get_varint(&mut buf)?;
    if cid == 0 {
        Some(buf)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// ADDRESS_ASSIGN / ADDRESS_REQUEST payloads (RFC 9484 §4.7.1, §4.7.2)
// ---------------------------------------------------------------------------

/// Encode the payload of an `ADDRESS_ASSIGN` or `ADDRESS_REQUEST` capsule:
/// a sequence of `Assigned Address` / `Requested Address` structures
/// (identical layout).
pub fn encode_address_value(entries: &[AssignedAddress]) -> Bytes {
    let mut v = BytesMut::new();
    for e in entries {
        put_varint(&mut v, e.request_id);
        match e.address {
            IpAddr::V4(a) => {
                v.put_u8(4);
                v.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                v.put_u8(6);
                v.extend_from_slice(&a.octets());
            }
        }
        v.put_u8(e.prefix_len);
    }
    v.freeze()
}

/// Parse the payload of an `ADDRESS_ASSIGN` / `ADDRESS_REQUEST` capsule.
/// Returns `None` on malformed input (truncated, IP Version not 4/6, address
/// of the wrong length, prefix length exceeding the address size).
pub fn decode_address_value(value: &[u8]) -> Option<Vec<AssignedAddress>> {
    let mut entries = Vec::new();
    let mut buf = value;

    while !buf.is_empty() {
        let request_id = get_varint(&mut buf)?;
        let version = *buf.first()?;
        buf = &buf[1..];
        let (addr, max_prefix) = match version {
            4 => {
                if buf.len() < 4 {
                    return None;
                }
                let octets = [buf[0], buf[1], buf[2], buf[3]];
                buf = &buf[4..];
                (IpAddr::V4(Ipv4Addr::from(octets)), 32u8)
            }
            6 => {
                if buf.len() < 16 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[..16]);
                buf = &buf[16..];
                (IpAddr::V6(Ipv6Addr::from(octets)), 128u8)
            }
            _ => return None,
        };
        let prefix_len = *buf.first()?;
        buf = &buf[1..];
        if prefix_len > max_prefix {
            return None;
        }
        entries.push(AssignedAddress {
            request_id,
            address: addr,
            prefix_len,
        });
    }

    Some(entries)
}

/// Encode a full `ADDRESS_ASSIGN` capsule (TLV + payload).
pub fn encode_address_assign(entries: &[AssignedAddress]) -> Bytes {
    encode_capsule(CAPSULE_ADDRESS_ASSIGN, &encode_address_value(entries))
}

/// Encode a full `ADDRESS_REQUEST` capsule (TLV + payload).
///
/// The proxy never sends an `ADDRESS_REQUEST` (that is the client's role in
/// RFC 9484 §4.7.2); this is part of the complete capsule API and is exercised
/// by the unit tests, hence `allow(dead_code)`.
#[allow(dead_code)]
pub fn encode_address_request(entries: &[AssignedAddress]) -> Bytes {
    encode_capsule(CAPSULE_ADDRESS_REQUEST, &encode_address_value(entries))
}

/// Decode a full `ADDRESS_ASSIGN` capsule (TLV + payload), or `None` if it is
/// not an ADDRESS_ASSIGN or the payload is malformed.
#[allow(dead_code)]
pub fn decode_address_assign(capsule: &[u8]) -> Option<Vec<AssignedAddress>> {
    match decode_capsule(capsule) {
        Some((CAPSULE_ADDRESS_ASSIGN, v)) => decode_address_value(&v),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// ROUTE_ADVERTISEMENT payload (RFC 9484 §4.7.3)
// ---------------------------------------------------------------------------

/// Encode the payload of a `ROUTE_ADVERTISEMENT` capsule: a sequence of
/// `IP Address Range` structures.
pub fn encode_route_value(ranges: &[IpRange]) -> Bytes {
    let mut v = BytesMut::new();
    for r in ranges {
        match r.start {
            IpAddr::V4(a) => {
                v.put_u8(4);
                v.extend_from_slice(&a.octets());
            }
            IpAddr::V6(a) => {
                v.put_u8(6);
                v.extend_from_slice(&a.octets());
            }
        }
        match r.end {
            IpAddr::V4(a) => v.extend_from_slice(&a.octets()),
            IpAddr::V6(a) => v.extend_from_slice(&a.octets()),
        }
        v.put_u8(r.ip_protocol);
    }
    v.freeze()
}

/// Parse the payload of a `ROUTE_ADVERTISEMENT` capsule. Returns `None` on
/// malformed input (truncated, IP Version not 4/6, Start > End, or start/end
/// of different families).
pub fn decode_route_value(value: &[u8]) -> Option<Vec<IpRange>> {
    let mut ranges = Vec::new();
    let mut buf = value;

    while !buf.is_empty() {
        let version = *buf.first()?;
        buf = &buf[1..];
        let addr_len = match version {
            4 => 4usize,
            6 => 16usize,
            _ => return None,
        };
        if buf.len() < addr_len * 2 + 1 {
            return None;
        }
        let mut start_octets = [0u8; 16];
        start_octets[..addr_len].copy_from_slice(&buf[..addr_len]);
        let mut end_octets = [0u8; 16];
        end_octets[..addr_len].copy_from_slice(&buf[addr_len..addr_len * 2]);
        buf = &buf[addr_len * 2..];
        let ip_protocol = buf[0];
        buf = &buf[1..];

        let start = if version == 4 {
            let mut o = [0u8; 4];
            o.copy_from_slice(&start_octets[..4]);
            IpAddr::V4(Ipv4Addr::from(o))
        } else {
            IpAddr::V6(Ipv6Addr::from(start_octets))
        };
        let end = if version == 4 {
            let mut o = [0u8; 4];
            o.copy_from_slice(&end_octets[..4]);
            IpAddr::V4(Ipv4Addr::from(o))
        } else {
            IpAddr::V6(Ipv6Addr::from(end_octets))
        };
        if start > end {
            return None;
        }
        ranges.push(IpRange {
            start,
            end,
            ip_protocol,
        });
    }

    Some(ranges)
}

/// Encode a full `ROUTE_ADVERTISEMENT` capsule (TLV + payload).
pub fn encode_route_advertisement(ranges: &[IpRange]) -> Bytes {
    encode_capsule(CAPSULE_ROUTE_ADVERTISEMENT, &encode_route_value(ranges))
}

/// Decode a full `ROUTE_ADVERTISEMENT` capsule (TLV + payload), or `None`.
#[allow(dead_code)]
pub fn decode_route_advertisement(capsule: &[u8]) -> Option<Vec<IpRange>> {
    match decode_capsule(capsule) {
        Some((CAPSULE_ROUTE_ADVERTISEMENT, v)) => decode_route_value(&v),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DNS_ASSIGN / PREF64 payloads (draft-ietf-masque-connect-ip-dns-06)
// ---------------------------------------------------------------------------

/// NAT64 prefix lengths permitted by §4.1 — the IPv6-to-IPv4 address synthesis
/// sizes listed in RFC 6052 §2.2. This is a **closed** set: a peer sending any
/// other length has sent a malformed capsule (§4.2).
pub const NAT64_PREFIX_LENGTHS: [u8; 6] = [32, 40, 48, 56, 64, 96];

/// RFC 1035 §2.3.4 caps a wire-format domain name at 255 octets.
const MAX_DOMAIN_NAME_LEN: usize = 255;

/// SvcParams use DNS RDATA encoding, whose RDLENGTH field is 16 bits
/// (RFC 1035 §4.1.3, referenced by RFC 9460 §2.2).
const MAX_SERVICE_PARAMETERS_LEN: usize = u16::MAX as usize;

/// One `NAT64 Prefix` (§4.1 Figure 8). Exactly 13 bytes on the wire, always.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nat64Prefix {
    /// Length of [`Self::prefix`] used for synthesis. One of
    /// [`NAT64_PREFIX_LENGTHS`].
    pub prefix_len: u8,
    /// The highest 96 bits of the IPv6 prefix, network byte order. This field
    /// is always 12 bytes — it does **not** shrink with `prefix_len` (§4.1).
    pub prefix: [u8; 12],
}

/// One `Nameserver` (§3.2 Figure 2): a SVCB ServiceMode record carrying the
/// resolver's addresses, its optional authentication domain, and Service
/// Parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNameserver {
    /// Priority relative to sibling nameservers (SVCB ServiceMode, RFC 9460
    /// §2.4.1). §3.2 forbids 0.
    pub service_priority: u16,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    /// Domain name used to authenticate an encrypted transport; empty when the
    /// nameserver only offers unencrypted DNS (§3.2).
    pub auth_domain: String,
    /// SVCB Service Parameters (RFC 9460 §2.2) kept **opaque**: this layer never
    /// generates them, and interpreting the individual keys (alpn, port,
    /// dohpath, ...) is a job for whoever configures or consumes DNS.
    pub service_parameters: Bytes,
}

/// One `DNS Configuration` (§3.3 Figure 3). A single capsule may carry several,
/// when different resolvers serve different internal domains (§3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsConfiguration {
    pub nameservers: Vec<DnsNameserver>,
    /// Domains (and their subdomains, §3.5) the nameservers here can resolve.
    /// An empty string is the DNS root, i.e. "resolves everything".
    pub internal_domains: Vec<String>,
    /// Search-path suffixes appended during name resolution.
    pub search_domains: Vec<String>,
}

/// Write one `Domain` (§3.1 Figure 1): `Domain Length (i) + Domain Name`.
fn put_domain(v: &mut BytesMut, name: &str) {
    put_varint(v, name.len() as u64);
    v.extend_from_slice(name.as_bytes());
}

/// Read one `Domain`, rejecting trailing junk and non-UTF-8 (an IDNA A-label is
/// ASCII by definition, §3.1).
fn get_domain(buf: &mut &[u8]) -> Option<String> {
    let len = get_varint(buf)? as usize;
    if len > MAX_DOMAIN_NAME_LEN || buf.len() < len {
        return None;
    }
    let name = std::str::from_utf8(&buf[..len]).ok()?.to_owned();
    *buf = &buf[len..];
    Some(name)
}

/// Read a counted run of `Domain` structures (used verbatim for both Internal
/// and Search Domains, §3.3).
fn get_domain_list(buf: &mut &[u8]) -> Option<Vec<String>> {
    let count = get_varint(buf)?;
    let mut domains = Vec::new();
    for _ in 0..count {
        domains.push(get_domain(buf)?);
    }
    Some(domains)
}

/// Encode the payload of a `DNS_ASSIGN` capsule: one or more `DNS
/// Configuration` structures (§3.4 Figure 4).
///
/// There is deliberately **no** count of DNS Configurations — Figure 4 repeats
/// `DNS Configuration (..)` to the end of the value, and each configuration is
/// self-delimiting because every list inside it carries its own count. Adding a
/// count would corrupt the first configuration's Nameserver Count and break
/// interoperability with `connect-ip-go`, which likewise parses until the value
/// is exhausted.
///
/// The caller is responsible for the invariants the encoder cannot express —
/// notably §3.2's non-zero Service Priority and its address-count rule; see the
/// builder in `config.rs`, which is where administrator input is validated.
pub fn encode_dns_value(configs: &[DnsConfiguration]) -> Bytes {
    let mut v = BytesMut::new();

    for cfg in configs {
        put_varint(&mut v, cfg.nameservers.len() as u64);
        for ns in &cfg.nameservers {
            v.put_u16(ns.service_priority);
            put_varint(&mut v, ns.ipv4.len() as u64);
            for a in &ns.ipv4 {
                v.extend_from_slice(&a.octets());
            }
            put_varint(&mut v, ns.ipv6.len() as u64);
            for a in &ns.ipv6 {
                v.extend_from_slice(&a.octets());
            }
            put_domain(&mut v, &ns.auth_domain);
            put_varint(&mut v, ns.service_parameters.len() as u64);
            v.extend_from_slice(&ns.service_parameters);
        }
        put_varint(&mut v, cfg.internal_domains.len() as u64);
        for d in &cfg.internal_domains {
            put_domain(&mut v, d);
        }
        put_varint(&mut v, cfg.search_domains.len() as u64);
        for d in &cfg.search_domains {
            put_domain(&mut v, d);
        }
    }

    v.freeze()
}

/// Parse the payload of a `DNS_ASSIGN` capsule, consuming configurations until
/// the value is exhausted (see [`encode_dns_value`] for why there is no outer
/// count). Returns `None` on malformed input: truncation, a Service Priority of
/// 0 (§3.2), over-long domains or Service Parameters, or non-UTF-8 names.
pub fn decode_dns_value(value: &[u8]) -> Option<Vec<DnsConfiguration>> {
    let mut buf = value;
    let mut configs = Vec::new();

    while !buf.is_empty() {
        let ns_count = get_varint(&mut buf)?;
        let mut nameservers = Vec::new();
        for _ in 0..ns_count {
            if buf.len() < 2 {
                return None;
            }
            let service_priority = u16::from_be_bytes([buf[0], buf[1]]);
            buf = &buf[2..];
            // §3.2: ServiceMode requires a non-zero priority.
            if service_priority == 0 {
                return None;
            }

            let v4_count = get_varint(&mut buf)? as usize;
            let mut ipv4 = Vec::new();
            for _ in 0..v4_count {
                if buf.len() < 4 {
                    return None;
                }
                ipv4.push(Ipv4Addr::from([buf[0], buf[1], buf[2], buf[3]]));
                buf = &buf[4..];
            }

            let v6_count = get_varint(&mut buf)? as usize;
            let mut ipv6 = Vec::new();
            for _ in 0..v6_count {
                if buf.len() < 16 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[..16]);
                buf = &buf[16..];
                ipv6.push(Ipv6Addr::from(octets));
            }

            let auth_domain = get_domain(&mut buf)?;

            let params_len = get_varint(&mut buf)? as usize;
            if params_len > MAX_SERVICE_PARAMETERS_LEN || buf.len() < params_len {
                return None;
            }
            let service_parameters = Bytes::copy_from_slice(&buf[..params_len]);
            buf = &buf[params_len..];

            nameservers.push(DnsNameserver {
                service_priority,
                ipv4,
                ipv6,
                auth_domain,
                service_parameters,
            });
        }

        let internal_domains = get_domain_list(&mut buf)?;
        let search_domains = get_domain_list(&mut buf)?;

        configs.push(DnsConfiguration {
            nameservers,
            internal_domains,
            search_domains,
        });
    }

    Some(configs)
}

/// Encode a full `DNS_ASSIGN` capsule (TLV + payload).
pub fn encode_dns_assign(configs: &[DnsConfiguration]) -> Bytes {
    encode_capsule(CAPSULE_DNS_ASSIGN, &encode_dns_value(configs))
}

/// Decode a full `DNS_ASSIGN` capsule (TLV + payload), or `None`.
pub fn decode_dns_assign(capsule: &[u8]) -> Option<Vec<DnsConfiguration>> {
    match decode_capsule(capsule) {
        Some((CAPSULE_DNS_ASSIGN, v)) => decode_dns_value(&v),
        _ => None,
    }
}

/// Encode the payload of a `PREF64` capsule (§4.1 Figure 7): a bare run of 13-
/// byte `NAT64 Prefix` structures — no count, no length field. An empty slice
/// encodes an empty capsule, which tells the peer that no NAT64 prefixes are
/// available (§4.2).
pub fn encode_pref64_value(prefixes: &[Nat64Prefix]) -> Bytes {
    let mut v = BytesMut::with_capacity(prefixes.len() * 13);
    for p in prefixes {
        v.put_u8(p.prefix_len);
        v.extend_from_slice(&p.prefix);
    }
    v.freeze()
}

/// Parse the payload of a `PREF64` capsule. Returns `None` when the value is
/// malformed per §4.2: a length that is not a multiple of 13 bytes, or a Prefix
/// Length outside [`NAT64_PREFIX_LENGTHS`]. An empty value yields an empty vec.
pub fn decode_pref64_value(value: &[u8]) -> Option<Vec<Nat64Prefix>> {
    // §4.2: a length that is not a multiple of 13 bytes is malformed. `as_chunks`
    // gives us the remainder directly, so this one call is both the length check
    // and the iteration.
    let (chunks, remainder) = value.as_chunks::<13>();
    if !remainder.is_empty() {
        return None;
    }
    let mut prefixes = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let prefix_len = chunk[0];
        if !NAT64_PREFIX_LENGTHS.contains(&prefix_len) {
            return None;
        }
        let mut prefix = [0u8; 12];
        prefix.copy_from_slice(&chunk[1..13]);
        prefixes.push(Nat64Prefix { prefix_len, prefix });
    }
    Some(prefixes)
}

/// Encode a full `PREF64` capsule (TLV + payload).
pub fn encode_pref64(prefixes: &[Nat64Prefix]) -> Bytes {
    encode_capsule(CAPSULE_PREF64, &encode_pref64_value(prefixes))
}

/// Decode a full `PREF64` capsule (TLV + payload), or `None`.
pub fn decode_pref64(capsule: &[u8]) -> Option<Vec<Nat64Prefix>> {
    match decode_capsule(capsule) {
        Some((CAPSULE_PREF64, v)) => decode_pref64_value(&v),
        _ => None,
    }
}

/// The CONNECT-IP DNS/NAT64 signalling capsules for an installation, encoded
/// **once** at startup: the configuration is static, so every session sends the
/// same bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectIpCapsules {
    /// Encoded `DNS_ASSIGN`, or `None` when no resolver is configured — in which
    /// case no DNS capsule is sent at all, preserving the pre-existing
    /// behaviour.
    pub dns_assign: Option<Bytes>,
    /// Encoded `PREF64`, or `None` when no NAT64 prefix is configured.
    pub pref64: Option<Bytes>,
}

impl ConnectIpCapsules {
    /// True when neither DNS nor NAT64 is configured, i.e. nothing extra goes on
    /// the request stream.
    pub fn is_empty(&self) -> bool {
        self.dns_assign.is_none() && self.pref64.is_none()
    }
}

// ---------------------------------------------------------------------------
// QUIC variable-length integers (RFC 9000 §16) — correct as-is
// ---------------------------------------------------------------------------

/// Encode `value` as a QUIC variable-length integer (RFC 9000 §16).
pub fn put_varint(buf: &mut BytesMut, value: u64) {
    match value {
        0x00..=0x3f => buf.put_u8(value as u8),
        0x40..=0x3fff => buf.put_u16((value | 0x4000) as u16),
        0x4000..=0x3fff_ffff => buf.put_u32((value | 0x8000_0000) as u32),
        _ => buf.put_u64(value | 0xc000_0000_0000_0000),
    }
}

/// Decode a QUIC variable-length integer from the front of `buf`, advancing it.
pub fn get_varint(buf: &mut &[u8]) -> Option<u64> {
    let first = *buf.first()?;
    let len = 1 << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut value: u64 = (first & 0x3f) as u64;
    for i in 1..len {
        value = (value << 8) | *buf.get(i)? as u64;
    }
    *buf = &buf[len..];
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn varint_round_trip_all_forms() {
        // Values that exercise the 1-, 2-, 4- and 8-byte encodings, plus the
        // boundaries between them.
        for v in [
            0u64,
            1,
            63,
            64,        // 1-byte -> 2-byte boundary
            16383,
            16384,     // 2-byte -> 4-byte boundary
            16385,
            0xffff_ffff,
            0x1_0000_0000, // 4-byte -> 8-byte boundary
        ] {
            let mut buf = BytesMut::new();
            put_varint(&mut buf, v);
            let bytes = buf.freeze();
            let mut slice = bytes.as_ref();
            let decoded = get_varint(&mut slice).expect("decode");
            assert_eq!(decoded, v, "varint round trip failed for {v}");
            assert!(slice.is_empty(), "varint left trailing bytes for {v}");
        }
    }

    #[test]
    fn varint_encoding_lengths() {
        // Confirm the encoded byte length for each form.
        assert_eq!(encoded_len(0), 1);
        assert_eq!(encoded_len(63), 1);
        assert_eq!(encoded_len(64), 2);
        assert_eq!(encoded_len(16383), 2);
        assert_eq!(encoded_len(16384), 4);
        assert_eq!(encoded_len(0x3fff_ffff), 4); // max 4-byte form
        assert_eq!(encoded_len(0x4000_0000), 8); // first 8-byte value
        assert_eq!(encoded_len(0x1_0000_0000), 8);
    }

    fn encoded_len(v: u64) -> usize {
        let mut buf = BytesMut::new();
        put_varint(&mut buf, v);
        buf.len()
    }

    #[test]
    fn generic_capsule_round_trip_and_rejects() {
        for (typ, payload) in [
            (CAPSULE_ADDRESS_ASSIGN, vec![0xAB; 1]),
            (CAPSULE_ROUTE_ADVERTISEMENT, vec![0xCD; 40]),
        ] {
            let capsule = encode_capsule(typ, &payload);
            let (t, v) = decode_capsule(&capsule).expect("decode");
            assert_eq!(t, typ);
            assert_eq!(v.as_ref(), &payload[..]);
        }

        // A 20_000-byte value forces a 4-byte (0x80...) Length varint.
        let big = vec![0x11u8; 20_000];
        let capsule = encode_capsule(CAPSULE_ADDRESS_ASSIGN, &big);
        // First byte of Length must be in the 4-byte form range.
        assert!(capsule[1] & 0xC0 == 0x80, "length should be 4-byte form");
        let (t, v) = decode_capsule(&capsule).expect("decode big");
        assert_eq!(t, CAPSULE_ADDRESS_ASSIGN);
        assert_eq!(v.len(), 20_000);

        // Truncated: claims a Length longer than the bytes present.
        let trunc = vec![0x01u8, 0x0A, 0x01, 0x02, 0x03];
        assert!(decode_capsule(&trunc).is_none());

        // Truncated varint at the very start.
        assert!(decode_capsule(&[0x40]).is_none());
    }

    #[test]
    fn split_capsule_reports_consumed_bytes() {
        // Two back-to-back ADDRESS_ASSIGN-ish capsules; split must report each.
        let c1 = encode_capsule(CAPSULE_ADDRESS_ASSIGN, &[0xAA, 0xBB]);
        let c2 = encode_capsule(CAPSULE_ADDRESS_REQUEST, &[0xCC]);
        let mut both = c1.to_vec();
        both.extend_from_slice(&c2);

        let (t1, v1, used1) = split_capsule(&both).expect("first");
        assert_eq!((t1, v1), (CAPSULE_ADDRESS_ASSIGN, &[0xAA, 0xBB][..]));
        let (t2, v2, used2) = split_capsule(&both[used1..]).expect("second");
        assert_eq!((t2, v2), (CAPSULE_ADDRESS_REQUEST, &[0xCC][..]));
        assert_eq!(used1 + used2, both.len());
    }

    #[test]
    fn context_id_zero_is_stripped_and_nonzero_dropped() {
        // Context ID 0 (single 0x00 byte) -> the remainder is the raw payload.
        let dgram = [0x00u8, 0x45, 0x00, 0x01];
        assert_eq!(strip_context_id(&dgram), Some(&[0x45u8, 0x00, 0x01][..]));

        // Empty payload after Context ID 0.
        assert_eq!(strip_context_id(&[0x00]), Some(&[][..]));

        // Single-byte non-zero Context ID (0x01) -> dropped.
        assert_eq!(strip_context_id(&[0x01, 0x45, 0x00]), None);

        // Multi-byte varint Context ID: 0x40 0x2A encodes 42 (RFC 9000 §16
        // 2-byte form) -> dropped.
        assert_eq!(strip_context_id(&[0x40, 0x2A, 0xDE, 0xAD]), None);

        // Truncated varint (0x40 announces 2 bytes, only 0 arrives) -> dropped.
        assert_eq!(strip_context_id(&[0x40]), None);

        // Empty datagram -> dropped.
        assert_eq!(strip_context_id(&[]), None);
    }

    /// ADDRESS_ASSIGN for `198.18.0.2/32` with Request ID 0, byte-for-byte per
    /// RFC 9484 §4.7.1 Figure 8:
    /// `Request ID (varint)=0, IP Version (8)=4, IP Address (32), IP Prefix
    /// Length (8)=32`, inside the RFC 9297 TLV (`Type=0x01, Length=7`).
    #[test]
    fn address_assign_v4_exact_bytes() {
        let capsule = encode_address_assign(&[AssignedAddress {
            request_id: 0,
            address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
            prefix_len: 32,
        }]);
        let expected: &[u8] = &[
            0x01, // Type = ADDRESS_ASSIGN
            0x07, // Length = 7
            0x00, // Request ID = 0 (1-byte varint)
            0x04, // IP Version = 4
            0xC6, 0x12, 0x00, 0x02, // 198.18.0.2
            0x20, // Prefix Length = 32
        ];
        assert_eq!(capsule.as_ref(), expected);
        let parsed = decode_address_value(&expected[2..]).expect("parse");
        assert_eq!(
            parsed,
            vec![AssignedAddress {
                request_id: 0,
                address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
                prefix_len: 32,
            }]
        );
    }

    /// ADDRESS_REQUEST for `2001:db8::1/64` with Request ID 5, byte-for-byte
    /// per RFC 9484 §4.7.2 Figure 10.
    #[test]
    fn address_request_v6_exact_bytes() {
        let capsule = encode_address_request(&[AssignedAddress {
            request_id: 5,
            address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            prefix_len: 64,
        }]);
        let expected: &[u8] = &[
            0x02, // Type = ADDRESS_REQUEST
            0x13, // Length = 19
            0x05, // Request ID = 5
            0x06, // IP Version = 6
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // 2001:db8::1
            0x40, // Prefix Length = 64
        ];
        assert_eq!(capsule.as_ref(), expected);
        let parsed = decode_address_value(&expected[2..]).expect("parse");
        assert_eq!(
            parsed,
            vec![AssignedAddress {
                request_id: 5,
                address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                prefix_len: 64,
            }]
        );
    }

    /// ROUTE_ADVERTISEMENT for the IPv4 default route (0.0.0.0–255.255.255.255,
    /// all protocols), byte-for-byte per RFC 9484 §4.7.3 Figure 12.
    #[test]
    fn route_advertisement_v4_default_route_exact_bytes() {
        let capsule = encode_route_advertisement(&[IpRange {
            start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            end: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            ip_protocol: 0,
        }]);
        let expected: &[u8] = &[
            0x03, // Type = ROUTE_ADVERTISEMENT
            0x0A, // Length = 10 (1 + 4 + 4 + 1)
            0x04, // IP Version = 4
            0x00, 0x00, 0x00, 0x00, // Start IP Address = 0.0.0.0
            0xFF, 0xFF, 0xFF, 0xFF, // End IP Address = 255.255.255.255
            0x00, // IP Protocol = 0 (all)
        ];
        assert_eq!(capsule.as_ref(), expected);
        let parsed = decode_route_value(&expected[2..]).expect("parse");
        assert_eq!(
            parsed,
            vec![IpRange {
                start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                end: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                ip_protocol: 0,
            }]
        );
    }

    #[test]
    fn address_value_round_trip_multiple_entries() {
        let entries = vec![
            AssignedAddress {
                request_id: 7,
                address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 6)),
                prefix_len: 30,
            },
            AssignedAddress {
                request_id: 0,
                address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
                prefix_len: 128,
            },
        ];
        let capsule = encode_address_assign(&entries);
        let (t, v) = decode_capsule(&capsule).expect("decode assign");
        assert_eq!(t, CAPSULE_ADDRESS_ASSIGN);
        let parsed = decode_address_value(&v).expect("parse assign value");
        assert_eq!(parsed, entries);
    }

    #[test]
    fn address_value_rejects_malformed() {
        // IP Version not 4/6.
        assert!(decode_address_value(&[0x00, 0x05, 1, 2, 3, 4, 24]).is_none());

        // Truncated IPv4 address (3 bytes).
        assert!(decode_address_value(&[0x00, 0x04, 1, 2, 3, 32]).is_none());

        // Truncated IPv6 address (15 bytes).
        let mut v = vec![0x00, 0x06];
        v.extend_from_slice(&[0u8; 15]);
        v.push(128);
        assert!(decode_address_value(&v).is_none());

        // Missing prefix length byte.
        assert!(decode_address_value(&[0x00, 0x04, 1, 2, 3, 4]).is_none());

        // Prefix length exceeds address size (33 for v4).
        assert!(decode_address_value(&[0x00, 0x04, 1, 2, 3, 4, 33]).is_none());
        // (129 for v6)
        let mut v = vec![0x00, 0x06];
        v.extend_from_slice(&[0u8; 16]);
        v.push(129);
        assert!(decode_address_value(&v).is_none());

        // Empty payload is a valid zero-entry capsule.
        assert_eq!(decode_address_value(&[]), Some(Vec::new()));
    }

    #[test]
    fn route_value_round_trip_v4_and_v6() {
        let ranges = vec![
            IpRange {
                start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)),
                ip_protocol: 6, // TCP only
            },
            IpRange {
                start: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                end: IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 0, 0xffff, 0xffff, 0xffff, 0xffff,
                )),
                ip_protocol: 0,
            },
        ];
        let capsule = encode_route_advertisement(&ranges);
        let (t, v) = decode_capsule(&capsule).expect("decode route");
        assert_eq!(t, CAPSULE_ROUTE_ADVERTISEMENT);
        let parsed = decode_route_value(&v).expect("parse route value");
        assert_eq!(parsed, ranges);
    }

    #[test]
    fn route_value_rejects_malformed() {
        // IP Version not 4/6.
        assert!(decode_route_value(&[0x05, 1, 2, 3, 4, 5, 6, 7, 8, 0]).is_none());

        // Truncated (missing End address + protocol).
        assert!(decode_route_value(&[0x04, 1, 2, 3, 4]).is_none());

        // Start > End.
        assert!(
            decode_route_value(&[0x04, 10, 0, 0, 5, 10, 0, 0, 1, 0]).is_none(),
            "Start IP Address > End IP Address must be rejected"
        );

        // Start (v4) and End (length implied by version) of wrong total size.
        assert!(decode_route_value(&[0x04, 1, 2, 3, 4, 5, 6, 7, 0]).is_none());

        // Empty payload is a valid zero-range capsule.
        assert_eq!(decode_route_value(&[]), Some(Vec::new()));
    }

    // -- DNS_ASSIGN / PREF64 (draft-ietf-masque-connect-ip-dns-06) ----------

    fn split_tunnel() -> DnsConfiguration {
        DnsConfiguration {
            nameservers: vec![DnsNameserver {
                service_priority: 1,
                ipv4: vec![Ipv4Addr::new(192, 0, 2, 33)],
                ipv6: vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)],
                auth_domain: String::new(),
                service_parameters: Bytes::new(),
            }],
            internal_domains: vec!["internal.corp.example.".to_string()],
            search_domains: Vec::new(),
        }
    }

    /// DNS_ASSIGN carrying §3.6.2's split-tunnel nameserver, byte-for-byte per
    /// §3.2/§3.3: `DNS Configuration { Nameserver Count (i), Nameserver { Service
    /// Priority (16), IPv4 Address Count (i), IPv4 Address (32), IPv6 Address
    /// Count (i), IPv6 Address (128), Domain, Service Parameters Length (i) },
    /// Internal Domain Count (i), Internal Domain (..), Search Domain Count (i) }`
    /// inside the RFC 9297 TLV. The capsule Type 0x1ACE79EC is > 0x3fff so it
    /// takes the 4-byte varint form: `0x8000_0000 | 0x1ACE79EC = 0x9ACE79EC`.
    #[test]
    fn dns_assign_split_tunnel_exact_bytes() {
        let capsule = encode_dns_assign(std::slice::from_ref(&split_tunnel()));
        // NOTE: the value carries no count of DNS Configurations — it begins
        // directly with the first configuration's Nameserver Count. See
        // `encode_dns_value`.
        let mut expected: Vec<u8> = vec![
            0x9A, 0xCE, 0x79, 0xEC, // Type = DNS_ASSIGN (4-byte varint)
            0x34, // Length = 52
            0x01, // Nameserver Count = 1
            0x00, 0x01, // Service Priority = 1
            0x01, // IPv4 Address Count = 1
            0xC0, 0x00, 0x02, 0x21, // 192.0.2.33
            0x01, // IPv6 Address Count = 1
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // 2001:db8::1
            0x00, // Authentication Domain Name = "" (empty Domain)
            0x00, // Service Parameters Length = 0
            0x01, // Internal Domain Count = 1
            0x16, // Domain Length = 22
        ];
        expected.extend_from_slice(b"internal.corp.example.");
        expected.push(0x00); // Search Domain Count = 0

        assert_eq!(
            expected.len(),
            4 + 1 + 52,
            "fixture length must match: Type (4-byte varint) + Length (1) + 52-byte value"
        );
        assert_eq!(capsule.as_ref(), &expected[..]);
        let parsed = decode_dns_assign(&expected).expect("parse");
        assert_eq!(parsed, vec![split_tunnel()]);
    }

    /// PREF64 signalling `64:ff9b::/96`, byte-for-byte from §4.3. Type
    /// 0x274C0FBC takes the 4-byte varint form `0x8000_0000 | 0x274C0FBC`.
    #[test]
    fn pref64_well_known_prefix_exact_bytes() {
        let mut prefix = [0u8; 12];
        prefix[..4].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b]);
        let capsule = encode_pref64(&[Nat64Prefix {
            prefix_len: 96,
            prefix,
        }]);
        let expected: &[u8] = &[
            0xA7, 0x4C, 0x0F, 0xBC, // Type = PREF64 (4-byte varint)
            0x0D, // Length = 13
            0x60, // Prefix Length = 96
            0x00, 0x64, 0xFF, 0x9B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, // Prefix (always 96 bits)
        ];
        assert_eq!(capsule.as_ref(), expected);
    }

    #[test]
    fn pref64_round_trip_multiple_prefixes() {
        let mut local = [0u8; 12];
        local[..6].copy_from_slice(&[0x00, 0x64, 0xff, 0x9b, 0x00, 0x01]);
        let prefixes = vec![
            Nat64Prefix {
                prefix_len: 96,
                prefix: local,
            },
            Nat64Prefix {
                prefix_len: 32,
                prefix: local,
            },
        ];
        let capsule = encode_pref64(&prefixes);
        let parsed = decode_pref64(&capsule).expect("decode PREF64");
        assert_eq!(parsed, prefixes);

        // §4.2: an empty capsule means "no NAT64 prefixes are available".
        let empty = encode_pref64(&[]);
        assert_eq!(decode_pref64(&empty), Some(Vec::new()));
    }

    #[test]
    fn pref64_rejects_malformed() {
        // Not a multiple of 13 bytes (§4.2).
        assert!(decode_pref64_value(&[0x60, 0x00, 0x64]).is_none());
        assert!(decode_pref64_value(&[0x00; 12]).is_none());
        assert!(decode_pref64_value(&[0x00; 14]).is_none());

        // Prefix Length outside the permitted set (RFC 6052 §2.2 sizes).
        for bad_len in [0u8, 1, 31, 33, 65, 95, 97, 128, 255] {
            let mut value = vec![bad_len];
            value.extend_from_slice(&[0x00; 12]);
            assert!(
                decode_pref64_value(&value).is_none(),
                "prefix length {bad_len} must be rejected"
            );
        }
        // 13 bytes but the *first* of two prefixes is invalid.
        let mut two = vec![0x60];
        two.extend_from_slice(&[0x00; 12]);
        two.push(0x0F); // not a valid NAT64 length
        two.extend_from_slice(&[0x00; 12]);
        assert!(decode_pref64_value(&two).is_none());
    }

    #[test]
    fn dns_value_round_trip_multiple_configurations() {
        let configs = vec![
            split_tunnel(),
            DnsConfiguration {
                nameservers: vec![
                    DnsNameserver {
                        service_priority: 1,
                        ipv4: vec![],
                        ipv6: vec![],
                        auth_domain: "masque.example.org.".to_string(),
                        // Stand-in SvcParams bytes; this layer treats them as
                        // opaque.
                        service_parameters: Bytes::from_static(&[0x00, 0x01, 0x02]),
                    },
                    DnsNameserver {
                        service_priority: 42,
                        ipv4: vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)],
                        ipv6: vec![Ipv6Addr::LOCALHOST],
                        auth_domain: String::new(),
                        service_parameters: Bytes::new(),
                    },
                ],
                internal_domains: vec![String::new()], // DNS root = resolves all
                search_domains: vec!["corp.example.".to_string(), "example.".to_string()],
            },
        ];
        let capsule = encode_dns_assign(&configs);
        let (t, v) = decode_capsule(&capsule).expect("decode DNS_ASSIGN");
        assert_eq!(t, CAPSULE_DNS_ASSIGN);
        assert_eq!(decode_dns_value(&v).expect("parse dns value"), configs);
    }

    #[test]
    fn dns_value_rejects_malformed() {
        let base = encode_dns_value(&[split_tunnel()]);

        // Service Priority 0 is forbidden in ServiceMode (§3.2).
        let mut zero_priority = base.to_vec();
        zero_priority[1] = 0x00; // Service Priority occupies value[1..3]
        zero_priority[2] = 0x00;
        assert!(decode_dns_value(&zero_priority).is_none());

        // Appending garbage does not make a *longer* configuration: it would
        // start a second DNS Configuration that cannot be parsed in full.
        let mut trailing = base.to_vec();
        trailing.push(0x00);
        assert!(decode_dns_value(&trailing).is_none());

        // Truncated: cut the search-domain count off the end.
        assert!(decode_dns_value(&base[..base.len() - 1]).is_none());

        // Truncated mid-IPv6-address.
        assert!(decode_dns_value(&base[..10]).is_none());

        // Domain Length larger than the value actually holds.
        let mut bad_domain: Vec<u8> = vec![
            0x01, // Nameserver Count = 1
            0x00, 0x01, // Service Priority
            0x00, // IPv4 Count
            0x00, // IPv6 Count
            0xFF, // Domain Length = 255 (claims far more than we send)
        ];
        bad_domain.extend_from_slice(b"short.example.");
        bad_domain.push(0x00); // Service Parameters Length
        bad_domain.push(0x00); // Internal Domain Count
        bad_domain.push(0x00); // Search Domain Count
        assert!(decode_dns_value(&bad_domain).is_none());

        // Non-UTF-8 Domain Name (an IDNA A-label is ASCII, §3.1).
        let mut non_utf8: Vec<u8> = vec![
            0x01, 0x00, 0x01, 0x00, 0x00, 0x02, // Domain Length = 2
        ];
        non_utf8.extend_from_slice(&[0xC3, 0x28]); // invalid UTF-8 sequence
        non_utf8.push(0x00); // Service Parameters Length
        non_utf8.push(0x00); // Internal Domain Count
        non_utf8.push(0x00); // Search Domain Count
        assert!(decode_dns_value(&non_utf8).is_none());

        // A header-only value cannot be completed.
        assert!(decode_dns_value(&[0x01, 0x00]).is_none());

        // Zero DNS Configurations is a legitimate zero-length value, same as
        // ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT.
        assert_eq!(decode_dns_value(&[]), Some(Vec::new()));
    }

    #[test]
    fn connect_ip_capsules_is_empty_only_when_nothing_is_configured() {
        let none = ConnectIpCapsules {
            dns_assign: None,
            pref64: None,
        };
        assert!(none.is_empty());

        let dns_only = ConnectIpCapsules {
            dns_assign: Some(encode_dns_assign(&[split_tunnel()])),
            pref64: None,
        };
        assert!(!dns_only.is_empty());

        let pref64_only = ConnectIpCapsules {
            dns_assign: None,
            pref64: Some(encode_pref64(&[])),
        };
        assert!(!pref64_only.is_empty());
    }
}
