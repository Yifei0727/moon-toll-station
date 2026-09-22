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
//!
//! All of this is pure, allocation-light, and fully unit-testable without root
//! or a network device.

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
pub(crate) const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;

/// `ADDRESS_REQUEST` (0x02) — an endpoint requests address assignment from its
/// peer (RFC 9484 §4.7.2).
pub(crate) const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;

/// `ROUTE_ADVERTISEMENT` (0x03) — an endpoint advertises the IP address ranges
/// it is willing to route for its peer (RFC 9484 §4.7.3).
pub(crate) const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

// ---------------------------------------------------------------------------
// CONNECT-IP signalling structures (RFC 9484 §4.7)
// ---------------------------------------------------------------------------

/// One `Assigned Address` / `Requested Address` (RFC 9484 §4.7.1 Figure 8 /
/// §4.7.2 Figure 10). The prefix length is mandatory (`/32` for a single host
/// IPv4 assignment, `/128` for IPv6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AssignedAddress {
    /// Echoed in the ADDRESS_ASSIGN response; 0 for unprompted assignments.
    pub request_id: u64,
    pub address: IpAddr,
    pub prefix_len: u8,
}

/// One `IP Address Range` (RFC 9484 §4.7.3 Figure 12): the inclusive range
/// `start..=end` for `ip_protocol` (`0` = all protocols; ICMP is always
/// allowed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IpRange {
    pub start: IpAddr,
    pub end: IpAddr,
    pub ip_protocol: u8,
}

// ---------------------------------------------------------------------------
// Generic capsule TLV (RFC 9297 §3) — request-stream framing ONLY
// ---------------------------------------------------------------------------

/// Encode a capsule: `Type` (varint) + `Length` (varint) + `Value`.
pub(crate) fn encode_capsule(typ: u64, value: &[u8]) -> Bytes {
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
pub(crate) fn split_capsule(bytes: &[u8]) -> Option<(u64, &[u8], usize)> {
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
pub(crate) fn decode_capsule(bytes: &[u8]) -> Option<(u64, Bytes)> {
    let (typ, value, _) = split_capsule(bytes)?;
    Some((typ, Bytes::copy_from_slice(value)))
}

/// Strip the HTTP-datagram `Context ID` (RFC 9297 §4) from the front of a
/// datagram payload (the Quarter Stream ID has already been removed by
/// `h3-datagram`). Returns the remainder **only** for Context ID 0 — the only
/// context we use. `None` means "drop this datagram silently": a non-zero
/// Context ID we did not negotiate, or a truncated varint. Dropping must not
/// error the tunnel (RFC 9298 §4.2 / RFC 9484 §4.2).
pub(crate) fn strip_context_id(dgram: &[u8]) -> Option<&[u8]> {
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
pub(crate) fn encode_address_value(entries: &[AssignedAddress]) -> Bytes {
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
pub(crate) fn decode_address_value(value: &[u8]) -> Option<Vec<AssignedAddress>> {
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
pub(crate) fn encode_address_assign(entries: &[AssignedAddress]) -> Bytes {
    encode_capsule(CAPSULE_ADDRESS_ASSIGN, &encode_address_value(entries))
}

/// Encode a full `ADDRESS_REQUEST` capsule (TLV + payload).
///
/// The proxy never sends an `ADDRESS_REQUEST` (that is the client's role in
/// RFC 9484 §4.7.2); this is part of the complete capsule API and is exercised
/// by the unit tests, hence `allow(dead_code)`.
#[allow(dead_code)]
pub(crate) fn encode_address_request(entries: &[AssignedAddress]) -> Bytes {
    encode_capsule(CAPSULE_ADDRESS_REQUEST, &encode_address_value(entries))
}

/// Decode a full `ADDRESS_ASSIGN` capsule (TLV + payload), or `None` if it is
/// not an ADDRESS_ASSIGN or the payload is malformed.
#[allow(dead_code)]
pub(crate) fn decode_address_assign(capsule: &[u8]) -> Option<Vec<AssignedAddress>> {
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
pub(crate) fn encode_route_value(ranges: &[IpRange]) -> Bytes {
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
pub(crate) fn decode_route_value(value: &[u8]) -> Option<Vec<IpRange>> {
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
pub(crate) fn encode_route_advertisement(ranges: &[IpRange]) -> Bytes {
    encode_capsule(CAPSULE_ROUTE_ADVERTISEMENT, &encode_route_value(ranges))
}

/// Decode a full `ROUTE_ADVERTISEMENT` capsule (TLV + payload), or `None`.
#[allow(dead_code)]
pub(crate) fn decode_route_advertisement(capsule: &[u8]) -> Option<Vec<IpRange>> {
    match decode_capsule(capsule) {
        Some((CAPSULE_ROUTE_ADVERTISEMENT, v)) => decode_route_value(&v),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// QUIC variable-length integers (RFC 9000 §16) — correct as-is
// ---------------------------------------------------------------------------

/// Encode `value` as a QUIC variable-length integer (RFC 9000 §16).
pub(crate) fn put_varint(buf: &mut BytesMut, value: u64) {
    match value {
        0x00..=0x3f => buf.put_u8(value as u8),
        0x40..=0x3fff => buf.put_u16((value | 0x4000) as u16),
        0x4000..=0x3fff_ffff => buf.put_u32((value | 0x8000_0000) as u32),
        _ => buf.put_u64(value | 0xc000_0000_0000_0000),
    }
}

/// Decode a QUIC variable-length integer from the front of `buf`, advancing it.
pub(crate) fn get_varint(buf: &mut &[u8]) -> Option<u64> {
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
}
