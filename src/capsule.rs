//! RFC 9297 capsule protocol + RFC 9484 (CONNECT-IP) capsule types.
//!
//! A "capsule" (RFC 9297 §3) is a self-delimiting Type-Length-Value unit:
//! `Type` and `Length` are QUIC variable-length integers (RFC 9000 §16) and
//! `Value` is exactly `Length` bytes. HTTP/3 MASQUE carries these inside
//! HTTP/3 DATAGRAM frames (RFC 9297 §4) with Context ID 0 — the same framing
//! `CONNECT-UDP` uses, so the encode/decode here is shared by both protocols.
//!
//! CONNECT-IP (RFC 9484 §7) defines the capsule types and the *structured
//! fields* that make up the `Value` of the address/route capsules. Those
//! structured fields are themselves a Type-Length-Value sequence (Type and
//! Length are varints, Value is the address/prefix bytes) — i.e. a capsule
//! nested inside a capsule. This module handles both layers.
//!
//! All of this is pure, allocation-light, and fully unit-testable without root
//! or a network device.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, Bytes, BytesMut};

/// `DATAGRAM` — the only capsule type `CONNECT-UDP` uses (RFC 9298 §4).
pub(crate) const CAPSULE_DATAGRAM: u64 = 0x00;

/// `New Client Address` — RFC 9484 §7.1. **Deprecated** by RFC 9484 in favour
/// of `Address Assign`/`Address Request`; we accept it on decode but never
/// require it and never send it.
///
/// Part of the complete RFC 9484 capsule type set; not emitted or matched by
/// the proxy today, hence `allow(dead_code)`.
#[allow(dead_code)]
pub(crate) const CAPSULE_NEW_CLIENT_ADDRESS: u64 = 0x01;

/// `IP` — an entire IP packet (starts with the IP header). Both directions of
/// the tunnel use this (RFC 9484 §7.4).
pub(crate) const CAPSULE_IP: u64 = 0x02;

/// `Address Assign` — proxy tells the client the address(es)/prefix(es) it
/// owns (RFC 9484 §7.2).
pub(crate) const CAPSULE_ADDRESS_ASSIGN: u64 = 0x03;

/// `Address Request` — client asks the proxy for address(es) (RFC 9484 §7.1).
pub(crate) const CAPSULE_ADDRESS_REQUEST: u64 = 0x04;

/// `Route Advertisement` — proxy advertises route(s)/prefix(es) to the client
/// (RFC 9484 §7.3).
pub(crate) const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x05;

// ---------------------------------------------------------------------------
// CONNECT-IP structured-field types (RFC 9484 §7). These appear inside the
// `Value` of ADDRESS_ASSIGN / ADDRESS_REQUEST / ROUTE_ADVERTISEMENT.
// ---------------------------------------------------------------------------

/// `IPv4 Address` structured field (Value = 4 bytes).
const FIELD_IPV4_ADDRESS: u64 = 0x04;
/// `IPv6 Address` structured field (Value = 16 bytes).
const FIELD_IPV6_ADDRESS: u64 = 0x06;
/// `Prefix Length` structured field (Value = 1 byte, 0..32 for v4 / 0..128 for v6).
const FIELD_PREFIX_LENGTH: u64 = 0x05;
/// `IPv6 Suffix` structured field (Value = 8 bytes). Part of the RFC 9484
/// structured-field set; not used by the proxy (we assign full prefixes), hence
/// `allow(dead_code)`.
#[allow(dead_code)]
const FIELD_IPV6_SUFFIX: u64 = 0x08;

/// One address assignment / request entry. `prefix_len == None` means a host
/// address (`/32` for IPv4, `/128` for IPv6); `Some(n)` is an explicit prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IpAddressEntry {
    pub address: IpAddr,
    pub prefix_len: Option<u8>,
}

/// A route advertised to the client. Unlike [`IpAddressEntry`], the prefix
/// length is mandatory (a route is meaningless without one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Route {
    pub address: IpAddr,
    pub prefix_len: u8,
}

// ---------------------------------------------------------------------------
// Generic capsule TLV (RFC 9297 §3)
// ---------------------------------------------------------------------------

/// Encode a capsule: `Type` (varint) + `Length` (varint) + `Value`.
pub(crate) fn encode_capsule(typ: u64, value: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(8 + value.len());
    put_varint(&mut buf, typ);
    put_varint(&mut buf, value.len() as u64);
    buf.extend_from_slice(value);
    buf.freeze()
}

/// Decode a capsule, returning `(Type, Value)`. Returns `None` if the framing
/// is truncated or garbled (a partial first varint, or `Length` claiming more
/// bytes than remain).
pub(crate) fn decode_capsule(bytes: &[u8]) -> Option<(u64, Bytes)> {
    let mut buf = bytes;
    let typ = get_varint(&mut buf)?;
    let len = get_varint(&mut buf)? as usize;
    if buf.len() < len {
        return None;
    }
    Some((typ, Bytes::copy_from_slice(&buf[..len])))
}

/// Wrap a raw IP packet as an `IP` capsule.
pub(crate) fn encode_ip_packet(packet: &[u8]) -> Bytes {
    encode_capsule(CAPSULE_IP, packet)
}

/// Decode an `IP` capsule back into the raw packet, or `None` if it is not an
/// `IP` capsule.
pub(crate) fn decode_ip_packet(capsule: &[u8]) -> Option<Bytes> {
    match decode_capsule(capsule) {
        Some((CAPSULE_IP, v)) => Some(v),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// CONNECT-IP address / route capsules (RFC 9484 §7)
// ---------------------------------------------------------------------------

/// Encode the `Value` of an `Address Assign` or `Address Request` capsule from a
/// sequence of entries. Each entry is an `IPv4 Address`/`IPv6 Address` field
/// followed by an optional `Prefix Length` field (RFC 9484 §7.1/§7.2).
pub(crate) fn encode_address_value(entries: &[IpAddressEntry]) -> Bytes {
    let mut v = BytesMut::new();
    for e in entries {
        match e.address {
            IpAddr::V4(a) => put_field(&mut v, FIELD_IPV4_ADDRESS, &a.octets()),
            IpAddr::V6(a) => put_field(&mut v, FIELD_IPV6_ADDRESS, &a.octets()),
        }
        if let Some(prefix) = e.prefix_len {
            put_field(&mut v, FIELD_PREFIX_LENGTH, &[prefix]);
        }
    }
    v.freeze()
}

/// Encode a full `Address Assign` capsule.
pub(crate) fn encode_address_assign(entries: &[IpAddressEntry]) -> Bytes {
    encode_capsule(CAPSULE_ADDRESS_ASSIGN, &encode_address_value(entries))
}

/// Encode a full `Address Request` capsule (same body layout as `Address Assign`).
///
/// The proxy never sends an `Address Request` (that is the client's role in
/// RFC 9484 §7.1); this is part of the complete capsule API and is exercised by
/// the unit tests, hence `allow(dead_code)`.
#[allow(dead_code)]
pub(crate) fn encode_address_request(entries: &[IpAddressEntry]) -> Bytes {
    encode_capsule(CAPSULE_ADDRESS_REQUEST, &encode_address_value(entries))
}

/// Parse the `Value` of an `Address Assign`/`Address Request` capsule into a
/// sequence of entries. Mirrors the "associative array" grammar: each IP Address
/// field opens a new entry, and an immediately following Prefix Length field
/// attaches to the pending entry. Returns `None` on any malformed input (truncated
/// field, prefix length without a preceding address, wrong-length address).
pub(crate) fn decode_address_value(value: &[u8]) -> Option<Vec<IpAddressEntry>> {
    let mut entries = Vec::new();
    let mut pending: Option<IpAddr> = None;
    let mut buf = value;

    while !buf.is_empty() {
        let field_type = get_varint(&mut buf)?;
        let field_len = get_varint(&mut buf)? as usize;
        if buf.len() < field_len {
            return None;
        }
        let field_val = &buf[..field_len];
        buf = &buf[field_len..];

        match field_type {
            FIELD_IPV4_ADDRESS => {
                if field_len != 4 {
                    return None;
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(field_val);
                flush_pending(&mut entries, &mut pending, None);
                pending = Some(IpAddr::V4(Ipv4Addr::from(octets)));
            }
            FIELD_IPV6_ADDRESS => {
                if field_len != 16 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(field_val);
                flush_pending(&mut entries, &mut pending, None);
                pending = Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            FIELD_PREFIX_LENGTH => {
                if field_len != 1 {
                    return None;
                }
                let prefix = field_val[0];
                // A Prefix Length with no preceding address is malformed.
                let addr = pending.take()?;
                entries.push(IpAddressEntry {
                    address: addr,
                    prefix_len: Some(prefix),
                });
            }
            // Unknown field (e.g. IPv6 Suffix 0x08) — RFC 9484 only defines the
            // three above for these capsules; treat anything else as malformed.
            _ => return None,
        }
    }

    // Flush a trailing address that had no explicit prefix (host assignment).
    flush_pending(&mut entries, &mut pending, None);
    Some(entries)
}

/// Encode the `Value` of a `Route Advertisement` capsule. Each route is an
/// `IP Prefix` field (IPv4/IPv6 address) immediately followed by a mandatory
/// `Prefix Length` field (RFC 9484 §7.3).
pub(crate) fn encode_route_value(routes: &[Route]) -> Bytes {
    let mut v = BytesMut::new();
    for r in routes {
        match r.address {
            IpAddr::V4(a) => put_field(&mut v, FIELD_IPV4_ADDRESS, &a.octets()),
            IpAddr::V6(a) => put_field(&mut v, FIELD_IPV6_ADDRESS, &a.octets()),
        }
        put_field(&mut v, FIELD_PREFIX_LENGTH, &[r.prefix_len]);
    }
    v.freeze()
}

/// Encode a full `Route Advertisement` capsule.
pub(crate) fn encode_route_advertisement(routes: &[Route]) -> Bytes {
    encode_capsule(CAPSULE_ROUTE_ADVERTISEMENT, &encode_route_value(routes))
}

/// Parse the `Value` of a `Route Advertisement` capsule. Every route is an
/// address followed by a *mandatory* prefix length; a missing prefix is an error.
pub(crate) fn decode_route_value(value: &[u8]) -> Option<Vec<Route>> {
    let mut routes = Vec::new();
    let mut pending: Option<IpAddr> = None;
    let mut buf = value;

    while !buf.is_empty() {
        let field_type = get_varint(&mut buf)?;
        let field_len = get_varint(&mut buf)? as usize;
        if buf.len() < field_len {
            return None;
        }
        let field_val = &buf[..field_len];
        buf = &buf[field_len..];

        match field_type {
            FIELD_IPV4_ADDRESS => {
                if field_len != 4 {
                    return None;
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(field_val);
                pending = Some(IpAddr::V4(Ipv4Addr::from(octets)));
            }
            FIELD_IPV6_ADDRESS => {
                if field_len != 16 {
                    return None;
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(field_val);
                pending = Some(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            FIELD_PREFIX_LENGTH => {
                if field_len != 1 {
                    return None;
                }
                let prefix = field_val[0];
                let addr = pending.take()?;
                routes.push(Route {
                    address: addr,
                    prefix_len: prefix,
                });
            }
            _ => return None,
        }
    }

    // A route must always carry a prefix length; a dangling address is malformed.
    if pending.is_some() {
        return None;
    }
    Some(routes)
}

/// Helper: finish any pending address entry with an optional explicit prefix.
/// `explicit` is unused today but kept for symmetry/clarity of intent.
fn flush_pending(
    entries: &mut Vec<IpAddressEntry>,
    pending: &mut Option<IpAddr>,
    explicit: Option<u8>,
) {
    if let Some(addr) = pending.take() {
        entries.push(IpAddressEntry {
            address: addr,
            prefix_len: explicit,
        });
    }
}

/// Put one CONNECT-IP structured field (Type varint + Length varint + Value).
fn put_field(buf: &mut BytesMut, typ: u64, value: &[u8]) {
    put_varint(buf, typ);
    put_varint(buf, value.len() as u64);
    buf.extend_from_slice(value);
}

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
            (CAPSULE_IP, vec![0u8; 0]),
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
        let capsule = encode_capsule(CAPSULE_IP, &big);
        // First byte of Length must be in the 4-byte form range.
        assert!(capsule[1] & 0xC0 == 0x80, "length should be 4-byte form");
        let (t, v) = decode_capsule(&capsule).expect("decode big");
        assert_eq!(t, CAPSULE_IP);
        assert_eq!(v.len(), 20_000);

        // Truncated: claims a Length longer than the bytes present.
        let trunc = vec![CAPSULE_IP as u8, 0x0A, 0x01, 0x02, 0x03];
        assert!(decode_capsule(&trunc).is_none());

        // Truncated varint at the very start.
        assert!(decode_capsule(&[0x40]).is_none());
    }

    #[test]
    fn ip_capsule_round_trip() {
        let pkt = vec![0x45u8, 0x00, 0x01, 0x02, 0xDE, 0xAD, 0xBE, 0xEF];
        let capsule = encode_ip_packet(&pkt);
        let decoded = decode_ip_packet(&capsule).expect("decode ip");
        assert_eq!(decoded.as_ref(), &pkt[..]);
        // A non-IP capsule is rejected.
        let not_ip = encode_capsule(CAPSULE_ADDRESS_ASSIGN, &[0u8; 4]);
        assert!(decode_ip_packet(&not_ip).is_none());
    }

    #[test]
    fn address_assign_round_trip_v4_and_v6() {
        let entries = vec![
            IpAddressEntry {
                address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)),
                prefix_len: Some(30),
            },
            IpAddressEntry {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_len: None, // host assignment
            },
            IpAddressEntry {
                address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                prefix_len: Some(64),
            },
        ];
        let capsule = encode_address_assign(&entries);
        let (t, v) = decode_capsule(&capsule).expect("decode assign");
        assert_eq!(t, CAPSULE_ADDRESS_ASSIGN);
        let parsed = decode_address_value(&v).expect("parse assign value");
        assert_eq!(parsed, entries);
    }

    #[test]
    fn address_assign_host_without_prefix() {
        // A bare IPv4 address with no following prefix length => host (/32).
        let entries = vec![IpAddressEntry {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            prefix_len: None,
        }];
        let capsule = encode_address_assign(&entries);
        let (_t, v) = decode_capsule(&capsule).unwrap();
        let parsed = decode_address_value(&v).unwrap();
        assert_eq!(parsed, entries);
    }

    #[test]
    fn address_assign_rejects_malformed() {
        // Prefix length with no preceding address.
        let mut v = BytesMut::new();
        put_field(&mut v, FIELD_PREFIX_LENGTH, &[24]);
        assert!(decode_address_value(&v).is_none());

        // IPv4 address with wrong length (3 bytes).
        let mut v = BytesMut::new();
        put_field(&mut v, FIELD_IPV4_ADDRESS, &[1, 2, 3]);
        assert!(decode_address_value(&v).is_none());

        // Truncated field (claims 10 bytes, has 3).
        let mut v = BytesMut::new();
        put_field(&mut v, FIELD_IPV4_ADDRESS, &[1, 2, 3]);
        // Manually corrupt the length to claim 10.
        let mut bytes = v.to_vec();
        bytes[1] = 0x0A;
        assert!(decode_address_value(&bytes).is_none());
    }

    #[test]
    fn route_advertisement_round_trip() {
        let routes = vec![
            Route {
                address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                prefix_len: 0, // default route
            },
            Route {
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
            },
            Route {
                address: IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0)),
                prefix_len: 32,
            },
        ];
        let capsule = encode_route_advertisement(&routes);
        let (t, v) = decode_capsule(&capsule).expect("decode route");
        assert_eq!(t, CAPSULE_ROUTE_ADVERTISEMENT);
        let parsed = decode_route_value(&v).expect("parse route value");
        assert_eq!(parsed, routes);
    }

    #[test]
    fn route_advertisement_requires_prefix() {
        // A route address with no following prefix length is malformed.
        let mut v = BytesMut::new();
        put_field(&mut v, FIELD_IPV4_ADDRESS, &[10, 0, 0, 0]);
        assert!(decode_route_value(&v).is_none());

        // Unknown field type inside a route body.
        let mut v = BytesMut::new();
        put_field(&mut v, 0x99, &[1]);
        assert!(decode_route_value(&v).is_none());
    }

    #[test]
    fn address_request_is_same_layout_as_assign() {
        let entries = vec![IpAddressEntry {
            address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            prefix_len: None,
        }];
        let capsule = encode_address_request(&entries);
        let (t, v) = decode_capsule(&capsule).expect("decode request");
        assert_eq!(t, CAPSULE_ADDRESS_REQUEST);
        let parsed = decode_address_value(&v).expect("parse request value");
        assert_eq!(parsed, entries);
    }
}
