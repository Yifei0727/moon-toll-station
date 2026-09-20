//! Extensions for the HTTP/3 protocol.

use bytes::Bytes;
use std::str::FromStr;

/// Describes the `:protocol` pseudo-header for extended connect
///
/// See: <https://www.rfc-editor.org/rfc/rfc8441#section-4>
#[derive(PartialEq, Debug, Clone)]
pub struct Protocol(ProtocolInner);

impl Protocol {
    /// WebTransport protocol
    pub const WEB_TRANSPORT: Protocol = Protocol(ProtocolInner::WebTransport);
    /// RFC 9298 protocol
    pub const CONNECT_UDP: Protocol = Protocol(ProtocolInner::ConnectUdp);

    /// Return a &str representation of the `:protocol` pseudo-header value
    #[inline]
    pub fn as_str(&self) -> &str {
        match self.0 {
            ProtocolInner::WebTransport => "webtransport",
            ProtocolInner::ConnectUdp => "connect-udp",
            // `Other` stores the exact wire bytes, so round-trip them back
            // verbatim. The value is guaranteed UTF-8 (h3 rejects non-UTF-8
            // `:protocol` before `from_str` runs), but guard anyway.
            ProtocolInner::Other(ref b) => std::str::from_utf8(b).unwrap_or(""),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
enum ProtocolInner {
    WebTransport,
    ConnectUdp,
    /// Any extended-CONNECT `:protocol` other than `webtransport` /
    /// `connect-udp` (e.g. `connect-ip`, `websocket`). h3 0.0.8 upstream only
    /// recognised the two built-ins and rejected everything else with
    /// `H3_MESSAGE_ERROR`; this variant lets MASQUE servers accept arbitrary
    /// protocols (RFC 9220 WebSocket, RFC 9484 CONNECT-IP, ...).
    Other(Bytes),
}

/// Error when parsing the protocol
#[derive(Debug)]
pub struct InvalidProtocol;

impl FromStr for Protocol {
    type Err = InvalidProtocol;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "webtransport" => Ok(Self(ProtocolInner::WebTransport)),
            "connect-udp" => Ok(Self(ProtocolInner::ConnectUdp)),
            // Accept any other non-empty, UTF-8 `:protocol` value as an opaque
            // protocol. h3 has already verified UTF-8 validity upstream, so this
            // is always safe; we still reject an empty string defensively.
            other if !other.is_empty() => Ok(Self(ProtocolInner::Other(Bytes::copy_from_slice(
                other.as_bytes(),
            )))),
            _ => Err(InvalidProtocol),
        }
    }
}
