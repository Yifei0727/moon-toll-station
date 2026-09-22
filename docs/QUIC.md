# QUIC / HTTP/3 support

`auto-server` can carry QUIC traffic in two independent ways, and additionally act as an
IP-tunnelling VPN gateway:

1. **SOCKS5 `UDP ASSOCIATE`** (existing) — relay arbitrary UDP datagrams, which is how a
   QUIC client tunnels its packets today.
2. **HTTP/3 MASQUE (`CONNECT-UDP`, RFC 9298)** (new) — terminate QUIC/HTTP/3 and relay the
   client's UDP payloads over HTTP/3 DATAGRAMs (RFC 9297). This lets an **HTTP proxy**
   client (e.g. Chrome configured as an HTTP/HTTPS proxy) also reach QUIC origins.
3. **HTTP/3 MASQUE (`CONNECT-IP`, RFC 9484)** (new) — on the same listener, act as a layer-3
   VPN gateway: assign the client an IP, carry IP packets as HTTP/3 DATAGRAMs (`Context ID 0` +
   the raw packet, RFC 9484 §4.2), signal addresses/routes as RFC 9297 capsules **on the request
   stream**, and NAT the client's traffic for egress (see §3). Requires root.
4. **Plain TCP `CONNECT` over HTTP/3 (RFC 9114 §4.4)** — a *non-extended* `CONNECT` (no
   `:protocol` token) that tunnels **arbitrary TCP** byte streams over a single HTTP/3 request
   stream. Unlike `CONNECT-UDP`/`CONNECT-IP` it uses no capsules and no DATAGRAMs — the request
   body is the raw tunneled bytes, exactly like a classic HTTP/1.1 `CONNECT` (see §4).

---

# 1. SOCKS5 UDP ASSOCIATE (existing)

`auto-server` relays QUIC (and therefore HTTP/3) traffic transparently through its
**SOCKS5 `UDP ASSOCIATE`** path. A QUIC client (e.g. Chrome with HTTP/3 enabled) tunnels
its UDP datagrams to the proxy, which forwards them verbatim to the origin and relays the
responses back. The proxy never terminates QUIC and never inspects the payload — the QUIC
connection is end-to-end between the client and the origin server.

## Why SOCKS5 UDP ASSOCIATE (and not HTTP CONNECT)

QUIC runs over UDP. The proxy's HTTP `CONNECT` and SOCKS4/5 `CONNECT` paths are TCP tunnels
(`TcpStream`), so they physically cannot carry QUIC. The only way to proxy QUIC is to relay UDP,
which is exactly what SOCKS5 `UDP ASSOCIATE` does.

> **Important:** the client must be configured to use `auto-server` as a **SOCKS5** proxy.
> If a client uses it as an HTTP/HTTPS proxy (`CONNECT`), QUIC cannot be tunneled and the
> client silently falls back to HTTP/2. `curl --socks5` works for TCP only and cannot drive
> QUIC either — use a real QUIC-capable client (Chrome/Firefox) configured for SOCKS5.

## Client configuration

Point the client at the proxy as a SOCKS5 proxy, e.g.:

```
# Chrome
chromium --proxy-server="socks5://127.0.0.1:1080" --user-data-dir=/tmp/quic-test

# Firefox
# network.proxy.socks = 127.0.0.1, network.proxy.socks_port = 1080,
# network.proxy.socks_remote_dns = true, network.proxy.type = 1
```

Then open any HTTP/3-capable site (e.g. `https://www.cloudflare.com`, `https://quic.tech`).

## What the relay guarantees for QUIC

The `UDP ASSOCIATE` implementation is hardened specifically for QUIC's behavior:

- **Connection migration (RFC 9000 §9):** client vs upstream is distinguished by the *content*
  of each datagram (a SOCKS5 UDP request vs a raw QUIC packet), not by source address. So when a
  QUIC client migrates its source address (e.g. switching WiFi/cellular), its packets are still
  recognized as client traffic and routed correctly instead of being misrouted as upstream responses.
- **No per-packet jitter:** the target is resolved (DNS + RFC 6890 special-address check) once per
  destination and cached. A UDP relay must not add RTT-scale latency/jitter to each packet, which QUIC's
  loss recovery is sensitive to.
- **Datagram boundaries preserved:** each UDP datagram is forwarded 1:1 (`recv_from` / `send_to`),
  never coalesced or split — required because one QUIC packet == one UDP datagram.
- **Resilient forwarding:** a single failed `send_to` is logged and skipped, not fatal — one dropped
  datagram does not tear down the QUIC session.

## Verifying with a third-party client (Chrome)

1. Start the proxy:
   ```
   auto-server --listen 127.0.0.1:1080
   ```
2. Launch Chrome over SOCKS5 (see above) and open an HTTP/3 site.
3. Confirm a QUIC session is active: `chrome://net-internals/#quic` → you should see an active
   QUIC session for the origin.
4. Confirm the proxy is carrying the QUIC datagrams (no code change needed; just observe on loopback):
   ```
   sudo tcpdump -i lo udp port 1080 -X
   ```
   You should see UDP packets whose first byte is `0xC0` (QUIC Initial long header) or `0x40`
   (QUIC short header) — these are the relayed QUIC packets.
5. Control test: stop the proxy → Chrome's QUIC to that origin fails (proves the path goes through
   the proxy); restart it → recovers.

---

# 2. HTTP/3 MASQUE (CONNECT-UDP, RFC 9298) — new in this build

`auto-server --enable h3` starts a **second, concurrent** listener that speaks QUIC/HTTP/3 and
implements MASQUE `CONNECT-UDP`. By default it runs *alongside* the existing TCP SOCKS/HTTP proxy
— that proxy is unaffected and keeps serving on `--listen`. Pass `--disable http` to run MASQUE
**only** (see below).

MASQUE lets an HTTP/HTTPS-proxy client tunnel UDP (and therefore QUIC) through the proxy without
needing SOCKS5. The client opens an HTTP/3 connection, sends `CONNECT-UDP` with `:protocol:
connect-udp` and a `Capsule-Protocol: ?1` header, and then exchanges UDP payloads as HTTP/3
DATAGRAMs (RFC 9297) whose payload is `Context ID 0` — a single `0x00` byte — followed by the
**raw** UDP payload (RFC 9297 §4 / RFC 9298 §4.2). No capsule TLV, no Length: datagrams carry
`Context ID (varint)` + data only, and datagrams with any other Context ID are dropped silently.

## Request form (RFC 9298 §3.4)

The UDP target is carried in the **`:path`**, not in `:authority`. Per RFC 9298 §3.4, `:authority`
is the **proxy's own authority** and `:path` is the expansion of the URI template. The normative
example (RFC 9298 Figure 5) is:

```
:method = CONNECT
:protocol = connect-udp
:scheme = https
:path = /.well-known/masque/udp/192.0.2.6/443/
:authority = example.org
capsule-protocol = ?1
```

We implement the **default** (IANA-registered) template from RFC 9298 §2 only:

```
https://$PROXY_HOST:$PROXY_PORT/.well-known/masque/udp/{target_host}/{target_port}/
```

Notes:

- **Clients configure no path.** The `/.well-known/masque/udp/...` prefix is hardcoded per the
  RFC's default template; it is not configurable, and a client never has to be told it.
- `{target_host}` is percent-decoded (RFC 9298 §3.1), so an IPv6 literal may arrive as
  `2001%3Adb8%3A%3A1`. Raw unencoded colons (`2001:db8::1`) are also accepted, because that is
  what Chromium actually puts on the wire.
- `{target_port}` must be present and numeric; there is no default port (RFC 9298 forbids an
  omitted one). A missing, empty or non-numeric port is rejected with `400`.
- `:authority` is **not** the target and is not used to derive it. It identifies the proxy, but
  this server has no config for its own public authority, so it performs no authority matching —
  it simply never treats `:authority` as the tunnel destination.
- The obsolete `draft-schinazi-masque-connect-udp-00` encoding (target in `:authority`) is **not**
  accepted, as a fallback or otherwise. No known client sends it.

## Why HTTP/3 (and not HTTP/2) MASQUE

RFC 9298 requires HTTP DATAGRAM frames (RFC 9297) to carry UDP payloads. The mature Rust HTTP/2
library (`h2`) does **not** implement DATAGRAM frames, so **MASQUE over HTTP/2 is not viable** with
current Rust crates. HTTP/3 (`h3` + `quinn`) has native datagram support, which is what this mode
uses. (Earlier docs described HTTP/2 MASQUE as impossible and HTTP/3 MASQUE as a "future option" —
that future option is now implemented.)

## Flags

```
auto-server --enable h3 --key xxx.pem --cert-chain xxxfull.chain.pem --h3-bind 0.0.0.0:443 --auth-token <TOKEN>
```

| Flag | Meaning |
| --- | --- |
| `--enable h3` | Enable the HTTP/3 MASQUE mode (the only accepted value today). |
| `--key <PATH>` | PEM private key for the QUIC/HTTP/3 listener. **Required** when `--enable h3`. |
| `--cert-chain <PATH>` | PEM certificate chain (fullchain) for the QUIC/HTTP/3 listener. **Required** when `--enable h3`. |
| `--auth-token <TOKEN>` | Shared secret. **Required** when `--enable h3`. See auth below. |
| `--h3-bind <ADDR:PORT>` | Full bind address (IP:port) for the QUIC listener. **Optional, default `0.0.0.0:443`.** Independent of `--listen`: the TCP proxy and the MASQUE endpoint each have their own bind address. |
| `--disable http` | Do not start the TCP listener on `--listen` at all, so **only** MASQUE runs. Optional. Requires `--enable h3`. |

`--listen` is purely the TCP proxy's bind address (SOCKS4/SOCKS5/HTTP CONNECT, default
`0.0.0.0:1080`); it has no influence on the MASQUE bind, which is `--h3-bind` alone.

`--key`, `--cert-chain`, and `--auth-token` are enforced by `clap` (`required_if_eq` on
`--enable h3`) and re-checked defensively in `run()`. Omitting any of them aborts with a clear
message before binding.

### `--disable http` (MASQUE-only)

The TCP listener on `--listen` serves SOCKS4, SOCKS5 **and** HTTP `CONNECT` together (it
auto-detects the protocol per connection), so `--disable http` disables **all three** — it is not
an HTTP-only toggle. With `--disable http`, `--listen` is never bound; the MASQUE listener binds
`--h3-bind` instead, which is fully independent of `--listen`.

```
auto-server --enable h3 --disable http --key key.pem --cert-chain cert.pem --auth-token <TOKEN> --h3-bind 0.0.0.0:8443
```

**Validation rule:** `--disable http` requires `--enable h3`. With no `--enable h3` there would
be nothing listening at all, so the process fails fast — before binding anything and before the
auto-upgrade loop starts — with:

```
Error: --disable http requires --enable h3: nothing would be listening
```

Auth (`--auth-token`), tunneling and datagram behavior are identical whether or not the TCP
listener is disabled.

## Authentication (required)

UDP/443 is a publicly reachable, open-proxy-grade port, so MASQUE is **always authenticated**.
Every `CONNECT-UDP` request must carry a valid `Proxy-Authorization` header, else the server
responds `407 Proxy Authentication Required`. Two schemes are accepted:

- `Proxy-Authorization: Bearer <TOKEN>` — recommended.
- `Proxy-Authorization: Basic <base64>` — for clients that only speak Basic. The server decodes the
  credential as `user:password` (RFC 7617) and accepts when **`password == <TOKEN>`**. (A few clients
  send just the token as the whole Basic credential; that is also accepted when it equals `<TOKEN>`.)

## Tunneling model

- A `CONNECT-UDP` request names exactly **one** target in its `:path`, as
  `/.well-known/masque/udp/{host}/{port}/` (host **and explicit port** — RFC 9298 forbids an
  omitted port). The server resolves it once (via the shared DNS resolver), applies the same
  `--acl-no-rfc6890`/`--no-loopback` blocking as the TCP proxy
  (`is_rfc6890_special`), and opens a single UDP socket to it.
- The tunnel is **1:1**: unlike SOCKS5 `UDP ASSOCIATE` there is no per-packet destination header.
  Every datagram on that stream is relayed to/from that one socket. (The SOCKS5 content-based
  client-migration logic does **not** apply here — it is specific to `UDP ASSOCIATE`.)
- The control (HTTP/3 request) stream is kept open for the tunnel's lifetime; it is only finished
  when the tunnel closes.
- A single QUIC connection may carry **multiple concurrent `CONNECT-UDP` streams** (Chrome
  multiplexes); each gets its own tunnel task and its own datagram sender, demultiplexed by QUIC
  stream id by a connection-wide datagram reader.

## Client configuration

Configure the browser/system as an **HTTP/HTTPS proxy** pointing at `https://<host>:<h3-bind-port>/`
with the proxy auth credential above, and ensure HTTP/3 (QUIC) is enabled. Chrome, for example,
tunnels QUIC to origins through an HTTP proxy via MASQUE `CONNECT-UDP` when so configured.

**Do not configure a path.** The `/.well-known/masque/udp/{host}/{port}/` prefix is the RFC 9298
default URI template, hardcoded on both sides — a proxy-config path (if your client even has such
a field) is not used for `CONNECT-UDP` and setting one will not change the target.

For interop testing, prefer the reference client from
[masque-go](https://github.com/quic-go/masque-go) (see Limitations — Chrome is not usable against
this server's mandatory auth).

## MTU / `TooLarge` limitation

QUIC datagrams are MTU-bounded (initially ~1200 bytes, growing with path MTU discovery). A UDP
packet larger than the current datagram MTU cannot be sent as a single HTTP/3 DATAGRAM. The server
pre-checks each outgoing datagram against `quinn`'s live `max_datagram_size()` and **drops** packets
that would not fit, logging at debug level and relying on the client's own retransmission (per RFC
9298). It never panics or tears down the tunnel for an oversized packet. Note that the
`h3-datagram` 0.0.2 `SendDatagramError` variants are private, so the server pre-checks the MTU
rather than matching the `TooLarge` error at runtime.

## Verifying

```
# 1. Generate a throwaway self-signed cert (NOT in the repo):
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj "/CN=localhost"

# 2. Start with MASQUE enabled (use a high UDP port to avoid needing root for 443):
auto-server --enable h3 --key key.pem --cert-chain cert.pem --auth-token s3cr3t --h3-bind 127.0.0.1:8443 --listen 127.0.0.1:1080
#    -> expect both log lines (the two binds are independent):
#       proxy server started listen=127.0.0.1:1080 ...
#       masque (HTTP/3 CONNECT-UDP) server started listen=127.0.0.1:8443

# 3. Missing auth-token is rejected before binding:
auto-server --enable h3 --key key.pem --cert-chain cert.pem --h3-bind 127.0.0.1:8443
#    -> error: the following required arguments were not provided: --auth-token <AUTH_TOKEN>

# 4. MASQUE-only: no TCP listener at all (1080 is never bound)
auto-server --enable h3 --disable http --key key.pem --cert-chain cert.pem --auth-token s3cr3t --h3-bind 127.0.0.1:8443
#    -> only: "masque (HTTP/3 CONNECT-UDP) server started listen=127.0.0.1:8443"
#       (no "proxy server started" line; nothing listening on 1080)

# 5. --disable http without --enable h3 is rejected before binding:
auto-server --disable http
#    -> error: --disable http requires --enable h3: nothing would be listening
```

### Automated end-to-end test

`src/masque.rs` also contains `e2e_connect_udp_roundtrip` — a real handshake that drives the
actual `MasqueServer` with a `quinn` + `h3` client over a freshly generated self-signed
certificate, sends `CONNECT-UDP` (in the RFC 9298 `:path` form above), asserts `200`, and
round-trips a UDP payload through a local echo socket via HTTP/3 DATAGRAMs (`0x00` + raw payload
both directions). It is
`#[ignore]`d (and a no-op if `openssl` is absent) so it does not run in the default `cargo test`:

```
cargo test -- --ignored e2e_connect_udp_roundtrip
```

The test proves two things a bind-only smoke test cannot: (a) the server advertises HTTP/3
DATAGRAM + extended-CONNECT settings (otherwise the client handshake fails), and (b) datagrams
flow both ways through the tunnel. Note it generates the self-signed cert with
`basicConstraints=CA:FALSE` + `extendedKeyUsage=serverAuth` so the client's real webpki verifier
accepts it as an end-entity.

## Limitations

- **Chrome cannot actually be used against this server today**, for two independent reasons:
  - **Chrome's MASQUE client does not send `Proxy-Authorization`.** This is a known Chromium gap
    tracked as `TODO(crbug.com/326437102)`; since our auth is mandatory, Chrome's `CONNECT-UDP`
    requests always get `407 Proxy Authentication Required`. (There is no flag to work around it
    from our side short of disabling auth, which we deliberately do not support on a public port.)
  - **`quic://` proxy support is debug-build only in Chromium.** `enable_quic_proxy_support` is
    gated on `is_debug`, so a shipping Chrome will not use a `quic://` proxy at all. Shipping
    Chrome uses **connect-ip (RFC 9484)** instead — see §3 for this server's CONNECT-IP support
    and its current caveats.
  Recommendation: test interop with [masque-go](https://github.com/quic-go/masque-go), which
  implements RFC 9298 with configurable proxy auth.
- **Only the default path template is implemented.** A client that negotiates a different
  `CONNECT-UDP` URI template — e.g. one advertised via a query-string template variant — will have
  its requests rejected with `400`. This matches every client we know of.
- **SOCKS5 still required for non-MASQUE QUIC:** the MASQUE listener only handles HTTP/3
  `CONNECT-UDP`. Clients that cannot do HTTP/3 MASQUE (or want to tunnel non-UDP traffic) continue
  to use the SOCKS5/HTTP `CONNECT` proxy.
- **HTTP/2 MASQUE is not implemented** (and not feasible with current Rust crates, as noted above).
- **Pre-release crates:** this mode depends on `h3` 0.0.8, `h3-quinn` 0.0.10, and `h3-datagram`
  0.0.2 — all **0.0.x pre-release** crates whose APIs are unstable. Pin and test before relying on
  them in production. The core QUIC layer (`quinn` 0.11) and TLS (`rustls` 0.23) are stable.
- **Crypto provider:** exactly one rustls crypto provider must be installed process-wide. `reqwest`
  (already a dependency, `rustls-tls-native-roots`) pulls the **`ring`** provider, so `quinn` is
  built with the `rustls-ring` feature and `main()` installs `ring` as the default provider once.
  Mixing in `aws-lc-rs` would violate rustls 0.23's single-provider rule.
- **No client-cert verification:** the server uses `with_no_client_auth` (MASQUE clients are
  authenticated by the `Proxy-Authorization` shared secret, not by TLS client certs).

---

# 3. HTTP/3 MASQUE (CONNECT-IP, RFC 9484) — VPN gateway

> **Platform support:** `CONNECT-IP` (the `tun` device, NAT, and route setup) is
> **Linux-only** (`cfg(target_os = "linux")`). It uses the Linux `TUNSETIFF`
> ioctl, `/proc/sys/net/ipv4/ip_forward`, and `iptables`. On Windows and macOS
> builds the module is compiled out; a `connect-ip` request is answered with
> `501 Not Implemented` and a "CONNECT-IP requires Linux" log line, while
> `CONNECT-UDP`, plain TCP `CONNECT`, and WebSocket-over-HTTP/3 are served as
> usual.

When `--enable h3` is on, the **same** QUIC/HTTP/3 listener also serves `CONNECT-IP` (RFC 9484),
the IP-tunneling sibling of `CONNECT-UDP`. Whereas `CONNECT-UDP` tunnels a single UDP flow,
`CONNECT-IP` turns the proxy into a **real layer-3 VPN gateway**: the client gets a routable IP
address, its traffic is carried as IP packets inside HTTP/3 DATAGRAMs (`Context ID 0` + the raw
IP packet, RFC 9484 §4.2 — no capsule TLV), the proxy
performs NAT for egress, and the client can reach the entire Internet (or any advertised prefix)
through the tunnel.

`CONNECT-UDP` and `CONNECT-IP` share one listener and one h3 connection driver; they are
dispatched by **request path** (the RFC 9484 default URI template
`/.well-known/masque/ip/` is disjoint from `CONNECT-UDP`'s `/.well-known/masque/udp/...`). See
"Known limitations" below for why path dispatch (not the `:protocol` token) is the discriminator
on the pinned crate.

## Request form (RFC 9484 §4)

Unlike `CONNECT-UDP`, the `connect-ip` URI template has **no path variables** — the client just
connects to the well-known prefix:

```
:method = CONNECT
:protocol = connect-ip
:scheme = https
:path = /.well-known/masque/ip/
:authority = <proxy authority>
capsule-protocol = ?1
```

After a `200` + `Capsule-Protocol: ?1` response there are two distinct planes:

**Datagram plane (data):** IP packets travel in HTTP/3 DATAGRAMs whose payload is `Context ID 0`
(a single `0x00` byte) followed by the **raw IP packet** — exactly like CONNECT-UDP, no capsule
TLV, no Length (RFC 9297 §4 / RFC 9484 §4.2). Datagrams with a non-zero Context ID are dropped
silently without tearing the tunnel down.

**Request stream (signalling):** RFC 9297 capsules (TLV framing: `Type` varint + `Length` varint
+ `Value`) travel **on the CONNECT request stream** via `send_data`/`recv_data` — never in
datagrams (RFC 9484 §4.7):

| Capsule type | Value | Direction | Purpose |
| --- | --- | --- | --- |
| `ADDRESS_ASSIGN` (0x01) | assigned address(es)/prefix(es) | proxy → client | the client's assigned address (sent unprompted after the 2xx, and in reply to `ADDRESS_REQUEST`) |
| `ADDRESS_REQUEST` (0x02) | requested address(es) | client → proxy | client asks for an address (we always assign from the pool, echoing the Request ID) |
| `ROUTE_ADVERTISEMENT` (0x03) | address range(s) | proxy → client | ranges we are willing to route (default route: `0.0.0.0–255.255.255.255`, all protocols) |

The capsule payloads use the **fixed RFC 9484 layouts** (§4.7 Figures 8/10/12) — not nested TLVs:

- `Assigned Address` / `Requested Address`:
  `Request ID (varint), IP Version (8 bits), IP Address (32/128 bits), IP Prefix Length (8 bits)`
  — e.g. `01 07 00 04 c6 12 00 02 20` is an `ADDRESS_ASSIGN` for `198.18.0.2/32` with Request
  ID 0.
- `IP Address Range`:
  `IP Version (8 bits), Start IP Address (32/128), End IP Address (32/128), IP Protocol (8 bits)`
  — `0` means all protocols (ICMP is always allowed); e.g. `03 0a 04 00 00 00 00 ff ff ff ff 00`
  is the IPv4 default route.

> **Note:** an earlier implementation of this server used a home-grown wire format here (an
> invented `IP` capsule 0x02 with TLV-framed addresses, renumbered capsule types, and signalling
> capsules sent as datagrams). That was **not** RFC 9484-conformant; it has been fixed, so
> third-party RFC-conforming clients (e.g. [masque-go](https://github.com/quic-go/masque-go)) are
> now expected to interoperate. All encode/decode lives in `src/capsule.rs` and is unit-tested
> against hand-derived RFC byte sequences without root or a device.

## Address pool (`--ip-pool`)

Each client gets its own routable block from a configured CIDR:

- **IPv4:** one `/30` per client (proxy = block base+1, client = base+2; the other two addresses
  are network/broadcast). Default pool `198.18.0.0/15` yields ~131,072 concurrent clients.
- **IPv6:** one `/64` per client (proxy = base+1, client = base+2). A pool with prefix larger than
  `/64` is rejected at startup (we cannot subdivide below a `/64` per client).

The pool is a single `Arc<Mutex<…>>` shared across all QUIC connections/sessions so allocations
never collide. Exhaustion returns `503 Service Unavailable`. Allocation is validated eagerly at
startup so a malformed `--ip-pool` fails fast.

```
--ip-pool <CIDR>     Connect-IP client address pool. Default: 198.18.0.0/15.
                     Use 100.64.0.0/10 for CGNAT-style ranges.
```

## Tunnel device, routing and NAT (requires root)

For each accepted `CONNECT-IP` request the proxy creates a real **`tun`** (layer-3, `IFF_TUN |
IFF_NO_PI`) device via raw `TUNSETIFF` ioctl and runs it asynchronously with
`tokio::io::unix::AsyncFd`. It then:

1. **Assigns addresses** on the tun device as a point-to-point link: `ip addr add <proxy>/<prefix>
   peer <client>`, bringing the interface `up` and setting the MTU (sized to fit inside a QUIC
   DATAGRAM so we rarely have to drop oversized IP packets).
2. **Routes the client's prefix** to the tun device (`ip route add <client>/<prefix> dev <tun>`),
   so the kernel delivers the client's traffic to our device.
3. **Enables IP forwarding** (`net.ipv4.ip_forward` / `net.ipv6.conf.all.forwarding`) — refcounted
   across sessions so it is only restored to its original value when the last tunnel closes.
4. **Masks the client's traffic for egress** with `iptables -t nat -A POSTROUTING -s <client>/<prefix>
   -j MASQUERADE` (and a companion `FORWARD` accept rule for the client prefix). This is what makes
   the tunnel a usable VPN rather than a dead-end link.

All of the above require `CAP_NET_ADMIN` (**root**). The `ip` and `iptables` binaries must be on
`PATH`. If device creation fails (e.g. not root, or the tools are missing), the request is torn
down with `500 Internal Server Error` and the failure is logged — it does **not** crash the server
or other tunnels.

### Cleanup guarantees

`TunDevice` owns every side effect it creates behind a `Drop` impl: on tunnel close (control stream
finished, connection dropped, or the task panicking) it deletes the tun interface, removes its
`iptables`/`ip route` rules, and releases its hold on the forwarded-flag refcount. Interface names
use the kernel's `auto%d` auto-naming template so concurrent tunnels never collide.

### Data plane

After setup, `handle_ip_stream` loops:

- **Uplink (client → Internet):** each incoming HTTP/3 DATAGRAM's Context ID varint is parsed; a
  non-zero Context ID is dropped silently (RFC 9484 §4.2), Context ID 0 is followed by the raw IP
  packet, which is written to the tun device; the kernel routes/NATs it to the real egress
  interface.
- **Downlink (Internet → client):** every packet read from the tun device is sent as an HTTP/3
  DATAGRAM consisting of `0x00` (Context ID 0) + the raw packet (pre-checked against
  `max_datagram_size()`; oversized packets are dropped, never fatal).
- **Signalling** (`ADDRESS_REQUEST` from the client, and the unprompted `ADDRESS_ASSIGN` +
  `ROUTE_ADVERTISEMENT` the proxy sends) travels as RFC 9297 capsules **on the request stream**,
  never in datagrams. A client `ADDRESS_REQUEST` is answered with a matching-Request-ID
  `ADDRESS_ASSIGN`; stream EOF is the tunnel teardown signal.

## Authentication (required)

`CONNECT-IP` uses the **same mandatory `Proxy-Authorization`** as `CONNECT-UDP` (`--auth-token` is
required whenever `--enable h3` is set). A missing/wrong token yields `407 Proxy Authentication
Required`. The request is also rejected without `Capsule-Protocol: ?1`, with a non-`CONNECT`
method, on a non-`/masque/ip` path, or if a `CONNECT-UDP` request lands on the IP path (`501`).

## Flags

```
auto-server --enable h3 --key key.pem --cert-chain cert.pem --auth-token <TOKEN> \
            --ip-pool 198.18.0.0/15 --h3-bind 0.0.0.0:8443
```

`--enable h3`, `--key`, `--cert-chain`, `--auth-token` behave exactly as in §2. `--ip-pool` is the
only new flag; it is optional and defaults to `198.18.0.0/15`.

## Verification

```
# 1. Generate a self-signed cert (NOT in the repo):
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj "/CN=localhost"

# 2. Start (must be root for tun/NAT; use a high UDP port to avoid needing root for 443):
sudo auto-server --enable h3 --key key.pem --cert-chain cert.pem --auth-token s3cr3t \
                 --ip-pool 198.18.0.0/15 --h3-bind 0.0.0.0:8443

# 3. After a client connects you should see:
#       CONNECT-IP tunnel established tun=tun0 proxy=198.18.0.0 client=198.18.0.2 prefix=30
#    and `ip addr show tun0` / `ip route show 198.18.0.2/30` should reflect the assignment.

# 4. Tear the client down -> tun0 disappears, iptables POSTROUTING/MASQUERADE rule removed,
#    ip_forward restored to its prior value.
```

### Unit tests (no root, run in CI)

`cargo test` covers the pure protocol logic without any device or privileges:

- `capsule` module: QUIC varint round-trips (1/2/4/8-byte forms + boundaries), capsule
  encode/decode round-trips (including a 20 000-byte value forcing a 4-byte `Length`),
  Context-ID parsing (`0x00` accepted and stripped; single-byte and multi-byte varint non-zero
  Context IDs, e.g. `0x40 0x2A`, dropped), and `ADDRESS_ASSIGN`/`ADDRESS_REQUEST`/
  `ROUTE_ADVERTISEMENT` codec tests that assert the exact RFC 9484 §4.7 byte sequences (e.g. an
  `ADDRESS_ASSIGN` for `198.18.0.2/32` = `01 07 00 04 c6 12 00 02 20`) plus rejection of
  malformed/truncated input (wrong IP version, truncated addresses, Start > End, out-of-range
  prefix lengths).
- `tun` module: pool allocation (distinct `/30` blocks), exhaustion, bad-CIDR rejection, and a
  `cstr`-to-`String` helper. The real device/routing/NAT test (`tun_integration`) is `#[ignore]`d
  and additionally skips unless `uid == 0` and `ip`/`iptables` exist.
- `masque` module: `connect-ip` path detection, `validate_connect_ip` accept/reject matrix
  (method, path, capsule-protocol, auth, and a `CONNECT-UDP` request on the IP path), and the
  `CONNECT-UDP` request-validation tests.

### Integration / end-to-end test (root, `#[ignore]`)

`tun_integration` (real tun + NAT) and `e2e_connect_ip_roundtrip` (live QUIC handshake asserting
`200`, parsing `ADDRESS_ASSIGN`/`ROUTE_ADVERTISEMENT` capsules **from the stream body**, and
pinging the proxy's tun address through the tunnel with `Context ID 0` + raw-packet datagrams,
including a non-zero-Context-ID silent-drop control) are both `#[ignore]`d and gated on root +
tool availability. They are **not** executed in the sandbox/CI environment (no root) and must be
run explicitly:

```
cargo test -- --ignored tun_integration
cargo test -- --ignored e2e_connect_ip_roundtrip
```

## Known limitations

- **`h3` 0.0.8 could not parse `connect-ip` / `websocket` `:protocol` tokens — now patched
  locally.** Upstream `h3`'s `Protocol::from_str` only accepts `connect-udp` / `webtransport`; any
  other value was rejected while parsing `:protocol`, so the server answered with `H3_MESSAGE_ERROR`
  before our code ran. A **patched local copy** of `h3` 0.0.8 lives at `vendor/h3-patched/` and is
  wired in via `[patch.crates-io]` in `Cargo.toml`. Its `Protocol` adds an opaque `Other(Bytes)`
  variant that accepts **any** non-empty UTF-8 `:protocol` (so `connect-ip` and `websocket` both
  parse and surface as `Protocol::Other`, round-tripped verbatim by `as_str()`). With that patch,
  live `connect-ip` clients are no longer blocked (see §3 and §5). **Caveat:** a `vendor/` path
  patch is not shippable (a fresh clone lacks the dir and `--locked` CI fails); for release the
  patched `h3` must be hosted on a fork repo and switched to `git = "..."` (see repo notes). The
  `connect-ip` protocol logic, capsule code, tun/NAT, and validation are all implemented and
  unit-tested; only the live end-to-end handshake is gated on root (`CAP_NET_ADMIN`).
- **Chrome cannot be used as a client** for the same two reasons as `CONNECT-UDP` (no
  `Proxy-Authorization` from Chrome's MASQUE client; `quic://` proxy support is debug-build only).
  Use a `connect-ip`-capable reference client (e.g. [masque-go](https://github.com/quic-go/masque-go))
  for interop. Third-party RFC 9484/9298-conforming clients are expected to interoperate since the
  wire-format fix (see the note in "Request form" above): datagrams are now `Context ID 0` + raw
  payloads and signalling capsules travel on the request stream.
- **IPv4-only egress NAT by default.** The MASQUERADE/forwarding rules are installed per allocated
  prefix; a dual-stack client is served on whichever family its assigned address is, but the
  default route advertisement is per-family based on the assigned address.
- **Pre-release crates:** same `h3` 0.0.8 / `h3-quinn` 0.0.10 / `h3-datagram` 0.0.2 caveat as §2.
- **musl cross-compile:** the tun device is created through **raw `libc` ioctls**
  (`TUNSETIFF`/`IFF_TUN`/`IFF_NO_PI`), which are architecture-independent and musl-safe. The
  `ip`/`iptables` shell-outs are dynamically resolved at runtime and do **not** require the
  target rootfs to contain them at build time, but at **runtime** on a musl target the `ip` and
  `iptables` binaries must be present on `PATH` or the tunnel setup will return `500`. Plan for
  that in minimal container/static images.

---

# 4. Plain TCP `CONNECT` over HTTP/3 (RFC 9114 §4.4)

When `--enable h3` is on, the **same** QUIC/HTTP/3 listener also serves a **plain** `CONNECT`
request — one with **no `:protocol` pseudo-header** at all. This is the HTTP/3 analogue of the
classic HTTP/1.1 `CONNECT` TCP tunnel (RFC 9114 §4.4 / the extended-`CONNECT` mechanism from
RFC 8441 used *without* a protocol). It gives an HTTP/3 client exactly what an HTTP/HTTPS proxy
`CONNECT` gives an HTTP/1.1 client: a raw, bidirectional **TCP** byte pipe to `host:port`.

Unlike `CONNECT-UDP` and `CONNECT-IP`, there are **no capsules, no DATAGRAMs, and no `:path`
template**. The HTTP/3 request stream body *is* the tunneled TCP byte stream, and the response
body is the bytes coming back from the target.

## Request form (RFC 9114 §4.4)

```
:method = CONNECT
:scheme = https
:authority = <target-host>:<target-port>
:path = /
```

Notes:

- **No `:protocol`.** This is the discriminator: `CONNECT-UDP` carries `:protocol = connect-udp`,
  `CONNECT-IP` lands on `/.well-known/masque/ip/`, and a plain `CONNECT` carries **neither** — just
  `:method = CONNECT` + a target in `:authority`. Any other `:protocol` value (e.g. `webtransport`,
  `websocket`) is rejected with `501 Not Implemented`.
- **The target is the `:authority`,** formatted `host:port`, exactly like an HTTP/1.1 `CONNECT`.
  `:path` is always `/` (or anything the client sends — it is ignored). Unlike `CONNECT-UDP`, the
  `:authority` here **is** the tunnel destination (RFC 9114, not RFC 9298).
- **An explicit port is mandatory.** RFC 9114 requires the target port to be present; a `:authority`
  with no `:port` (or a non-numeric port) is rejected with `400 Bad Request`. This reuses the same
  `parse_authority` logic as the HTTP/1.1 `CONNECT` path in `src/server.rs`.
- **Host forms:** IPv4 (`203.0.113.7:443`), bracketed IPv6 (`[2001:db8::1]:443`), and hostnames
  (`example.com:443`) are all accepted. A bare (un-bracketed) IPv6 literal cannot appear on the wire
  because it is not a valid URI authority; the underlying `parse_authority` parser does accept the
  `host:port` string form should it ever be constructed directly.

## Dispatch order

The accept loop dispatches every `CONNECT` on the MASQUE listener in this order:

1. non-`CONNECT` method → `405 Method Not Allowed`;
2. `:protocol == connect-udp` → `handle_stream` (UDP/DATAGRAM tunnel, §2);
3. `:protocol == connect-ip` **or** (`:protocol` absent **and** path on `/.well-known/masque/ip/`)
   → `handle_ip_stream` (§3); the path-only form is kept for legacy clients that send no `:protocol`;
4. `:protocol == websocket` (RFC 9220) → `handle_websocket_connect_stream`, which reuses the plain
   TCP tunnel (this section); the proxy does **not** interpret WebSocket — it is a byte pipe;
5. `:protocol` absent (plain `CONNECT`) → `handle_tcp_connect_stream` (this section);
6. any other `:protocol` present (e.g. `webtransport`) → `501 Not Implemented` (logged).

With the patched `h3` (§"Known limitations") both `connect-ip` and `websocket` now parse and reach
their own dispatch arms; plain TCP `CONNECT` is unaffected because it carries no `:protocol` and is
the *intended* step-5 case.

## Authentication (required)

Same mandatory `Proxy-Authorization` as §2/§3 (`--auth-token` is required whenever `--enable h3`
is set). Missing/wrong token → `407 Proxy Authentication Required`. Accepted schemes:
`Bearer <TOKEN>` and `Basic <base64>` with `password == <TOKEN>` (the same two accepted by
`check_proxy_auth`).

## Tunneling model

- `handle_tcp_connect_stream` resolves the `:authority` host via the shared DNS resolver, applies
  the same `is_rfc6890_special` block as the TCP proxy (special/RFC 6890 and loopback addresses are
  rejected with `403 Forbidden`), and opens a single `TcpStream` to it (`tokio::time::timeout` of
  10 s → `502 Bad Gateway` on failure).
- It responds `2xx` with an **empty body** and does **not** call `stream.finish()` — the request
  stream stays open for the tunnel's lifetime.
- The tunnel is a **pure byte pipe** driven by `req_stream.split()` (the underlying QUIC stream is
  bidirectional), so both directions are pumped concurrently on one task:
  - **client → target:** `RequestStream::recv_data()` → `TcpStream::write_all(...)`. An `Ok(None)`
    (client closed its send side) triggers `TcpStream::shutdown()`; any error breaks the loop.
  - **target → client:** `TcpStream::read(...)` → `RequestStream::send_data(Bytes::copy_from_slice(...))`.
    On EOF (`Ok(0)`) the loop ends and calls `RequestStream::finish()` to close the response.
  - `tokio::join!` runs both directions; whichever ends first triggers the counterpart's close, so
    the tunnel tears down cleanly when either side closes or errors.
- No capsule, datagram, or tun device is involved — it is the minimal h3 realization of an
  HTTP/1.1 `CONNECT` tunnel.

## Flags

No new flags. Plain TCP `CONNECT` is served automatically by the existing `--enable h3` listener and
shares `--auth-token`, `--key`, `--cert-chain`, and `--h3-bind` with `CONNECT-UDP`/`CONNECT-IP`.

```
auto-server --enable h3 --key key.pem --cert-chain cert.pem --auth-token <TOKEN> --h3-bind 0.0.0.0:8443
```

## Verification / automated end-to-end test

`src/masque.rs` contains `e2e_tcp_connect_roundtrip` — a real handshake that drives the actual
`MasqueServer` with a `quinn` + `h3` client over a freshly generated self-signed certificate, sends
a plain `CONNECT` (no `:protocol`, target in `:authority`) to a local TCP echo listener, and:

- asserts the response is `200 OK`;
- sends a payload over the request body and asserts the echoed bytes round-trip intact;
- **negative control:** a second request carrying a `:protocol` (here `webtransport`, which the
  dispatcher returns `501` for) is asserted to **not** return `200` — proving the dispatcher never
  routes a protocol-bearing request to the TCP tunnel.

It is `#[ignore]`d and a no-op if `openssl` is absent, so it does not run in the default `cargo test`:

```
cargo test -- --ignored e2e_tcp_connect_roundtrip
```

The same test file's `#[ignore]` `e2e_connect_udp_roundtrip` / `e2e_connect_ip_roundtrip` exercise
the sibling tunnels. `validate_tcp_connect` (accept/reject matrix: method, missing `:protocol`,
auth, missing port, bare/unknown `:protocol`) and an in-memory isolation pipe test
(`tcp_connect_pipe_logic_round_trips_and_eof_closes`) run in the default `cargo test` without any
network or certs.

## Limitations

- **Unimplemented `:protocol` values return `501`.** The dispatcher returns `501 Not Implemented`
  for any extended-`CONNECT` `:protocol` it does not tunnel (e.g. `webtransport`). `connect-ip` and
  `websocket` are handled (§3 / §5); everything else is rejected. See §5 for the RFC 9220 WebSocket
  path.
- **No concurrent multiplexing of multiple TCP tunnels per request.** Like HTTP/1.1 `CONNECT`, one
  request stream == one TCP tunnel. A client opens additional TCP tunnels on additional HTTP/3
  request streams on the same QUIC connection (all multiplexed by QUIC, as with `CONNECT-UDP`).
- **Pre-release crates:** same `h3` 0.0.8 / `h3-quinn` 0.0.10 caveat as §2/§3 (plus the local
  `vendor/h3-patched` patch noted in "Known limitations").

---

# 5. WebSocket over HTTP/3 (RFC 9220)

When `--enable h3` is on, the **same** QUIC/HTTP/3 listener also serves **RFC 9220 WebSocket over
HTTP/3**. Bootstrapping is an **extended `CONNECT`** with `:protocol = websocket`; after the proxy
returns `200`, the stream carries the WebSocket opening handshake and subsequent frames as the
**request/response body**. The proxy is a **byte pipe** to the origin (target = `:authority`,
`host:port`) — it does **not** interpret WebSocket at all, the same as a plain TCP `CONNECT` (§4).
Upgrade headers are simply forwarded through the tunnel unchanged.

## Request form (RFC 9220)

```
:method = CONNECT
:scheme = https
:authority = <target-host>:<target-port>
:protocol = websocket
```

Notes:

- **The `:protocol` is `websocket`.** This is what distinguishes it from a plain TCP `CONNECT` (§4,
  which carries no `:protocol`). The patched `h3` (see "Known limitations") parses `websocket` into
  a `Protocol::Other` extension instead of rejecting it with `H3_MESSAGE_ERROR`.
- **The target is the `:authority`** (`host:port`), exactly like a plain TCP `CONNECT`. `:path` is
  ignored.
- **Auth is identical** to the other MASQUE tunnels (`--auth-token` / `Proxy-Authorization`).
- **It reuses the TCP tunnel.** `handle_websocket_connect_stream` shares the exact bidirectional
  byte-pipe logic of `handle_tcp_connect_stream` (DNS resolve, `is_rfc6890_special` block, `2xx` +
  empty body, concurrent `split()` pump). Only the flow-log tag differs (`ws` vs `tcp`).

## Verification / automated end-to-end test

`src/masque.rs` contains `e2e_websocket_connect_roundtrip` — a real handshake that drives the actual
`MasqueServer` with a `quinn` + `h3` client over a freshly generated self-signed certificate and:

- sends `CONNECT` with `:protocol = websocket` to a local TCP echo, asserts `200 OK`, and round-trips
  a payload through the h3 stream (the end-to-end proof that the patched `h3` accepts arbitrary
  `:protocol` values);
- **positive control:** a plain TCP `CONNECT` (no `:protocol`) on the same connection also returns
  `200` and round-trips, proving the WebSocket path is just the TCP tunnel;
- **negative control:** an unknown `:protocol` (`webtransport`, which we do not implement) is asserted
  to **not** return `200`.

It is `#[ignore]`d and a no-op if `openssl` is absent, so it does not run in the default `cargo test`:

```
cargo test --lib -- --ignored e2e_websocket_connect_roundtrip
```

The patched `h3` is also covered by library unit tests (`h3_accepts_arbitrary_protocols_connect_ip_and_websocket`
and `connect_ip_protocol_extension_reaches_validation`) that run in the default `cargo test`.

