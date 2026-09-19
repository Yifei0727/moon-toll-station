# QUIC / HTTP/3 support

`auto-server` can carry QUIC traffic in two independent ways:

1. **SOCKS5 `UDP ASSOCIATE`** (existing) — relay arbitrary UDP datagrams, which is how a
   QUIC client tunnels its packets today.
2. **HTTP/3 MASQUE (`CONNECT-UDP`, RFC 9298)** (new) — terminate QUIC/HTTP/3 and relay the
   client's UDP payloads over HTTP/3 DATAGRAMs (RFC 9297). This lets an **HTTP proxy**
   client (e.g. Chrome configured as an HTTP/HTTPS proxy) also reach QUIC origins.

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
DATAGRAMs (RFC 9297) whose body is a `DATAGRAM` capsule (type `0x00` = UDP payload, RFC 9298 §4).

## Why HTTP/3 (and not HTTP/2) MASQUE

RFC 9298 requires HTTP DATAGRAM frames (RFC 9297) to carry UDP payloads. The mature Rust HTTP/2
library (`h2`) does **not** implement DATAGRAM frames, so **MASQUE over HTTP/2 is not viable** with
current Rust crates. HTTP/3 (`h3` + `quinn`) has native datagram support, which is what this mode
uses. (Earlier docs described HTTP/2 MASQUE as impossible and HTTP/3 MASQUE as a "future option" —
that future option is now implemented.)

## Flags

```
auto-server --enable h3 --key xxx.pem --cert-chain xxxfull.chain.pem --udp-port 443 --auth-token <TOKEN>
```

| Flag | Meaning |
| --- | --- |
| `--enable h3` | Enable the HTTP/3 MASQUE mode (the only accepted value today). |
| `--key <PATH>` | PEM private key for the QUIC/HTTP/3 listener. **Required** when `--enable h3`. |
| `--cert-chain <PATH>` | PEM certificate chain (fullchain) for the QUIC/HTTP/3 listener. **Required** when `--enable h3`. |
| `--auth-token <TOKEN>` | Shared secret. **Required** when `--enable h3`. See auth below. |
| `--udp-port <PORT>` | UDP port for the QUIC listener. **Optional, default `443`.** Bound to `--listen`'s IP (so `--listen 0.0.0.0` → `0.0.0.0:443`), no separate bind-address flag is needed. |
| `--disable http` | Do not start the TCP listener on `--listen` at all, so **only** MASQUE runs. Optional. Requires `--enable h3`. |

`--key`, `--cert-chain`, and `--auth-token` are enforced by `clap` (`required_if_eq` on
`--enable h3`) and re-checked defensively in `run()`. Omitting any of them aborts with a clear
message before binding.

### `--disable http` (MASQUE-only)

The TCP listener on `--listen` serves SOCKS4, SOCKS5 **and** HTTP `CONNECT` together (it
auto-detects the protocol per connection), so `--disable http` disables **all three** — it is not
an HTTP-only toggle. With `--disable http`, `--listen` is never bound; only its IP is still used
to derive the MASQUE bind address (`--listen`'s IP + `--udp-port`).

```
auto-server --enable h3 --disable http --key key.pem --cert-chain cert.pem --auth-token <TOKEN> --udp-port 8443
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

- A `CONNECT-UDP` request names exactly **one** target in its `:authority` (host **and explicit
  port** — RFC 9298 forbids an omitted port). The server resolves it once (via the shared DNS
  resolver), applies the same `--acl-no-rfc6890`/`--no-loopback` blocking as the TCP proxy
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

Configure the browser/system as an **HTTP/HTTPS proxy** pointing at `https://<host>:<udp-port>/`
with the proxy auth credential above, and ensure HTTP/3 (QUIC) is enabled. Chrome, for example,
tunnels QUIC to origins through an HTTP proxy via MASQUE `CONNECT-UDP` when so configured.

## MTU / `TooLarge` limitation

QUIC datagrams are MTU-bounded (initially ~1200 bytes, growing with path MTU discovery). A UDP
packet larger than the current datagram MTU cannot be sent as a single HTTP/3 DATAGRAM. The server
pre-checks each outgoing capsule against `quinn`'s live `max_datagram_size()` and **drops** packets
that would not fit, logging at debug level and relying on the client's own retransmission (per RFC
9298). It never panics or tears down the tunnel for an oversized packet. Note that the
`h3-datagram` 0.0.2 `SendDatagramError` variants are private, so the server pre-checks the MTU
rather than matching the `TooLarge` error at runtime.

## Verifying

```
# 1. Generate a throwaway self-signed cert (NOT in the repo):
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 -subj "/CN=localhost"

# 2. Start with MASQUE enabled (use a high UDP port to avoid needing root for 443):
auto-server --enable h3 --key key.pem --cert-chain cert.pem --auth-token s3cr3t --udp-port 8443 --listen 127.0.0.1:1080
#    -> expect both log lines:
#       proxy server started listen=127.0.0.1:1080 ...
#       masque (HTTP/3 CONNECT-UDP) server started listen=127.0.0.1:8443

# 3. Missing auth-token is rejected before binding:
auto-server --enable h3 --key key.pem --cert-chain cert.pem --udp-port 8443
#    -> error: the following required arguments were not provided: --auth-token <AUTH_TOKEN>

# 4. MASQUE-only: no TCP listener at all (1080 is never bound)
auto-server --enable h3 --disable http --key key.pem --cert-chain cert.pem --auth-token s3cr3t --udp-port 8443
#    -> only: "masque (HTTP/3 CONNECT-UDP) server started listen=0.0.0.0:8443"
#       (no "proxy server started" line; nothing listening on 1080)

# 5. --disable http without --enable h3 is rejected before binding:
auto-server --disable http
#    -> error: --disable http requires --enable h3: nothing would be listening
```

### Automated end-to-end test

`src/masque.rs` also contains `e2e_connect_udp_roundtrip` — a real handshake that drives the
actual `MasqueServer` with a `quinn` + `h3` client over a freshly generated self-signed
certificate, sends `CONNECT-UDP`, asserts `200`, and round-trips a UDP payload through a local
echo socket via HTTP/3 DATAGRAM capsules. It is `#[ignore]`d (and a no-op if `openssl` is absent)
so it does not run in the default `cargo test`:

```
cargo test -- --ignored e2e_connect_udp_roundtrip
```

The test proves two things a bind-only smoke test cannot: (a) the server advertises HTTP/3
DATAGRAM + extended-CONNECT settings (otherwise the client handshake fails), and (b) datagrams
flow both ways through the tunnel. Note it generates the self-signed cert with
`basicConstraints=CA:FALSE` + `extendedKeyUsage=serverAuth` so the client's real webpki verifier
accepts it as an end-entity.

## Limitations

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
