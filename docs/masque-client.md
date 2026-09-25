# `masque-client` — end-to-end client for the MASQUE listener

`masque-client` is a **standalone binary** (built from `src/bin/masque-client.rs`, so no
`Cargo.toml` change is needed) that exercises every protocol `auto-server --enable h3`
serves from its single HTTP/3 listener. Use it to verify a running server instead of
hand-writing QUIC clients or reading logs.

Build it with the rest of the project:

```bash
cargo build          # -> target/debug/masque-client
```

## CLI surface

Common options (all modes):

| flag | meaning |
|------|---------|
| `--proxy <host:port>` | **required.** MASQUE proxy to connect to (the server's `--h3-bind`). |
| `--token <TOKEN>` | sent as `Proxy-Authorization: Bearer <TOKEN>`. Mandatory if the server was started with `--auth-token`. |
| `--ca <pem>` | **repeatable.** Adds PEM certificates to the client's webpki root store. See *Trust* below. |
| `--server-name <name>` | TLS server name / QUIC SNI. Defaults to the host part of `--proxy`; must match a SAN in the server certificate. |
| `--timeout-ms <ms>` | budget for the whole run (default 15000). Non-zero exit on expiry. |

Subcommands:

```
masque-client <common> udp --target <host:port> [--dns <name>] [--payload-hex <hex>]
masque-client <common> tcp --target <host:port> [--payload <str> | --http-get <path>]
masque-client <common> ws  --target <host:port> [--payload <str>]
masque-client <common> ip  [--ping <ipv4>]
```

* `udp` — `CONNECT-UDP` (RFC 9298). Default payload is a DNS `A` query for `--dns`
  (`example.com` by default); `--payload-hex` sends raw bytes instead.
* `tcp` — plain `CONNECT` (RFC 9114 §4.4), no `:protocol`. Target comes from `:authority`.
* `ws` — `:protocol=websocket` byte pipe (RFC 9220). The proxy does not interpret WebSocket,
  so no handshake bytes are added: what you pass in `--payload` is what the origin receives.
* `ip` — `CONNECT-IP` (RFC 9484). Parses `ADDRESS_ASSIGN` / `ROUTE_ADVERTISEMENT` from the
  request stream, then sends an ICMP echo request as `Context ID 0` + a raw IP packet.
  `--ping` sets the destination; by default it pings the proxy end of the point-to-point
  link (the server's pool allocates `/30`s with proxy = base+1, client = base+2).

Each step is reported individually and a failure exits non-zero, which makes the tool usable
in a loop or CI step:

```
  handshake (QUIC + HTTP/3)            ... PASS
  CONNECT-UDP accepted                 ... PASS
  datagram round-trip                  ... PASS
RESULT: PASS
```

Negative cases were also verified explicitly: a wrong (or missing) token yields
`407 Proxy Authentication Required` and running with no `--ca` fails immediately with
"no trust anchor", both exiting `1`.

### Trust: no `--insecure`, by design

There is deliberately **no certificate-verification bypass**. Self-signed test certificates
are trusted by pointing `--ca` at the server's PEM, which goes into a real
`rustls::RootCertStore` — no custom verifier, no disabled checks. Adding `--insecure` would
require enabling rustls' `dangerous_configuration` feature only for this tool.

> **Not an independent conformance check.** `masque-client` reuses the server's own
> `auto_server::capsule` codec, so a green run proves that the server works end-to-end — it
> does **not** prove that our wire format matches an independent implementation.
> **masque-go remains the independent interop test.**

## Running all four modes

### 1. Certificate and server

```bash
mkdir -p /tmp/masque-verify && cd /tmp/masque-verify

# Throwaway self-signed cert — never generate this inside the repo.
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "extendedKeyUsage=serverAuth" \
  -addext "keyUsage=digitalSignature,keyEncipherment"

auto-server --listen 127.0.0.1:0 --enable h3 \
  --h3-bind 127.0.0.1:4433 \
  --key /tmp/masque-verify/key.pem \
  --cert-chain /tmp/masque-verify/cert.pem \
  --auth-token test-masque-token
```

`--server-name localhost` is needed below because the cert's SANs are `DNS:localhost` /
`IP:127.0.0.1`, not the numeric proxy address.

### 2. Local echo targets

A tiny UDP + TCP echo pair (any equivalent will do):

```python
# /tmp/masque-verify/echo.py — python3 echo.py   (UDP 43001, TCP 43002)
import socket, threading
def udp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", port))
    while True:
        data, addr = s.recvfrom(65535); s.sendto(data, addr)
def tcp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("127.0.0.1", port)); s.listen(16)
    def handle(c):
        while True:
            data = c.recv(65535)
            if not data: c.close(); return
            c.sendall(data)
    while True:
        c, _ = s.accept(); threading.Thread(target=handle, args=(c,), daemon=True).start()
threading.Thread(target=udp, args=(43001,), daemon=True).start(); tcp(43002)
```

### 3. One command per mode

```bash
COMMON="--proxy 127.0.0.1:4433 --server-name localhost --ca /tmp/masque-verify/cert.pem --token test-masque-token"

masque-client $COMMON udp --target 127.0.0.1:43001                        # DNS A query for example.com
masque-client $COMMON udp --target 127.0.0.1:43001 --payload-hex deadbeef # raw bytes
masque-client $COMMON tcp --target 127.0.0.1:43002 --payload hello-tcp
masque-client $COMMON tcp --target 127.0.0.1:43002 --http-get /ping
masque-client $COMMON ws  --target 127.0.0.1:43002 --payload hello-ws
masque-client $COMMON ip                                                  # ICMP echo through the tunnel
```

All four were executed against a locally started server on this host; see *Verification
status* below.

## `ip` mode needs root — on the server

`CONNECT-IP` allocates a real `tun` device, adds a NAT rule and enables forwarding, so the
**server** must have `CAP_NET_ADMIN`. The client itself does not. As a non-root user the
mode fails at exactly one step, with the server logging why:

```
  CONNECT-IP accepted                  ... FAIL
      reason: expected 200, got 500 Internal Server Error (auth missing? is the server on Linux and running as root?)
```

```text
# server-side log
WARN failed to create tun device peer=127.0.0.1:59132 client=198.18.0.2 \
     error=TUNSETIFF ioctl failed (need CAP_NET_ADMIN / root)
```

### Verifying `ip` without touching the host

If you prefer not to run anything privileged against your machine, run the whole test inside
a throwaway network namespace the process owns — nothing on the host changes, and the
namespace (interface, NAT rules, `ip_forward`) disappears with it:

```bash
unshare -Urn bash -c '
  ip link set lo up
  python3 /tmp/masque-verify/echo.py & sleep 1
  auto-server --listen 127.0.0.1:0 --enable h3 --h3-bind 127.0.0.1:4433 \
    --key /tmp/masque-verify/key.pem --cert-chain /tmp/masque-verify/cert.pem \
    --auth-token test-masque-token & sleep 2
  masque-client --proxy 127.0.0.1:4433 --server-name localhost \
    --ca /tmp/masque-verify/cert.pem --token test-masque-token ip
'
```

Inside the namespace the client pings the proxy's tun address and the kernel answers from the
tunnel itself:

```
      ADDRESS_ASSIGN      198.18.0.2/30
      ROUTE_ADVERTISEMENT 1 range(s): 0.0.0.0..=255.255.255.255 proto 0
      source (assigned)   198.18.0.2
      ICMP echo request   198.18.0.2 -> 198.18.0.1
  IP packet round-trip                 ... PASS
      ICMP echo reply: IPv4 198.18.0.1 -> 198.18.0.2, type 0 (echo reply), 57 bytes
```

The first downlink packet is often **not** your echo reply — a freshly created `tun` sees the
kernel's IPv6 router solicitation. The client drains those and reports them ("skipped N
unrelated downlink packet(s)") rather than failing on them.

## Verification status (as of v0.5.0)

* Executed end-to-end on this host: `udp` (DNS query **and** `--payload-hex`), `tcp`
  (`--payload` and `--http-get`), `ws`, and `ip` — the last inside a private namespace as
  shown above (the current user is not root, uid 1000). Every mode reached `RESULT: PASS`.
* Teardown was checked too: once the client disconnects, the `tun` interface and the
  `MASQUERADE` rule are both gone within ~1 second and nothing is left behind.
* Automated in-tree tests still pass: `cargo test` (51 unit tests) and
  `cargo test --lib -- --ignored` (5 e2e tests, including the existing CONNECT-UDP, plain TCP
  CONNECT and WebSocket round-trips).

## Notes / gotchas for maintainers

* **Capture the h3 stream id before reading the body.** `h3-quinn`'s `RecvStream` parks its
  underlying stream while a read is in flight, so calling `RequestStream::id()` at that moment
  panics inside `recv_id()`. `ip` mode therefore reads the id immediately after the response —
  this is why its stream handling differs slightly from `udp`'s.
* The binary deliberately duplicates the small ICMP/IP-checksum helpers from the e2e module
  rather than exporting test-only code. Everything protocol-shaped comes from the shared
  `auto_server::capsule` codec.
