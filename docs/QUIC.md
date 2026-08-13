# QUIC / HTTP/3 support

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
  destination and cached. A UDP relay must not add RTT-scale latency to every datagram, which QUIC's
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

## Limitations

- Requires a **SOCKS5**-capable client. Clients configured with an **HTTP/HTTPS proxy** (Chrome's
  default proxy type) will use HTTP/2, not HTTP/3, through this proxy.
- We evaluated adding MASQUE (`RFC 9298` `CONNECT-UDP`) so that HTTP-proxy clients could also tunnel
  QUIC. `RFC 9298` requires HTTP/2 DATAGRAM frames (`RFC 9297`) to carry UDP payloads, but the
  mature Rust HTTP/2 library (`h2`) does not implement DATAGRAM frames, so MASQUE over HTTP/2 cannot
  interoperate with Chrome using current Rust crates. A future option is MASQUE over HTTP/3
  (`h3` + `quinn`), which has native datagram support.
