# Copilot Instructions for `auto-server`

## Build, test, and lint

Use standard Cargo commands from the repository root.

- Build: `cargo build`
- Run: `cargo run`
- Full test suite: `cargo test`
- Run a single test: `cargo test <test_name>`
  - Example (exact name): `cargo test my_unit_test`
  - Example (substring match): `cargo test my_module::`
- Run a single integration test file: `cargo test --test <test_file>`
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`
- Format check: `cargo fmt --all -- --check`

## High-level architecture

Current state:

- `Cargo.toml` defines one package (`auto-server`) on Rust edition 2024 with no external dependencies yet.
- `src/main.rs` contains the only executable entry point (`fn main()`), which currently prints `"Hello, world!"`.

Target architecture for upcoming work:

- Build a Rust proxy server that supports both:
  - SOCKS server behavior (full server-side protocol handling)
  - HTTP `CONNECT` tunneling
- Accept a custom DNS server from CLI parameters and use that resolver path for outbound name resolution.
- On the first client handshake packet, detect protocol family and version automatically, then route to the corresponding handler.

## Key conventions in this codebase

- Keep this as a Cargo-native Rust project; use `cargo` subcommands for all build/test/lint flows.
- Rust edition is **2024**; keep new code compatible with edition-2024 idioms.
- The crate is currently **binary-only** (`src/main.rs`) rather than a `lib.rs` + binary split.
- Dependency set is intentionally empty in `Cargo.toml`; add crates only when implementation requires them.
- Protocol selection should be handshake-driven (no separate listening ports required purely for protocol type).
- SOCKS and HTTP `CONNECT` should share lower-level connection and DNS plumbing where possible; keep protocol parsing/negotiation separated from transport forwarding.
- Treat custom DNS selection as runtime configuration (CLI) rather than compile-time constants.
