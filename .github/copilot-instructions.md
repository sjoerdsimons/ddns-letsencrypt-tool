# Copilot Instructions

## Project Overview

`ddns-letsencrypt-tool` is a Rust application that combines:
- An **RFC 2136 dynamic DNS (DDNS) update client** — keeps DNS A/AAAA records in sync with the host's current IP addresses using TSIG-authenticated DNS updates.
- An **ACME client** — automatically requests and renews TLS certificates from Let's Encrypt using the DNS-01 challenge.

The tool is intended to run as a long-lived daemon (see `data/ddns-letsencrypt-tool.service`) that monitors network address changes via rtnetlink and reacts accordingly.

## Repository Layout

```
src/
  main.rs            – Entry point; CLI parsing, config loading, ACME logic, main loop
  address_monitor.rs – Watches network interface address changes via rtnetlink/netlink
  certstore.rs       – Manages on-disk certificate and account storage
  dnsupdate.rs       – RFC 2136 DNS update implementation (TSIG-authenticated)
data/
  config.yml         – Example configuration file
  ddns-letsencrypt-tool.service – Example systemd unit file
.github/
  workflows/
    ci.yml           – CI: cargo test, cargo fmt, cargo clippy
    dist.yml         – Release/distribution workflow
  dependabot.yml     – Automated dependency updates (Cargo + GitHub Actions)
```

## Language & Toolchain

- **Language:** Rust (edition 2024, MSRV 1.90)
- **Async runtime:** Tokio (full features)
- **Key libraries:** `instant-acme`, `domain` (DNS), `rtnetlink`, `serde`/`serde_yaml`, `clap`, `tracing`

## Building

```bash
cargo build
cargo build --release
```

## Testing

```bash
cargo test --all-targets --all-features
```

## Linting & Formatting

The CI enforces both formatting and clippy warnings:

```bash
cargo fmt --all --check   # check formatting
cargo fmt --all           # auto-format
cargo clippy --all-targets -- -D warnings  # lints (warnings are errors)
```

Always run `cargo fmt` before committing and ensure `cargo clippy` produces no warnings.

## Configuration

The tool is configured via a YAML file (see `data/config.yml`). Key fields:

| Field | Description |
|-------|-------------|
| `server` | DNS server address (FQDN with trailing dot) |
| `zone` | DNS zone to update |
| `hostname` | Hostname to register |
| `key.id` / `key.algorithm` / `key.secret` | TSIG key for authenticated DNS updates |
| `letsencrypt.contacts` | Contact email addresses for ACME account |
| `letsencrypt.store` | Directory for storing certificates and account credentials |
| `letsencrypt.production` | `true` for production Let's Encrypt, `false` for staging |
| `addresses.ipv4.enabled` / `addresses.ipv6.enabled` | Which address families to update in DNS |

## Coding Conventions

- Use `anyhow` for error propagation with `.context()`/`bail!`/`anyhow!` macros.
- Use `thiserror` for defining structured error types.
- Use `tracing` (`info!`, `warn!`, etc.) for logging — not `println!` or `eprintln!`.
- Async functions use `tokio` primitives (`tokio::time::sleep`, `tokio::select!`, etc.).
- Deserializable config structs derive `serde::Deserialize`; serializable state structs derive both `Serialize` and `Deserialize`.
- Follow standard Rust naming conventions (snake_case for functions/variables, CamelCase for types).
- Keep `cargo fmt` formatting; clippy warnings must not be introduced.
