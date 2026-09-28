# Changelog

All notable changes are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Clients that disconnect or stay silent are logged at debug level instead of as warnings.
  rustls warnings about misbehaving clients are hidden unless `RUST_LOG` enables them.

## [0.3.0] - 2026-09-28

### Added
- Republish the pkarr packet every hour (`--no-republish`, `--republish-interval-secs`).
- Configurable DHT bootstrap nodes and relays (`--pkarr-bootstrap-node`, `--pkarr-relay`,
  `--no-pkarr-dht`, `--no-pkarr-relays`).
- Config file `~/.pubky-tls-proxy/config.toml`, or `--config <FILE>`.
- `RUST_LOG` support.
- Release binaries are built on GitHub Actions, now including 32-bit ARM.

### Changed
- **Breaking:** a relative `--secret-file` is resolved against the config directory.
- Updated pkarr to 8.0.2.
- No ANSI colours in logs when stdout isn't a terminal.

## [0.2.0] - 2026-09-28

### Added
- Route plain HTTP, Pubky TLS and regular HTTPS on one port (`--https-backend-addr`).
- PROXY protocol v1 header to the backends (`--no-proxy-protocol`).
- Repeatable `--listen-addr`.
- `502 Bad Gateway` when the backend is unreachable.
- systemd service file.

### Changed
- **Breaking:** the PROXY protocol header is on by default.
- **Breaking:** the default backend is `127.0.0.1:6286` (was `127.0.0.1:8080`).
- `--backend-addr` is now `--http-backend-addr` (old name kept as alias).

## [0.1.0-rc.0] - 2025-04-25

- First release candidate.

[Unreleased]: https://github.com/pubky/pubky-tls-proxy/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/pubky/pubky-tls-proxy/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pubky/pubky-tls-proxy/compare/v0.1.0-rc.0...v0.2.0
[0.1.0-rc.0]: https://github.com/pubky/pubky-tls-proxy/releases/tag/v0.1.0-rc.0
