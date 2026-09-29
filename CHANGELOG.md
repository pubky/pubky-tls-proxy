# Changelog

All notable changes are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Return a generic 502 response without backend addresses or OS errors; keep full diagnostics
  in server logs for plain HTTP and Pubky TLS backend failures.

### Changed
- Reworked the README with a plain-language introduction, clearer setup choices,
  and an overview of traffic forwarding and backend requirements.

## [0.3.2] - 2026-09-28

### Security
- Limit concurrent connections across listeners, bound Pubky TLS handshakes and backend setup,
  and close idle connections to prevent stalled clients from exhausting proxy resources.

### Added
- `plain_http = false` / `--no-plain-http` to reject incoming plain HTTP on a Pubky-only port
  without affecting decrypted Pubky TLS; rejected protocol traffic is logged at debug level.
- Guide: [set up the proxy with nginx and Let's Encrypt](docs/guides/nginx-letsencrypt.md),
  with the proxy on its own port (8443).
- Guide: [share ports 80 and 443 between nginx and the proxy](docs/guides/nginx-letsencrypt-shared-port.md).

### Changed
- Reworked both nginx and Let's Encrypt guides for manual setup with a text editor
  instead of shell-generated configuration files.
- The example systemd unit runs the proxy as an unprivileged `pubky-tls-proxy` user, with
  the config in `/etc/pubky-tls-proxy/` and the packet cache in `/var/lib/pubky-tls-proxy/`.
  For ports below 1024 it needs `CAP_NET_BIND_SERVICE`, see the comment in the unit.
- The configuration reference moved from the README to `docs/configuration.md`.

## [0.3.1] - 2026-09-28

### Added
- Cache the pkarr packet on disk (`pkarr-packet.cache`, `--packet-cache-file`), so it can
  still be republished if it disappears from the DHT and the relays.

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

[Unreleased]: https://github.com/pubky/pubky-tls-proxy/compare/v0.3.2...HEAD
[0.3.2]: https://github.com/pubky/pubky-tls-proxy/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/pubky/pubky-tls-proxy/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/pubky/pubky-tls-proxy/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/pubky/pubky-tls-proxy/compare/v0.1.0-rc.0...v0.2.0
[0.1.0-rc.0]: https://github.com/pubky/pubky-tls-proxy/releases/tag/v0.1.0-rc.0
