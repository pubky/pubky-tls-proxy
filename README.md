# Pubky TLS Proxy

[![GitHub Release](https://img.shields.io/github/v/release/pubky/pubky-tls-proxy)](https://github.com/pubky/pubky-tls-proxy/releases/latest/)
[![Telegram Chat Group](https://img.shields.io/badge/Chat-Telegram-violet)](https://t.me/pubkycore)

Pubky TLS Proxy is a reverse proxy that adds raw public key TLS support to existing
HTTP services, with optional passthrough for certificate-based TLS. It handles the
raw public key TLS connection and forwards decrypted HTTP traffic to your server,
such as nginx.

You can give raw public key TLS its own port or share ports 80 and 443 with plain HTTP
and certificate-based HTTPS. On shared ports, your web server continues to handle certificates.

Pubky uses [raw public key TLS (RFC 7250)](https://datatracker.ietf.org/doc/html/rfc7250):
clients identify the server by its public key rather than a certificate issued by a
certificate authority. The proxy handles this part so your web server doesn't need to.

A **Public Key Domain** is a domain named by an encoded public key. Its DNS records
are published through [PKARR](https://github.com/pubky/pkarr), so the server's IP
address can change while the domain stays the same.

## Getting started

You'll need an HTTP service, such as nginx, for the proxy to forward requests to.

**Choose a setup guide:**

- **[Separate port (recommended)](docs/guides/nginx-letsencrypt.md)** — Keep nginx on
  ports 80 and 443 and run Pubky TLS Proxy on port 8443.
- **[Shared ports](docs/guides/nginx-letsencrypt-shared-port.md)** — Run the proxy in
  front of nginx to serve both raw public key TLS and certificate-based HTTPS on
  port 443.

Both guides cover installation, configuration, and running the proxy on Ubuntu or
Debian.

For other setups, download a binary from the
[latest release](https://github.com/pubky/pubky-tls-proxy/releases/latest/) and follow
the [configuration reference](docs/configuration.md).

## How it works

The proxy checks the start of each connection to decide where to send it. A backend
is the server behind the proxy that handles the request.

| Incoming traffic | What the proxy does | Destination |
|------------------|---------------------|-------------|
| Raw public key TLS | Handles TLS using your secret key and forwards decrypted HTTP | HTTP backend |
| Plain HTTP | Forwards the HTTP traffic | HTTP backend |
| Certificate-based HTTPS | Passes the encrypted traffic through; the backend handles TLS | TLS passthrough backend |

You can disable incoming plain HTTP with `--no-plain-http`. Certificate-based HTTPS connections
are closed unless you configure a TLS passthrough backend. See the
[configuration reference](docs/configuration.md) for backend addresses and other settings.

By default, the proxy sends the client's address to each backend using a
[PROXY protocol header](docs/configuration.md#proxy-protocol). Your backend must be
configured to accept this header. If it doesn't support the PROXY protocol, use
`--no-proxy-protocol`.

Local-record publishing is the default: startup requires `dns-records.toml`, publishes
changes automatically, and republishes the PKARR packet every hour. To use externally
managed records, explicitly set `[pkarr] mode = "external-packet"`; the proxy then
republishes the latest packet from the network (or cached copy) unchanged.

## Documentation

- [Terminology](docs/terminology.md): domains, keys, connection types, and PKARR publishing.
- [Configuration](docs/configuration.md): command-line options, config files,
  connection limits, packet republishing, and logging.
- [Changelog](CHANGELOG.md): changes in each release.
- [Releasing](RELEASE.md): how to build and publish a release.
