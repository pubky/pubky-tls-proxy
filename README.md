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
are published through PKARR, so the server's IP address can change while the domain
stays the same.

## Getting started

With a version that includes `init` (currently unreleased), prepare your files first:

```sh
pubky-tls-proxy init
```

The interactive setup suggests your outbound public IPv4 address and asks you to
review it and the public TLS port (default `8443`) before creating files. It creates
`config.toml`, `secret`, and `dns-records.toml` in `~/.pubky-tls-proxy/`, preserving
existing files. **Nothing is published until you start the proxy.** Review the files
and configure your backend before starting. Behind NAT or a load balancer, use the
address clients connect to and arrange inbound routing to the advertised port.
See [initialization](docs/configuration.md#initialization) for unattended setup.

Download a binary for your platform from the
[latest release](https://github.com/pubky/pubky-tls-proxy/releases/latest/), then choose
a setup guide.

- [Use a separate port for raw public key TLS](docs/guides/nginx-letsencrypt.md) (recommended).
  This Ubuntu and Debian guide leaves nginx on ports 80 and 443 and runs the proxy on
  port 8443.
- [Share ports 80 and 443](docs/guides/nginx-letsencrypt-shared-port.md).
  Use this setup if raw public key TLS must be available on port 443. The proxy sits
  in front of nginx and routes both types of TLS connection.

You will need:

- A web server or HTTP service for the proxy to forward requests to.
- (Optionally) a secret key. The proxy generates one on first startup at
  `~/.pubky-tls-proxy/secret`, or you can supply an existing key with `--secret-key-file`.

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

With `dns-records.toml`, the proxy publishes changes automatically and republishes
the PKARR packet every hour. Without the file, it republishes
the latest PKARR packet from the network (or cached copy) unchanged.

## Documentation

- [Terminology](docs/terminology.md): domains, keys, connection types, and PKARR publishing.
- [Configuration migration](docs/configuration-migration.md): renamed CLI options and configuration keys.
- [Configuration](docs/configuration.md): command-line options, config files,
  connection limits, packet republishing, and logging.
- [Changelog](CHANGELOG.md): changes in each release.
- [Releasing](RELEASE.md): how to build and publish a release.
