# Pubky TLS Proxy

[![GitHub Release](https://img.shields.io/github/v/release/pubky/pubky-tls-proxy)](https://github.com/pubky/pubky-tls-proxy/releases/latest/)
[![Telegram Chat Group](https://img.shields.io/badge/Chat-Telegram-violet)](https://t.me/pubkycore)

Pubky TLS Proxy lets Pubky clients connect to an existing web server, such as nginx.
It handles the Pubky TLS connection and forwards the decrypted HTTP traffic to your server.

You can give Pubky clients their own port or share ports 80 and 443 with regular browser
traffic. On shared ports, your web server continues to handle HTTPS certificates.

Pubky uses [raw public key TLS (RFC 7250)](https://datatracker.ietf.org/doc/html/rfc7250):
clients identify the server by its public key rather than a certificate issued by a
certificate authority. The proxy handles this part so your web server doesn't need to.

## Getting started

Download a binary for your platform from the
[latest release](https://github.com/pubky/pubky-tls-proxy/releases/latest/), then choose
a setup guide:

- [Use a separate port for Pubky clients](docs/guides/nginx-letsencrypt.md) (recommended).
  This Ubuntu and Debian guide leaves nginx on ports 80 and 443 and runs the proxy on
  port 8443.
- [Share ports 80 and 443](docs/guides/nginx-letsencrypt-shared-port.md).
  Use this setup if Pubky clients need to connect on port 443. The proxy sits in front
  of nginx and routes both Pubky and browser connections.

You will need:

- A web server or HTTP service for the proxy to forward requests to.
- A Pubky secret key stored in a file as 64 hex characters (32 bytes).
- A published pkarr packet for that key. It tells clients where to connect, with an
  `A` record for your server's address and an `HTTPS` record for the proxy's port.
  The proxy republishes an existing packet; you need to publish it once with another tool.

## How it works

The proxy checks the start of each connection to decide where to send it. A backend
is the server behind the proxy that handles the request.

| Incoming traffic | What the proxy does | Destination |
|------------------|---------------------|-------------|
| Pubky TLS | Handles TLS using your secret key and forwards decrypted HTTP | HTTP backend |
| Plain HTTP | Forwards the HTTP traffic | HTTP backend |
| Regular HTTPS | Passes the encrypted traffic through; the backend handles TLS | HTTPS backend |

You can disable incoming plain HTTP with `--no-plain-http`. Regular HTTPS connections
are closed unless you configure an HTTPS backend. See the
[configuration reference](docs/configuration.md) for backend addresses and other settings.

By default, the proxy sends the client's address to each backend using a
[PROXY protocol header](docs/configuration.md#proxy-protocol). Your backend must be
configured to accept this header. If it doesn't support the PROXY protocol, use
`--no-proxy-protocol`.

The proxy also republishes your pkarr packet every hour and keeps a copy on disk.
If the packet disappears from the network, it can republish the cached copy.
It never creates a new packet or changes its records.

If a backend is unreachable, plain HTTP and Pubky TLS clients receive a
`502 Bad Gateway`. Regular HTTPS connections are closed because only the backend
can complete their TLS handshake.

## Documentation

- [Configuration](docs/configuration.md): command-line options, config files,
  connection limits, packet republishing, and logging.
- [Changelog](CHANGELOG.md): changes in each release.
- [Releasing](RELEASE.md): how to build and publish a release.
