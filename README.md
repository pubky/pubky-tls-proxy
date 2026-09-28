# Pubky TLS Proxy

[![GitHub Release](https://img.shields.io/github/v/release/pubky/pubky-tls-proxy)](https://github.com/pubky/pubky-tls-proxy/releases/latest/)
[![Telegram Chat Group](https://img.shields.io/badge/Chat-Telegram-violet)](https://t.me/pubkycore)

A proxy that terminates [raw public key TLS (RFC 7250)](https://datatracker.ietf.org/doc/html/rfc7250), which Pubky uses, in front of a regular web server such as nginx. The same ports serve Pubky clients, browsers over HTTPS and plain HTTP.

| Incoming traffic | What the proxy does                                  | Forwarded to           |
|------------------|------------------------------------------------------|------------------------|
| Plain HTTP       | forwards it unchanged                                | `--http-backend-addr`  |
| Pubky TLS        | terminates TLS with your pubky secret key            | `--http-backend-addr`  |
| Regular HTTPS    | forwards it still encrypted, the backend handles TLS | `--https-backend-addr` |

The proxy also keeps your pkarr packet alive: it republishes it every hour and keeps a copy on disk.

## Requirements

- A pubky secret key (32 bytes as hex).
- A **published pkarr packet** for that key, with an `A` record for your server and an `HTTPS` record for port 443. The proxy republishes this packet, but never creates one.

## Getting started

- [Set up pubky-tls-proxy with nginx and Let's Encrypt](docs/guides/nginx-letsencrypt.md): a step-by-step guide for Ubuntu and Debian servers.
- Download a binary from the [latest release](https://github.com/pubky/pubky-tls-proxy/releases/latest/).

## Documentation

- [Configuration](docs/configuration.md): all arguments, the config file, republishing, the packet cache and the PROXY protocol.
- [Releasing](RELEASE.md) and the [changelog](CHANGELOG.md).

## How it works

1. The proxy loads the secret key and creates a Pubky keypair.
2. It listens on every listen address and starts republishing the pkarr packet in the background.
3. For each connection it reads the first bytes the client sends:
   - Anything that doesn't start with a TLS handshake is **plain HTTP**.
   - A TLS ClientHello that offers Raw Public Keys as server certificate type (RFC 7250) is **Pubky TLS**. Pubky clients only offer raw public keys. Browsers never do. The SNI is ignored.
   - Any other TLS ClientHello is **regular HTTPS**.
4. It opens a TCP connection to the matching backend and sends a [PROXY protocol](docs/configuration.md#proxy-protocol) header with the client's address, unless that's turned off.
5. It replays the bytes it has already read, then copies data in both directions. Pubky TLS is decrypted on the way.

If the backend is unreachable, plain HTTP and Pubky TLS clients receive a `502 Bad Gateway`. Regular HTTPS connections are closed, because only the backend can complete their TLS handshake.
