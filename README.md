# Pubky TLS Proxy

[![GitHub Release](https://img.shields.io/github/v/release/pubky/pubky-tls-proxy)](https://github.com/pubky/pubky-tls-proxy/releases/latest/)
[![Telegram Chat Group](https://img.shields.io/badge/Chat-Telegram-violet)](https://t.me/pubkycore)


This tool terminates [raw public key TLS (RFC 7250)](https://datatracker.ietf.org/doc/html/rfc7250), which Pubky uses, in front of a regular web server such as nginx. A single port can serve Pubky clients, plain HTTP and regular HTTPS side by side.

| Incoming traffic | What the proxy does                                  | Forwarded to           |
|------------------|------------------------------------------------------|------------------------|
| Plain HTTP       | forwards it unchanged                                | `--http-backend-addr`  |
| Pubky TLS        | terminates TLS with your pubky secret key            | `--http-backend-addr`  |
| Regular HTTPS    | forwards it still encrypted, the backend handles TLS | `--https-backend-addr` |

## Usage

```bash
pubky-tls-proxy --secret-file <PATH> [--listen-addr <ADDR>]... [--http-backend-addr <ADDR>] [--https-backend-addr <ADDR>] [--no-proxy-protocol]
```

### Arguments

- `--secret-file`: Path to a file containing the pubky secret in HEX format (must be 32 bytes/64 hex characters).
- `--listen-addr`: Address to listen on. Can be repeated, e.g. for ports 80 and 443 [default: 0.0.0.0:8443].
- `--http-backend-addr`: Backend for plain HTTP and decrypted Pubky TLS traffic [default: 127.0.0.1:6286]. `--backend-addr` still works as an alias.
- `--https-backend-addr`: Backend for regular HTTPS traffic. If it isn't set, regular HTTPS connections are closed.
- `--no-proxy-protocol`: Don't send a [PROXY protocol](https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt) header to the backends. See below.

### PROXY protocol

The backend sees every connection coming from the proxy. So that it still knows the real client address, the proxy starts each backend connection with a PROXY protocol v1 header, e.g. `PROXY TCP4 203.0.113.7 10.0.0.1 51000 443`.

This is **on by default**. The backend must be configured to expect the header (in nginx: `listen ... proxy_protocol;`). If the backend doesn't support it, pass `--no-proxy-protocol`.

### Example: in front of nginx

The proxy owns the public ports 80 and 443, while nginx listens on localhost only:

```bash
pubky-tls-proxy --secret-file secret \
  --listen-addr 0.0.0.0:80 --listen-addr 0.0.0.0:443 \
  --http-backend-addr 127.0.0.1:6286 \
  --https-backend-addr 127.0.0.1:6443
```

```nginx
server {
    # Plain HTTP and decrypted Pubky TLS.
    listen 127.0.0.1:6286 proxy_protocol;
    # Regular HTTPS, nginx terminates TLS with its usual certificates.
    listen 127.0.0.1:6443 ssl proxy_protocol;

    server_name example.com;
    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    # Use the client address from the PROXY protocol header.
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    location / {
        proxy_pass http://127.0.0.1:8080;  # e.g. the Pubky homeserver
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_protocol_addr;
    }
}
```

Requests from Pubky clients arrive on the plain HTTP listener, so they are recognisable by their `Host` header, which is the public key, e.g. `server_name <your-z32-public-key>;`.

### Example: directly in front of a Pubky homeserver

```bash
pubky-tls-proxy --secret-file secret --listen-addr 0.0.0.0:8443 --http-backend-addr 127.0.0.1:6286 --no-proxy-protocol
```

### Creating a Secret Key File

To generate a new secret key:

```bash
# Generate a 32-byte random secret and save as hex
openssl rand -hex 32 > secret
```

## How It Works

1. The proxy loads the secret key and creates a Pubky keypair.
2. It listens on every `--listen-addr`.
3. For each connection it reads the first bytes the client sends:
   - Anything that doesn't start with a TLS handshake is **plain HTTP**.
   - A TLS ClientHello that offers Raw Public Keys as server certificate type (RFC 7250) is **Pubky TLS**. Pubky clients only offer raw public keys. Browsers never do. The SNI is ignored.
   - Any other TLS ClientHello is **regular HTTPS**.
4. It opens a TCP connection to the matching backend and sends the PROXY protocol header, unless it's disabled.
5. It replays the bytes it has already read, then copies data in both directions. Pubky TLS is decrypted on the way.

If the backend is unreachable, plain HTTP and Pubky TLS clients receive a `502 Bad Gateway`. Regular HTTPS connections are closed, because only the backend can complete their TLS handshake.
