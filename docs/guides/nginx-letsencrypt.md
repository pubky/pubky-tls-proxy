# Set up pubky-tls-proxy with nginx and Let's Encrypt

This guide sets up a website that is reachable in two ways:

- **Browsers** open `https://example.com` and get a regular Let's Encrypt certificate.
- **Pubky clients** open `https://<your public key>` and connect with Pubky TLS.

Both end up on the same nginx site. pubky-tls-proxy owns the public ports 80 and 443 and routes each connection. nginx only listens on localhost.

```
                            ┌───────────────── your server ──────────────────┐
  browser ── HTTPS ───┐     │                        ┌─> 127.0.0.1:8443 ─┐     │
  browser ── HTTP ────┼──> :80/:443  pubky-tls-proxy ┤   (nginx, TLS)    ├─> website
  Pubky client ───────┘     │                        └─> 127.0.0.1:8080 ─┘     │
      (Pubky TLS)           │                            (nginx, plain HTTP)   │
                            └────────────────────────────────────────────────┘
```

The proxy decrypts Pubky TLS itself and passes regular HTTPS through untouched, so nginx terminates it with the Let's Encrypt certificate. Every connection to nginx starts with a [PROXY protocol](../configuration.md#proxy-protocol) header, so nginx still sees the real client addresses.

The commands were tested on Debian 13 and work the same on Debian 12 and Ubuntu 24.04.

## Before you begin

You need:

- A server running **Ubuntu 24.04, Debian 12 or Debian 13** with a public IPv4 address, and a user with `sudo`.
- **Ports 80 and 443 (TCP)** open in the server's firewall and in your cloud provider's firewall.
- A **domain** whose `A` record points to the server, e.g. `example.com`.
- Your **pubky secret key**: a file with 32 bytes as hex (64 characters).
- A **published pkarr packet** for that key, with an `A` record pointing to the server and an `HTTPS` record for port 443. The proxy keeps the packet alive, but doesn't create it.

Copy your secret key to your home directory on the server, e.g. from your computer:

```bash
scp secret user@example.com:~/secret
```

Nothing else may use ports 80 and 443 on the server. This guide installs nginx and moves it off these ports.

## 1. Install nginx and certbot

```bash
sudo apt update
sudo apt install -y nginx certbot
```

nginx's default site listens on port 80, which the proxy needs. Turn it off:

```bash
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl reload nginx
```

## 2. Create the website

Set your domain once. The following steps use it:

```bash
DOMAIN=example.com
```

> If you open a new terminal later, run this line again.

Create a page to serve:

```bash
sudo mkdir -p /var/www/$DOMAIN
echo "<h1>Hello from $DOMAIN</h1>" | sudo tee /var/www/$DOMAIN/index.html
```

Create the nginx site. For now it only serves plain HTTP on `127.0.0.1:8080`, which is where the proxy sends plain HTTP and decrypted Pubky TLS:

```bash
sudo tee /etc/nginx/sites-available/$DOMAIN > /dev/null <<'EOF'
# All traffic arrives through pubky-tls-proxy, which starts every connection with a
# PROXY protocol header. Take the client address from there.
set_real_ip_from 127.0.0.1;
real_ip_header proxy_protocol;

server {
    # Plain HTTP and decrypted Pubky TLS.
    listen 127.0.0.1:8080 default_server proxy_protocol;
    server_name _;

    root /var/www/example.com;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}
EOF
sudo sed -i "s/example\.com/$DOMAIN/g" /etc/nginx/sites-available/$DOMAIN
sudo ln -s /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/$DOMAIN
sudo nginx -t && sudo systemctl reload nginx
```

## 3. Install pubky-tls-proxy

Download the [latest release](https://github.com/pubky/pubky-tls-proxy/releases/latest) for your server's architecture, check it and install it:

```bash
VERSION=0.3.1
ARCH=$(dpkg --print-architecture)
RELEASE=https://github.com/pubky/pubky-tls-proxy/releases/download/v$VERSION
cd "$(mktemp -d)"

curl -fsSLO $RELEASE/pubky-tls-proxy-linux-$ARCH-v$VERSION.tar.gz
curl -fsSLO $RELEASE/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS

tar -xzf pubky-tls-proxy-linux-$ARCH-v$VERSION.tar.gz
sudo install -m 0755 pubky-tls-proxy-linux-$ARCH-v$VERSION/pubky-tls-proxy /usr/local/bin/
pubky-tls-proxy --version
```

`sha256sum` must print `OK` for the archive.

## 4. Configure the proxy

Create a system user for the proxy and put the secret key where only root and that user can read it:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin pubky-tls-proxy
sudo install -d -m 0750 -o root -g pubky-tls-proxy /etc/pubky-tls-proxy
sudo install -m 0640 -o root -g pubky-tls-proxy ~/secret /etc/pubky-tls-proxy/secret
rm ~/secret
```

Write the config file:

```bash
sudo tee /etc/pubky-tls-proxy/config.toml > /dev/null <<'EOF'
# Relative to this file's directory.
secret_file = "secret"

# The proxy owns the public ports.
listen_addrs = ["0.0.0.0:80", "0.0.0.0:443"]
# nginx: plain HTTP and decrypted Pubky TLS.
http_backend_addr = "127.0.0.1:8080"
# nginx: regular HTTPS, set up in step 6.
https_backend_addr = "127.0.0.1:8443"

[republish]
# /etc is read-only for the service, systemd creates this directory.
cache_file = "/var/lib/pubky-tls-proxy/pkarr-packet.cache"
EOF
```

See [Configuration](../configuration.md) for all settings.

## 5. Start the proxy

Create the systemd service. It runs the proxy as the `pubky-tls-proxy` user and only allows it to bind the ports and write its cache:

```bash
sudo tee /etc/systemd/system/pubky-tls-proxy.service > /dev/null <<'EOF'
[Unit]
Description=pubky-tls-proxy - routes Pubky TLS, HTTPS and HTTP to a web server
Documentation=https://github.com/pubky/pubky-tls-proxy
After=network-online.target nginx.service
Wants=network-online.target

[Service]
User=pubky-tls-proxy
Group=pubky-tls-proxy
ExecStart=/usr/local/bin/pubky-tls-proxy --config /etc/pubky-tls-proxy/config.toml
Restart=on-failure
RestartSec=5s

# Bind ports 80 and 443 without running as root.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# Writable /var/lib/pubky-tls-proxy for the pkarr packet cache.
StateDirectory=pubky-tls-proxy

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now pubky-tls-proxy
```

Check the log:

```bash
sudo journalctl -u pubky-tls-proxy -n 30 --no-pager
```

You should see:

- `Using public key: …` with **your** public key,
- `Listening on 0.0.0.0:80` and `Listening on 0.0.0.0:443`,
- after a few seconds, `Republished pkarr packet for … to: …`. If it's not there yet, wait a moment and run the command again.

If the log says `No pkarr packet found`, your packet isn't published yet. See [Troubleshooting](#troubleshooting).

## 6. Get a Let's Encrypt certificate and turn on HTTPS

Let's Encrypt checks your domain over plain HTTP. The request goes through the proxy to nginx, which serves the challenge from the website directory. certbot asks for an email address and for you to accept the terms of service:

```bash
sudo certbot certonly --webroot -w /var/www/$DOMAIN -d $DOMAIN --deploy-hook "systemctl reload nginx"
```

certbot renews the certificate automatically and reloads nginx afterwards (`--deploy-hook`).

Now add the HTTPS listener on `127.0.0.1:8443`, where the proxy sends regular HTTPS. Plain HTTP requests for the domain are redirected to HTTPS. Pubky clients use the public key as host name, so they're never redirected:

```bash
sudo tee /etc/nginx/sites-available/$DOMAIN > /dev/null <<'EOF'
# All traffic arrives through pubky-tls-proxy, which starts every connection with a
# PROXY protocol header. Take the client address from there.
set_real_ip_from 127.0.0.1;
real_ip_header proxy_protocol;

server {
    # Plain HTTP, decrypted Pubky TLS and regular HTTPS.
    listen 127.0.0.1:8080 default_server proxy_protocol;
    listen 127.0.0.1:8443 default_server ssl proxy_protocol;
    server_name _;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    root /var/www/example.com;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}

# Redirect plain HTTP for the domain to HTTPS, except the Let's Encrypt challenges.
server {
    listen 127.0.0.1:8080 proxy_protocol;
    server_name example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/example.com;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}
EOF
sudo sed -i "s/example\.com/$DOMAIN/g" /etc/nginx/sites-available/$DOMAIN
sudo nginx -t && sudo systemctl reload nginx
```

## 7. Check that everything works

Browsers: plain HTTP redirects to HTTPS, and HTTPS returns your page with a valid certificate:

```bash
curl -sI http://$DOMAIN | head -n 1
curl -s https://$DOMAIN
```

Pubky clients: the proxy answers with your public key instead of a certificate. This needs OpenSSL 3.2 or newer (Debian 13). On Debian 12 and Ubuntu 24.04, run it from another machine with a newer OpenSSL:

```bash
echo | openssl s_client -connect $DOMAIN:443 -enable_server_rpk 2>/dev/null | grep "raw public key negotiated"
```

It prints `Server-to-client raw public key negotiated`.

Your pkarr packet is published. This reads your public key from the proxy's log and asks a relay for the packet:

```bash
PUBLIC_KEY=$(sudo journalctl -u pubky-tls-proxy -o cat | grep -oP 'Using public key: \K\w+' | tail -n 1)
curl -s -o /dev/null -w "%{http_code}\n" https://pkarr.pubky.org/$PUBLIC_KEY
```

It prints `200`.

nginx logs the real client addresses, not `127.0.0.1`:

```bash
sudo tail -n 3 /var/log/nginx/access.log
```

For the `curl` commands above, run on the server, that's the server's own public address. A line with `""` and `400` from `127.0.0.1` is the `openssl` check, which connects without sending a request.

Certificate renewal works through the proxy:

```bash
sudo certbot renew --dry-run
```

## Serve an app instead of static files

To put an app behind the proxy, e.g. one listening on `127.0.0.1:3000`, replace the `root`, `index` and `location / { … }` lines of the first `server` block with:

```nginx
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
```

Keep the `location /.well-known/acme-challenge/` block in the second `server` block, so certificate renewals keep working. Requests from Pubky clients arrive with your public key as `Host`.

## Troubleshooting

**The proxy doesn't start: `Failed to bind to listen address 0.0.0.0:80`.**
Something else uses the port, usually nginx's default site. Run `sudo ss -tlnp | grep -E ':(80|443) '` to find it. Make sure `/etc/nginx/sites-enabled/default` is gone and that no other nginx site listens on `80` or `443`.

**The log says `No pkarr packet found … Publish one first`.**
The proxy only republishes existing packets. Publish a packet for your key with an `A` record for the server and an `HTTPS` record for port 443, then restart the proxy with `sudo systemctl restart pubky-tls-proxy`.

**The log shows DHT errors, but `Republished … to: relays`.**
Some networks block mainline DHT traffic (UDP), e.g. through a restrictive cloud firewall. The relays publish your packet to the DHT for you. To stop the errors, turn off the DHT in `/etc/pubky-tls-proxy/config.toml` and restart the proxy:

```toml
[pkarr]
bootstrap_nodes = []
```

**`502 Bad Gateway`.**
nginx isn't listening on `127.0.0.1:8080`. Check `sudo nginx -t` and `sudo systemctl status nginx`.

**HTTPS connections are closed right away.**
nginx isn't listening on `127.0.0.1:8443` yet. Finish step 6.

**certbot fails with a connection or timeout error.**
Check that the domain's `A` record points to the server (`dig +short $DOMAIN`), that port 80 is open in every firewall, and that `curl -sI http://$DOMAIN` works.

**nginx shows `broken header` errors.**
Something connects to nginx without going through the proxy. Only the proxy may connect to `127.0.0.1:8080` and `127.0.0.1:8443`.

**More details in the log.**
Add `Environment=RUST_LOG=pubky_tls_proxy=debug` to the `[Service]` section, then run `sudo systemctl daemon-reload` and `sudo systemctl restart pubky-tls-proxy`.

## Next steps

- [Configuration](../configuration.md): every setting of the proxy.
- Update the proxy: repeat step 3 with the new `VERSION`, then `sudo systemctl restart pubky-tls-proxy`.
