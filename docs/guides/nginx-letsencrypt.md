# Set up pubky-tls-proxy with nginx and Let's Encrypt

This guide sets up a website that is reachable in two ways:

- **Browsers** open `https://example.com` and get a regular Let's Encrypt certificate.
- **Pubky clients** open `https://<your public key>` and connect with Pubky TLS.

Both end up on the same nginx site. nginx serves browsers on ports 80 and 443 as on any other server. pubky-tls-proxy listens on its own port, 8443, decrypts Pubky TLS and passes the requests on to nginx.

```
browser ──── HTTP / HTTPS ──────────────────────────> nginx :80 / :443 ────────────┐
                                                                                   ├─> website
Pubky client ── Pubky TLS ──> pubky-tls-proxy :8443 ──> nginx 127.0.0.1:8080 ──────┘
```

Pubky clients find port 8443 in your pkarr packet. The proxy starts every connection to nginx with a [PROXY protocol](../configuration.md#proxy-protocol) header, so nginx still sees the real client addresses of Pubky clients.

The commands were tested on Debian 13 and work the same on Debian 12 and Ubuntu 24.04.

> If your Pubky users sit behind firewalls that only allow port 443, see [Share ports 80 and 443 between nginx and pubky-tls-proxy](nginx-letsencrypt-shared-port.md) instead.

## Before you begin

You need:

- A server running **Ubuntu 24.04, Debian 12 or Debian 13** with a public IPv4 address, and a user with `sudo`.
- **Ports 80, 443 and 8443 (TCP)** open in the server's firewall and in your cloud provider's firewall.
- A **domain** whose `A` record points to the server, e.g. `example.com`.
- Your **pubky secret key**: a file with 32 bytes as hex (64 characters).
- A **published pkarr packet** for that key, with an `A` record pointing to the server and an `HTTPS` record for **port 8443**. The proxy keeps the packet alive, but doesn't create it.

Copy your secret key to your home directory on the server, e.g. from your computer:

```bash
scp secret user@example.com:~/secret
```

## 1. Install nginx and certbot

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
```

`python3-certbot-nginx` lets certbot set up HTTPS in nginx for you.

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

Create the nginx site for browsers. It's a regular site on port 80; certbot adds HTTPS in step 3:

```bash
sudo tee /etc/nginx/sites-available/$DOMAIN > /dev/null <<'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name example.com;

    root /var/www/example.com;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}
EOF
sudo sed -i "s/example\.com/$DOMAIN/g" /etc/nginx/sites-available/$DOMAIN
sudo ln -s /etc/nginx/sites-available/$DOMAIN /etc/nginx/sites-enabled/$DOMAIN
```

Create a second site for Pubky clients. It only listens on `127.0.0.1:8080`, where the proxy sends the decrypted requests, and serves the same page. It's a separate file, so certbot never changes it:

```bash
sudo tee /etc/nginx/sites-available/pubky-tls-proxy > /dev/null <<'EOF'
# Pubky clients, decrypted by pubky-tls-proxy.
server {
    listen 127.0.0.1:8080 proxy_protocol;
    server_name _;

    # The proxy starts every connection with a PROXY protocol header.
    # Take the client address from there.
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    root /var/www/example.com;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}
EOF
sudo sed -i "s/example\.com/$DOMAIN/g" /etc/nginx/sites-available/pubky-tls-proxy
sudo ln -s /etc/nginx/sites-available/pubky-tls-proxy /etc/nginx/sites-enabled/pubky-tls-proxy
sudo nginx -t && sudo systemctl reload nginx
```

## 3. Get a Let's Encrypt certificate

certbot gets the certificate, adds HTTPS to the site and redirects HTTP to HTTPS. It asks for an email address and for you to accept the terms of service:

```bash
sudo certbot --nginx -d $DOMAIN
```

certbot renews the certificate automatically.

## 4. Install pubky-tls-proxy

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

## 5. Configure the proxy

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

# The port in the HTTPS record of your pkarr packet.
listen_addrs = ["0.0.0.0:8443"]
# nginx site for Pubky clients.
http_backend_addr = "127.0.0.1:8080"

[republish]
# /etc is read-only for the service, systemd creates this directory.
cache_file = "/var/lib/pubky-tls-proxy/pkarr-packet.cache"
EOF
```

See [Configuration](../configuration.md) for all settings.

## 6. Start the proxy

Create the systemd service. It runs the proxy as the `pubky-tls-proxy` user and only allows it to write its cache:

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

# To listen on ports below 1024 (e.g. 80 and 443) without running as root, add:
# AmbientCapabilities=CAP_NET_BIND_SERVICE
# CapabilityBoundingSet=CAP_NET_BIND_SERVICE
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
- `Listening on 0.0.0.0:8443`,
- after a few seconds, `Republished pkarr packet for … to: …`. If it's not there yet, wait a moment and run the command again.

`Regular HTTPS -> rejected, no HTTPS backend configured` is expected: browsers talk to nginx directly and never reach the proxy.

If the log says `No pkarr packet found`, your packet isn't published yet. See [Troubleshooting](#troubleshooting).

## 7. Check that everything works

Browsers: plain HTTP redirects to HTTPS, and HTTPS returns your page with a valid certificate:

```bash
curl -sI http://$DOMAIN | head -n 1
curl -s https://$DOMAIN
```

Pubky clients: the proxy answers on port 8443 with your public key instead of a certificate. This needs OpenSSL 3.2 or newer (Debian 13). On Debian 12 and Ubuntu 24.04, run it from another machine with a newer OpenSSL:

```bash
echo | openssl s_client -connect $DOMAIN:8443 -enable_server_rpk 2>/dev/null | grep "raw public key negotiated"
```

It prints `Server-to-client raw public key negotiated`.

Your pkarr packet is published. This reads your public key from the proxy's log and asks a relay for the packet:

```bash
PUBLIC_KEY=$(sudo journalctl -u pubky-tls-proxy -o cat | grep -oP 'Using public key: \K\w+' | tail -n 1)
curl -s -o /dev/null -w "%{http_code}\n" https://pkarr.pubky.org/$PUBLIC_KEY
```

It prints `200`.

Certificate renewal works:

```bash
sudo certbot renew --dry-run
```

## Serve an app instead of static files

To put an app behind nginx, e.g. one listening on `127.0.0.1:3000`, replace the `root`, `index` and `location / { … }` lines in **both** sites with:

```nginx
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
```

Requests from Pubky clients arrive with your public key as `Host`, and with `X-Forwarded-Proto: http`, because the proxy already decrypted them.

## Troubleshooting

**Pubky clients can't connect, but `openssl s_client` on the server works.**
Port 8443 is blocked. Open 8443/TCP in the server's firewall and in your cloud provider's firewall, for all source addresses (`0.0.0.0/0`). A connection that times out, e.g. `nc -vz -w 5 $DOMAIN 8443` from another machine, means a firewall drops it.

**Pubky clients connect to the wrong port.**
The `HTTPS` record in your pkarr packet must name the port the proxy listens on (8443). Publish the packet again with the right port. Clients may use a cached packet for up to an hour.

**The log says `No pkarr packet found … Publish one first`.**
The proxy only republishes existing packets. Publish a packet for your key with an `A` record for the server and an `HTTPS` record for port 8443, then restart the proxy with `sudo systemctl restart pubky-tls-proxy`.

**The log shows DHT errors, but `Republished … to: relays`.**
Some networks block mainline DHT traffic (UDP), e.g. through a restrictive cloud firewall. The relays publish your packet to the DHT for you. To stop the errors, turn off the DHT in `/etc/pubky-tls-proxy/config.toml` and restart the proxy:

```toml
[pkarr]
bootstrap_nodes = []
```

**Pubky clients get `502 Bad Gateway`.**
nginx isn't listening on `127.0.0.1:8080`. Check `sudo nginx -t`, `sudo systemctl status nginx` and that `/etc/nginx/sites-enabled/pubky-tls-proxy` exists.

**certbot fails with a connection or timeout error.**
Check that the domain's `A` record points to the server (`dig +short $DOMAIN`), that port 80 is open in every firewall, and that `curl -sI http://$DOMAIN` works.

**More details in the log.**
Add `Environment=RUST_LOG=pubky_tls_proxy=debug` to the `[Service]` section, then run `sudo systemctl daemon-reload` and `sudo systemctl restart pubky-tls-proxy`.

## Next steps

- [Configuration](../configuration.md): every setting of the proxy.
- Update the proxy: repeat step 4 with the new `VERSION`, then `sudo systemctl restart pubky-tls-proxy`.
- [Share ports 80 and 443 between nginx and pubky-tls-proxy](nginx-letsencrypt-shared-port.md): if Pubky clients must use port 443.
