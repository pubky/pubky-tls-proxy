# Set up pubky-tls-proxy with nginx and Let's Encrypt

This guide serves one website two ways: browsers use ordinary HTTPS on port 443, and Pubky clients use Pubky TLS on port 8443. nginx handles the browser traffic; the proxy decrypts Pubky TLS and passes those requests to nginx on localhost.

```text
Browser ────────────────> nginx :80 / :443 ──────────────┐
                                                         ├─> website
Pubky client ──> proxy :8443 ──> nginx 127.0.0.1:8080 ──┘
```

The commands were tested on Debian 13. They also apply to Debian 12 and Ubuntu 24.04. If Pubky clients must use port 443, use the [shared-port guide](nginx-letsencrypt-shared-port.md) instead.

## Before you begin

You need:

- A server with a public IPv4 address and a user with `sudo` access. Open **TCP ports 80, 443 and 8443** in the server and cloud firewalls.
- A domain pointing to that address. This guide uses `example.com`; **replace it with your domain everywhere**, including in file names and configuration examples.
- Your Pubky secret key in a file containing 32 bytes as hex (64 characters). Copy it to your home directory on the server; for example, from your computer: `scp secret your-user@example.com:~/secret`.
- An **already published pkarr packet** for that key with an `A` record for your server and an `HTTPS` record specifying **port 8443**. The proxy republishes existing packets but does not create them.

Keep another copy of the secret key somewhere safe. The guide moves the server copy into `/etc`.

## 1. Install nginx and certbot

```bash
sudo apt update
sudo apt install nginx certbot python3-certbot-nginx nano curl
```

The nginx plugin lets certbot configure HTTPS and renewal for you. Leave nginx's default site in place for now.

## 2. Create the website

Create a directory and a simple page:

```bash
sudo mkdir -p /var/www/example.com
sudo nano /var/www/example.com/index.html
```

Paste this into the editor (with your own domain), then save with **Ctrl+O**, Enter, and exit with **Ctrl+X**:

```html
<h1>Hello from example.com</h1>
```

Open the nginx site in the editor:

```bash
sudo nano /etc/nginx/sites-available/example.com
```

Paste this configuration, replacing `example.com` in both places:

```nginx
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
```

Save and exit. Enable the site by linking it into `sites-enabled`, then check and reload nginx:

```bash
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/example.com
sudo nginx -t
sudo systemctl reload nginx
```

Create a **second** nginx site for Pubky requests. Keeping it separate means certbot won't alter it:

```bash
sudo nano /etc/nginx/sites-available/pubky-tls-proxy
```

Paste this (again, replace `example.com`):

```nginx
server {
    listen 127.0.0.1:8080 proxy_protocol;
    server_name _;

    # Trust client addresses supplied by the local proxy.
    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    root /var/www/example.com;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}
```

Save and exit, then enable this site too:

```bash
sudo ln -s /etc/nginx/sites-available/pubky-tls-proxy /etc/nginx/sites-enabled/pubky-tls-proxy
sudo nginx -t
sudo systemctl reload nginx
```

## 3. Enable HTTPS for browsers

Ask certbot to set up the certificate and HTTPS in the **domain's** nginx site:

```bash
sudo certbot --nginx -d example.com
```

Enter your email address, accept the terms, and choose to redirect HTTP to HTTPS when prompted. certbot also arranges automatic renewal. The Pubky nginx site stays untouched.

## 4. Install pubky-tls-proxy

On the [releases page](https://github.com/pubky/pubky-tls-proxy/releases/latest), find the latest version and the Linux archive for your server (for example, `linux-amd64` on an Intel/AMD server). The commands below use **v0.3.1 on linux-amd64**; replace the version and platform in the file names and URLs if necessary.

Download the archive and checksum list into a folder in your home directory:

```bash
mkdir -p ~/pubky-tls-proxy-download
cd ~/pubky-tls-proxy-download
curl -fLO https://github.com/pubky/pubky-tls-proxy/releases/download/v0.3.1/pubky-tls-proxy-linux-amd64-v0.3.1.tar.gz
curl -fLO https://github.com/pubky/pubky-tls-proxy/releases/download/v0.3.1/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

The checksum check must print `OK`. Extract and install the binary:

```bash
tar -xzf pubky-tls-proxy-linux-amd64-v0.3.1.tar.gz
sudo cp pubky-tls-proxy-linux-amd64-v0.3.1/pubky-tls-proxy /usr/local/bin/pubky-tls-proxy
sudo chmod 755 /usr/local/bin/pubky-tls-proxy
pubky-tls-proxy --version
```

## 5. Configure the proxy

Create a service user and a directory for the config and secret. Only the service user and root will be able to read the secret:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin pubky-tls-proxy
sudo mkdir -p /etc/pubky-tls-proxy
sudo chown root:pubky-tls-proxy /etc/pubky-tls-proxy
sudo cp ~/secret /etc/pubky-tls-proxy/secret
sudo chown root:pubky-tls-proxy /etc/pubky-tls-proxy/secret
sudo chmod 640 /etc/pubky-tls-proxy/secret
sudo chmod 750 /etc/pubky-tls-proxy
```

After confirming the copy is in place, remove the copy in your home directory with `rm ~/secret` (keep your offline backup).

Open the config:

```bash
sudo nano /etc/pubky-tls-proxy/config.toml
```

Paste this configuration and save it. The secret path is relative to this file; the cache path is writable by the service:

```toml
secret_file = "secret"
listen_addrs = ["0.0.0.0:8443"]
http_backend_addr = "127.0.0.1:8080"

[republish]
cache_file = "/var/lib/pubky-tls-proxy/pkarr-packet.cache"
```

For other options, see [Configuration](../configuration.md).

## 6. Start the proxy

Create a systemd service:

```bash
sudo nano /etc/systemd/system/pubky-tls-proxy.service
```

Paste the following and save. systemd creates the writable `/var/lib/pubky-tls-proxy` cache directory. The proxy doesn't need root privileges to listen on port 8443.

```ini
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
```

Enable and start the service, then inspect its log:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pubky-tls-proxy
sudo journalctl -u pubky-tls-proxy -n 30 --no-pager
```

Look for your public key, `Listening on 0.0.0.0:8443`, and `Republished pkarr packet for …`. Republish may take a few seconds; check the log again if needed. `Regular HTTPS -> rejected, no HTTPS backend configured` is expected: browsers connect directly to nginx, not to this proxy.

## 7. Verify the setup

Replace `example.com` with your domain in these checks:

```bash
curl -I http://example.com
curl https://example.com
sudo certbot renew --dry-run
```

HTTP should redirect to HTTPS; the HTTPS request should print your page without a certificate error; the renewal test should succeed.

To check Pubky TLS, use OpenSSL 3.2 or newer (available on Debian 13). On Debian 12 or Ubuntu 24.04, run this command from another computer with a newer OpenSSL:

```bash
openssl s_client -connect example.com:8443 -enable_server_rpk
```

Look for `Server-to-client raw public key negotiated`. This confirms the proxy is listening, but does not verify that the presented public key is yours; use a Pubky-capable client for that. You can find your key in `sudo journalctl -u pubky-tls-proxy -n 30 --no-pager` and inspect its published packet at `https://pkarr.pubky.org/<your-public-key>`.

## Serve an app instead of static files

If your app listens on `127.0.0.1:3000`, edit **both** nginx sites. In each one, replace the `root`, `index` and `location /` lines with:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Test with `sudo nginx -t` and reload with `sudo systemctl reload nginx`. Pubky clients arrive with your public key as `Host`. nginx sees `http` for their forwarded requests because the proxy already decrypted Pubky TLS.

## Troubleshooting

- **Pubky clients can't connect:** Check that TCP port 8443 is open to your users (for a public site, source range `0.0.0.0/0`). From another machine, run `nc -vz -w 5 example.com 8443`. A timeout usually means a firewall is dropping traffic.
- **Pubky clients go to the wrong port:** The pkarr `HTTPS` record must specify 8443. Republish the packet with the right port; clients may cache the old one for up to an hour.
- **`No pkarr packet found`:** The proxy can't create a packet. Publish one with an `A` record for the server and an `HTTPS` record for port 8443, then restart the proxy.
- **DHT errors, but publishing to relays succeeds:** If your network blocks DHT (UDP), add `[pkarr]` and `bootstrap_nodes = []` to the config file. Restart the proxy; the relays publish to the DHT on your behalf.
- **`502 Bad Gateway` for Pubky clients:** Check `sudo systemctl status nginx` and `sudo nginx -t`. nginx must listen on `127.0.0.1:8080` with `proxy_protocol` enabled.
- **certbot fails:** Confirm the domain's A record points to this server and port 80 is open. Test `curl -I http://example.com`.

For more logs, set `Environment=RUST_LOG=pubky_tls_proxy=debug` in the systemd service under `[Service]`, then run `sudo systemctl daemon-reload` and `sudo systemctl restart pubky-tls-proxy`.

## Next steps

- [Configuration](../configuration.md) covers all settings.
- To update the proxy, download the newer version as in step 4. Stop the service with `sudo systemctl stop pubky-tls-proxy` before copying over the running binary; then start it with `sudo systemctl start pubky-tls-proxy`.
- To serve Pubky TLS and ordinary HTTPS on **the same port 443**, follow the [shared-port guide](nginx-letsencrypt-shared-port.md).
