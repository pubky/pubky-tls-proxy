# Share ports 80 and 443 between nginx and pubky-tls-proxy

This is the alternative to the [simpler nginx and Let's Encrypt guide](nginx-letsencrypt.md), where Pubky clients connect to the proxy on port 8443. Here, **browsers and Pubky clients both use port 443**. Choose this if clients cannot reach port 8443.

```text
Browser ── HTTP/HTTPS ─┐                 ┌─> nginx 127.0.0.1:8443 (HTTPS) ─┐
                      ├─> proxy :80/:443 ┤                                   ├─> website
Pubky client ──────────┘                 └─> nginx 127.0.0.1:8080 (HTTP) ────┘
```

The proxy decrypts Pubky TLS but passes browser HTTPS through untouched, so nginx handles the Let's Encrypt certificate. nginx only listens on localhost. This setup was tested on Debian 13; the same commands apply to Debian 12 and Ubuntu 24.04.

## Before you begin

You need a server with `sudo` access, TCP ports **80 and 443** open to the public, and a domain whose A record points to your server. This guide calls that domain `example.com`: **replace it with yours in every file name, command, and configuration example**.

You also need your Pubky secret key (32 bytes as hex) and an **already published pkarr packet** for that key, with an A record pointing to the server and an HTTPS record for **port 443**. The proxy republishes existing packets; it doesn't create one. Copy your secret file to your home directory on the server, for example `scp secret your-user@example.com:~/secret`. Keep an offline backup.

## 1. Install nginx and certbot

```bash
sudo apt update
sudo apt install nginx certbot nano curl
```

nginx's default site uses port 80, which the proxy needs. Remove its **enabled link** and reload nginx:

```bash
sudo rm /etc/nginx/sites-enabled/default
sudo systemctl reload nginx
```

## 2. Create the website

Make a directory and a test page:

```bash
sudo mkdir -p /var/www/example.com
sudo nano /var/www/example.com/index.html
```

Paste this page, replacing `example.com` with your domain. Save in nano with **Ctrl+O**, Enter; exit with **Ctrl+X**:

```html
<h1>Hello from example.com</h1>
```

nginx must first serve **plain HTTP** so Let's Encrypt can check your domain. Open a new nginx site:

```bash
sudo nano /etc/nginx/sites-available/example.com
```

Paste this, replacing `example.com` in the `root` line. A browser's Host header isn't restricted yet; step 6 adds the domain-specific redirect after the certificate exists.

```nginx
server {
    listen 127.0.0.1:8080 default_server proxy_protocol;
    server_name _;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    root /var/www/example.com;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}
```

Save and exit. Enable the site, then test and reload nginx:

```bash
sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/example.com
sudo nginx -t
sudo systemctl reload nginx
```

## 3. Install pubky-tls-proxy

Go to the [releases page](https://github.com/pubky/pubky-tls-proxy/releases/latest) and find the latest Linux archive for your server. The commands here use **v0.3.1 on linux-amd64**; change the version and platform in the names and URLs if needed.

```bash
mkdir -p ~/pubky-tls-proxy-download
cd ~/pubky-tls-proxy-download
curl -fLO https://github.com/pubky/pubky-tls-proxy/releases/download/v0.3.1/pubky-tls-proxy-linux-amd64-v0.3.1.tar.gz
curl -fLO https://github.com/pubky/pubky-tls-proxy/releases/download/v0.3.1/SHA256SUMS
sha256sum --ignore-missing -c SHA256SUMS
```

The checksum must print `OK`. Extract and install the binary:

```bash
tar -xzf pubky-tls-proxy-linux-amd64-v0.3.1.tar.gz
sudo cp pubky-tls-proxy-linux-amd64-v0.3.1/pubky-tls-proxy /usr/local/bin/pubky-tls-proxy
sudo chmod 755 /usr/local/bin/pubky-tls-proxy
pubky-tls-proxy --version
```

## 4. Configure the proxy

Create a user for the proxy and protect the secret file:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin pubky-tls-proxy
sudo mkdir -p /etc/pubky-tls-proxy
sudo chown root:pubky-tls-proxy /etc/pubky-tls-proxy
sudo cp ~/secret /etc/pubky-tls-proxy/secret
sudo chown root:pubky-tls-proxy /etc/pubky-tls-proxy/secret
sudo chmod 640 /etc/pubky-tls-proxy/secret
sudo chmod 750 /etc/pubky-tls-proxy
```

After confirming the copy is in place, run `rm ~/secret` to remove the extra server copy (keep your offline backup).

Open the config file:

```bash
sudo nano /etc/pubky-tls-proxy/config.toml
```

Paste this and save it. The proxy owns ports 80 and 443. nginx receives decrypted Pubky TLS on port 8080 and regular, still-encrypted HTTPS on port 8443 (after step 6).

```toml
secret_file = "secret"
listen_addrs = ["0.0.0.0:80", "0.0.0.0:443"]
http_backend_addr = "127.0.0.1:8080"
https_backend_addr = "127.0.0.1:8443"

[republish]
cache_file = "/var/lib/pubky-tls-proxy/pkarr-packet.cache"
```

## 5. Start the proxy

Open the systemd service file:

```bash
sudo nano /etc/systemd/system/pubky-tls-proxy.service
```

Paste the following and save. Unlike the own-port setup, this service needs permission to bind ports **below 1024**:

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

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
StateDirectory=pubky-tls-proxy

[Install]
WantedBy=multi-user.target
```

Start it and inspect the log:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pubky-tls-proxy
sudo journalctl -u pubky-tls-proxy -n 30 --no-pager
```

Look for your public key, `Listening on 0.0.0.0:80`, `Listening on 0.0.0.0:443` and a successful republish. Republish may take a few seconds; check the log again if needed.

## 6. Get the certificate and enable browser HTTPS

Let's Encrypt checks your domain on port 80. The proxy forwards that plain HTTP request to nginx, which serves the challenge from the website directory:

```bash
sudo certbot certonly --webroot -w /var/www/example.com -d example.com --deploy-hook "systemctl reload nginx"
```

Replace `example.com` in both places. certbot asks for an email address and to accept its terms. The deploy hook reloads nginx after future renewals.

Now edit the nginx site again:

```bash
sudo nano /etc/nginx/sites-available/example.com
```

**Replace its entire contents** with the following. Replace **every** `example.com`, including in the certificate paths. nginx now terminates regular HTTPS on localhost:8443; the second block redirects only ordinary HTTP requests for your domain. Pubky requests have the public key as Host, so they aren't redirected.

```nginx
server {
    listen 127.0.0.1:8080 default_server proxy_protocol;
    listen 127.0.0.1:8443 default_server ssl proxy_protocol;
    server_name _;

    set_real_ip_from 127.0.0.1;
    real_ip_header proxy_protocol;

    ssl_certificate     /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    root /var/www/example.com;
    index index.html;
    location / {
        try_files $uri $uri/ =404;
    }
}

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
```

Save, check and reload nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 7. Verify the setup

Replace `example.com` with your domain:

```bash
curl -I http://example.com
curl https://example.com
sudo certbot renew --dry-run
```

HTTP should redirect to HTTPS, the HTTPS request should show your page with a valid certificate, and the renewal test should succeed.

To check Pubky TLS, use OpenSSL **3.2 or newer** (Debian 13 has it; Debian 12 and Ubuntu 24.04 need another computer with newer OpenSSL):

```bash
openssl s_client -connect example.com:443 -enable_server_rpk
```

Look for `Server-to-client raw public key negotiated`. This doesn't verify that the key is yours; check it with a Pubky-capable client. The proxy's public key appears in `sudo journalctl -u pubky-tls-proxy -n 30 --no-pager`, and you can inspect its packet at `https://pkarr.pubky.org/<your-public-key>`.

## Serve an app instead of static files

If your app listens on `127.0.0.1:3000`, edit the **first** nginx server block in step 6. Replace the `root`, `index` and `location /` lines with:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Keep the `/.well-known/acme-challenge/` block in the second server block, so certificate renewals work.

## Troubleshooting

- **The proxy can't bind port 80 or 443:** Something else uses it, often nginx's default site. Run `sudo ss -tlnp` and check that no nginx site listens on a public port.
- **Pubky clients can't connect:** Your pkarr packet must contain an A record for the server and an HTTPS record for port **443**. Publish the correct packet; clients may cache an old one for up to an hour.
- **`No pkarr packet found`:** The proxy only republishes; it doesn't create packets. Publish one before starting it.
- **DHT errors, but relay republishing works:** If your network blocks DHT (UDP), add `[pkarr]` and `bootstrap_nodes = []` to the config. Restart the proxy. The relays publish to the DHT for you.
- **`502 Bad Gateway`:** nginx must listen on `127.0.0.1:8080`. Check `sudo nginx -t` and `sudo systemctl status nginx`.
- **Browser HTTPS disconnects:** Check that nginx listens on `127.0.0.1:8443` with `ssl proxy_protocol` and that the proxy config names it as `https_backend_addr`.
- **certbot can't reach the challenge:** Check the domain's A record, open TCP port 80, and test `curl -I http://example.com`.

For more detail, add `Environment=RUST_LOG=pubky_tls_proxy=debug` under `[Service]` in the systemd unit. Then run `sudo systemctl daemon-reload` and `sudo systemctl restart pubky-tls-proxy`.

## Next steps

- [Configuration](../configuration.md) covers all settings.
- To update the proxy, download the newer version as in step 3. Stop the service with `sudo systemctl stop pubky-tls-proxy` before copying over the running binary; then start it with `sudo systemctl start pubky-tls-proxy`.
- To leave nginx on public ports 80/443 and run the proxy on 8443 instead, use the [simpler guide](nginx-letsencrypt.md).
