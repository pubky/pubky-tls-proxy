# Pubky TLS Proxy

> ⚠️ Very rough prototype. Production use not recommended.

This tool acts as a TLS terminating proxy for RFC 7250 certificates. It allows you to:

1. Load a Pubky secret from a file.
2. Create a TLS server using Pubky TLS (RFC 7250).
3. Forward decrypted traffic to another service, for example NGINX.

## Usage

```bash
pubky-tls-proxy --secret-file <PATH_TO_SECRET_KEY> --backend-addr <BACKEND_ADDRESS> --listen-addr <LISTEN_ADDRESS>
```

### Arguments

- `--secret-file`: Path to a file containing the pubky secret in HEX format (must be 32 bytes/64 hex characters)
- `--backend-addr`: Address to proxy requests to after TLS termination (e.g., 127.0.0.1:8080) [default: 127.0.0.1:8080]
- `--listen-addr`: Address to listen on for incoming TLS connections (e.g., 0.0.0.0:8443) [default: 0.0.0.0:8443]

### Example

To create a proxy that:
- Listens for TLS connections on port 8443
- Uses a pubky secret from `secret`
- Forwards decrypted traffic to a local service on port 3000

```bash
pubky-tls-proxy --secret-file secret --backend-addr 127.0.0.1:3000 --listen-addr 0.0.0.0:8443
```

### Creating a Secret Key File

To generate a new secret key:

```bash
# Generate a 32-byte random secret and save as hex
openssl rand -hex 32 > secret
```

## How It Works

This proxy:

1. Loads the secret key and creates a Pubky keypair.
2. Sets up a TLS listener using the keypair.
3. For each connection:
   - Terminates the TLS
   - Opens a TCP connection to the backend
   - Bidirectionally copies data between the client and backend
