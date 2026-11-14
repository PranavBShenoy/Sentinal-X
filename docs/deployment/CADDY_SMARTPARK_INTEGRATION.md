# Caddy Reverse Proxy Integration Guide: SmartPark & Sentinel-X

This guide explains how to route a custom subdomain (e.g., `sentinelx.yourdomain.com`) to the **Sentinel-X** Docker Compose stack using the existing **Caddy** web server on AWS EC2, with **zero downtime or disruption to the existing SmartPark application**.

---

## 1. Architectural Overview

```
                                    Internet (Client HTTPS Requests)
                                                  │
                                                  ▼
                                      AWS EC2 Host (54.79.97.73)
                             ┌─────────────────────────────────────────┐
                             │       Host Caddy Server (:80, :443)     │
                             │   (Automatic Let's Encrypt / ZeroSSL)   │
                             └────────────┬───────────────┬────────────┘
                                          │               │
            SNI: smartpark.yourdomain.com │               │ SNI: sentinelx.yourdomain.com
                                          ▼               ▼
                               ┌─────────────────┐ ┌───────────────────────────────────────┐
                               │    SmartPark    │ │              SENTINEL-X               │
                               │ App Container   │ │         Docker Compose Stack          │
                               │ (e.g. port 5000)│ │                                       │
                               └─────────────────┘ │  ┌───────────────┐ ┌───────────────┐  │
                                                   │  │   Frontend    │ │  Control API  │  │
                                                   │  │ (Nginx :3000) │ │ (FastAPI:8000)│  │
                                                   │  └───────────────┘ └───────────────┘  │
                                                   │  ┌───────────────┐ ┌───────────────┐  │
                                                   │  │ Celery Worker │ │ PostgreSQL/R  │  │
                                                   │  └───────────────┘ └───────────────┘  │
                                                   └───────────────────────────────────────┘
```

### Key Safety Guarantees
1. **Isolated Server Blocks:** Caddy uses Server Name Indication (SNI) to match domains. Requests for `smartpark.yourdomain.com` and `sentinelx.yourdomain.com` are handled by completely independent routing trees.
2. **Independent TLS Certificates:** Caddy automatically requests and renews distinct TLS certificates from Let's Encrypt for each domain. A certificate renewal for Sentinel-X will never impact SmartPark.
3. **Atomic Zero-Downtime Reload:** Running `sudo caddy reload` validates the new configuration in memory before hot-swapping listener routes, preserving in-flight HTTP connections to SmartPark.

---

## 2. Step-by-Step Deployment Instructions

### Step 2.1: DNS Configuration
Add an `A` record in your DNS provider:
* **Host / Subdomain:** `sentinelx` (e.g., `sentinelx.yourdomain.com`)
* **Type:** `A`
* **Target IP:** `54.79.97.73`
* **TTL:** `300` (5 minutes)

*(For testing without a custom domain, you can use the wildcard nip.io domain `sentinelx.54.79.97.73.nip.io`).*

---

### Step 2.2: Add Sentinel-X Snippet to Caddyfile
On the EC2 instance, edit `/etc/caddy/Caddyfile`:

```bash
# Option A: Import the snippet directly
echo 'import /home/ubuntu/Sentinal-X/infrastructure/caddy/Caddyfile.snippet' | sudo tee -a /etc/caddy/Caddyfile

# Option B: Paste the block directly into /etc/caddy/Caddyfile:
sudo nano /etc/caddy/Caddyfile
```

Add the following block:
```caddy
sentinelx.yourdomain.com {
    encode zstd gzip

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    # API Proxy to FastAPI backend
    handle /api/* {
        reverse_proxy 127.0.0.1:8000 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }

    # Dashboard Proxy to React/Nginx frontend
    handle {
        reverse_proxy 127.0.0.1:3000 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-For {remote_host}
            header_up X-Forwarded-Proto {scheme}
        }
    }
}
```

---

### Step 2.3: Validate & Gracefully Reload Caddy
Execute the following commands on the EC2 host:

```bash
# 1. Validate syntax without affecting running services
sudo caddy validate --config /etc/caddy/Caddyfile

# 2. Hot-reload Caddy without dropping existing SmartPark traffic
sudo caddy reload --config /etc/caddy/Caddyfile
```

---

### Step 2.4: Update Sentinel-X CORS Origins
In `/home/ubuntu/Sentinal-X/.env`, update `CORS_ORIGINS` to permit the new HTTPS domain:

```env
CORS_ORIGINS=https://sentinelx.yourdomain.com,http://54.79.97.73:3000,http://localhost:3000
```

Then refresh the API container:
```bash
docker compose up -d api
```

---

## 3. Verification & Health Checks

1. Verify HTTPS certificate generation:
   ```bash
   curl -I https://sentinelx.yourdomain.com
   ```
   *Expected: `HTTP/2 200` with Let's Encrypt certificate and security headers.*

2. Verify API proxy routing:
   ```bash
   curl -s https://sentinelx.yourdomain.com/api/v1/health | jq .
   ```
   *Expected: `{"status":"healthy","service":"sentinelx-api",...}`.*

3. Verify SmartPark is unaffected:
   ```bash
   curl -I https://smartpark.yourdomain.com
   ```
   *Expected: Normal SmartPark response without any interruption.*
