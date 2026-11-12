# Runtime Host mTLS terminator (Nginx)

This directory contains the only public-facing Runtime Host entry point.

## Trust boundary

```
control plane / worker
        │  TLS 1.2+ with a client certificate issued by client_ca
        ▼
runtime_host_proxy (nginx)  ── validates chain against client_ca.crt
        │  private Docker network "sentinelx-runtime-edge"
        │  X-Client-Cert: URL-encoded PEM of the verified client cert
        │  X-Runtime-Proxy-Token: shared secret from a Docker secret
        ▼
runtime_host (FastAPI, no published port) ── re-verifies chain + clientAuth EKU
```

- `runtime_host` has **no published host port**.
- `runtime_host_proxy` is the only service attached to the external-facing
  Runtime Host port.
- The Runtime Host backend is reachable only over the dedicated
  `sentinelx-runtime-edge` network, and additionally requires the shared
  proxy token. Direct callers cannot authenticate even if they reach the
  backend network.
- Nginx overwrites every identity header it forwards. Caller-supplied
  `X-SSL-Client-Cert`, `X-Client-Cert`, `X-Client-Fingerprint`, and related
  headers are discarded before the trusted values are injected.
- The backend independently verifies that the forwarded leaf certificate
  chains to the configured client CA, asserts `clientAuth` EKU, is not a CA,
  and is currently valid. Nginx is not the only verifier.

Nginx OSS exposes only a SHA-1 client fingerprint variable. To avoid using a
weak identity, Nginx forwards the URL-encoded PEM of the certificate it
verified, and the Runtime Host computes the SHA-256 fingerprint over the DER
bytes. The fingerprint is therefore derived from the Nginx-verified
certificate, never from a caller-supplied header.

## Required environment

### Proxy

| Variable | Purpose |
|---|---|
| `NGINX_SERVER_CERT` | Server certificate path (inside container) |
| `NGINX_SERVER_KEY` | Server private key path |
| `NGINX_CLIENT_CA` | Trusted client CA bundle (public cert only) |
| `NGINX_CLIENT_CRL` | Optional CRL path |
| `NGINX_REQUIRE_CRL` | `true` to fail startup when no CRL is configured |
| `NGINX_VERIFY_DEPTH` | Client chain verification depth (default `2`) |
| `NGINX_RUNTIME_DIR` | Writable directory for generated `token.conf`/`crl.conf` |
| `RUNTIME_HOST_PROXY_TOKEN_FILE` | Protected file containing the token (Docker secret) |
| `RUNTIME_HOST_PROXY_TOKEN` | Token fallback when no file is configured |

### Backend

| Variable | Purpose |
|---|---|
| `RUNTIME_HOST_PUBLIC_KEY_PATH` | Ed25519 JWT verification key (public) |
| `RUNTIME_HOST_CLIENT_CA_PATH` | Trusted client CA certificate (public) |
| `RUNTIME_HOST_PROXY_TOKEN_FILE` | Same protected token file as the proxy |
| `RUNTIME_HOST_AUDIENCE` | Expected JWT audience (required in production) |

## Proxy token

Generate at least 32 characters of random material and store it in a protected
file, for example:

```sh
mkdir -p runtime_host/certs
python3 -c "import secrets; print(secrets.token_urlsafe(48))" \
  > runtime_host/certs/proxy_token
chmod 600 runtime_host/certs/proxy_token
```

Docker Compose provides the file to both containers as the secret
`runtime_host_proxy_token` (mounted at `/run/secrets/runtime_host_proxy_token`).
Set `RUNTIME_HOST_PROXY_TOKEN_SECRET_FILE` to use a different host path.

The proxy entrypoint reads the secret and writes it to
`$NGINX_RUNTIME_DIR/token.conf` (mode 0600) as an Nginx `set` variable. The
token is therefore **not** written into the rendered `default.conf`, and it is
not placed in the container environment. It is never logged.

Token rules: at least 32 characters; only `A-Z`, `a-z`, `0-9`, `_`, `-`; and
no `CHANGE_ME`/placeholder text. Rotate by replacing the secret file and
restarting both the proxy and the Runtime Host together. There is deliberately
no dual-token fallback; a failed rotation fails closed.

## Certificates

Generate disposable development certificates outside the repository, for
example:

```sh
runtime_host/certs/generate_certs.sh /tmp/sentinelx-certs
```

The script produces a separated layout:

```
/tmp/sentinelx-certs/
  ca/        client_ca.{crt,key}, server_ca.{crt,key}   (keep offline)
  server/    server.crt, server.key, client_ca.crt      (proxy)
  client/    client.crt, client.key, server_ca.crt      (control plane)
  crl/       optional CRLs
```

Provisioning rules:

- **Runtime Host backend** mounts only the JWT public key and
  `server/client_ca.crt`.
- **Proxy** mounts only `server/server.crt`, `server/server.key`,
  `server/client_ca.crt`, and optionally a CRL from `crl/`.
- **Control plane** keeps `client/client.crt` and `client/client.key`; it
  trusts `client/server_ca.crt` for the proxy server certificate.
- **Never** mount `ca/client_ca.key`, `ca/server_ca.key`, `client/client.key`,
  or the whole `certs/` directory into any container.

The Runtime Host also requires an Ed25519 public verification key at
`RUNTIME_HOST_PUBLIC_KEY_PATH`; that key is produced by the control plane
(Stage 2B), not by this directory.

Never commit private keys, tokens, or production certificates. The repository
`.gitignore` excludes generated certificate directories and token files.

### Migrating existing certificate material

Earlier revisions stored `ca.crt`, `ca.key`, `server.crt`, `server.key`,
`client.crt`, and `client.key` in one directory and mounted that directory into
both containers. Do not delete the old files; migrate manually:

1. Create `ca/`, `server/`, `client/`, and `crl/` directories alongside the old
   files.
2. Move the existing CA material into `ca/`. Keep `ca.key` offline.
3. Move the server certificate/key into `server/` and the control-plane
   certificate/key into `client/`.
4. Copy the public CA certificate to `server/client_ca.crt` and the public
   server CA certificate to `client/server_ca.crt`.
5. Update the host-side locations used by `docker-compose.yml` (or regenerate
   with `generate_certs.sh`).
6. Remove the old broad directory mounts. Verify no container can read
   `ca.key`, `client.key`, or `client.crt`.

Existing single-CA deployments can map the old `ca.crt` to
`server/client_ca.crt`; the new generator uses separate client and server CAs
for certificate-purpose separation.

## CRL

Mount CRLs from `runtime_host/certs/crl` and set
`NGINX_CLIENT_CRL=/etc/nginx/tls/crl/<name>.crl`. The entrypoint parses the
CRL and fails startup if it is malformed. Set `NGINX_REQUIRE_CRL=true` to
refuse startup when no CRL is configured.

## Direct access

The backend has no `ports:` entry in `docker-compose.yml`. Do not add one.
Reaching the backend directly does not bypass mTLS: the backend requires the
proxy token **and** re-verifies the forwarded certificate chain. Keep
`sentinelx-runtime-edge` limited to the proxy and Runtime Host; no other
application service may join it.
