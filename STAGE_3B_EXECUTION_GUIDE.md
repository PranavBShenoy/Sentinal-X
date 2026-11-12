# Stage 3B Live Execution Guide

Run this only on the Technical Lead's host, with access to the local PostgreSQL database, the Runtime Host Docker daemon, the mTLS certificates, and the matching Ed25519 key pair. The test performs real database writes and real Runtime Host build/run/cleanup requests; it uses no mocks.

## Important Compose naming and engine check

The current `docker-compose.yml` defines `postgres`, `migrate`, `runtime_host`, and `runtime_host_proxy`. It does **not** define services named `runtime_engine` or `nginx_proxy`. The Runtime Host image installs the Docker CLI but does not start a daemon, and the Compose Runtime Host service has no Docker socket or dind service attached. The command below starts the actual declared services; it does not provision a Docker engine. Do not proceed to the test unless Runtime Host health reports `docker_available: true` from a separately provisioned, isolated Runtime Host daemon.

## Checklist

1. From the repository root, create the local development TLS files and proxy secret if they are not already present:

   ```bash
   bash runtime_host/certs/generate_certs.sh runtime_host/certs
   if [ ! -e runtime_host/certs/proxy_token ]; then
     python -c 'import secrets; print(secrets.token_urlsafe(48))' > runtime_host/certs/proxy_token
     chmod 600 runtime_host/certs/proxy_token
   fi
   ```

2. Generate an Ed25519 job signing pair. Keep the private key on the control-plane host; mount only the public key at `runtime_host/certs/public_key.pem` for the Runtime Host. The signer public key used by this test must match that mounted public key:

   ```bash
   python - <<'PY'
   from pathlib import Path
   from cryptography.hazmat.primitives import serialization
   from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

   client = Path("runtime_host/certs/client")
   client.mkdir(parents=True, exist_ok=True)
   private_path = client / "job_signing_private.pem"
   public_path = Path("runtime_host/certs/public_key.pem")
   if private_path.exists() or public_path.exists():
       raise SystemExit("Refusing to overwrite existing signing key material")
   private_key = Ed25519PrivateKey.generate()
   private_pem = private_key.private_bytes(
       serialization.Encoding.PEM,
       serialization.PrivateFormat.PKCS8,
       serialization.NoEncryption(),
   )
   public_pem = private_key.public_key().public_bytes(
       serialization.Encoding.PEM,
       serialization.PublicFormat.SubjectPublicKeyInfo,
   )
   private_path.write_bytes(private_pem)
   private_path.chmod(0o600)
   public_path.write_bytes(public_pem)
   PY
   ```

3. Set `RUNTIME_HOST_PROXY_TOKEN_SECRET_FILE=./runtime_host/certs/proxy_token` in `.env`, then start the services that actually exist in Compose:

   ```bash
   docker compose up -d postgres migrate runtime_host runtime_host_proxy
   ```

4. Confirm PostgreSQL is ready, the migration job completed, the proxy is listening on loopback port 8443, and a real isolated daemon is available to the Runtime Host. The test fails closed if mTLS, the database, the artifact origin, or Docker health is unavailable.

5. Publish an immutable `.tar.gz` fixture containing a minimal harmless Python or Node application to an HTTPS host. For `raw.githubusercontent.com`, use a 40-character commit SHA in the URL. Configure the exact hostname in `RUNTIME_ARTIFACT_ORIGINS`, and record the archive's SHA-256 digest.

6. Export the live environment values. Adjust PostgreSQL credentials and paths to the generated local files:

   ```bash
   export STAGE_3B_DATABASE_URL='postgresql+psycopg2://sentinelx:sentinelx_dev_pass_change_in_prod@127.0.0.1:5432/sentinelx'
   export RUNTIME_URL='https://127.0.0.1:8443'
   export RUNTIME_CLIENT_CERT="$PWD/runtime_host/certs/client/client.crt"
   export RUNTIME_CLIENT_KEY="$PWD/runtime_host/certs/client/client.key"
   export RUNTIME_CA_CERT="$PWD/runtime_host/certs/client/server_ca.crt"
   export STAGE_3B_AUTH_PRIVATE_KEY_PATH="$PWD/runtime_host/certs/client/job_signing_private.pem"
   export STAGE_3B_AUTH_PUBLIC_KEY_PATH="$PWD/runtime_host/certs/public_key.pem"
   export STAGE_3B_RUNTIME_HOST_PUBLIC_KEY_PATH="$PWD/runtime_host/certs/public_key.pem"
   export RUNTIME_HOST_AUDIENCE='runtime-host'
   export RUNTIME_ARTIFACT_ORIGINS='raw.githubusercontent.com'
   export STAGE_3B_ARTIFACT_URL='https://raw.githubusercontent.com/OWNER/REPOSITORY/40_CHARACTER_COMMIT/path/to/live-fixture.tar.gz'
   export STAGE_3B_ARTIFACT_SHA256='sha256:REPLACE_WITH_64_HEX_DIGEST'
   ```

7. Run the harness from the repository root:

   ```bash
   python -m pytest -v backend/tests/integration/test_live_execution.py
   ```

The test uses the PostgreSQL URL supplied through `STAGE_3B_DATABASE_URL`, inserts and removes its own uniquely named user, project, assessment, worker, and consumed authorization request, submits build/run jobs over the real mTLS client, polls for at most 180 seconds, fetches logs, and sends cleanup in a `finally` block.

## Result handling

A passing test confirms the path exercised by this harness on the configured host. It does not verify other host or production configurations. A failure at the Docker health preflight means the Runtime Host has no reachable daemon. A failure after build/run starts should be treated as a real execution-plane defect; retain the pytest output and inspect the Runtime Host and proxy logs before retrying.
