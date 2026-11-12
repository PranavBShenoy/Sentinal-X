#!/usr/bin/env bash
# Generate mTLS certificates for the Runtime Host.
#
# Output layout (never mount the ca/ directory into a container):
#   ca/client_ca.crt, ca/client_ca.key   Trust anchor for worker/client certs.
#   ca/server_ca.crt, ca/server_ca.key   Trust anchor for the proxy server cert.
#   server/server.crt, server/server.key Proxy TLS identity.
#   server/client_ca.crt                 Public client CA for the proxy/backend.
#   client/client.crt, client/client.key Control-plane mTLS identity.
#   client/server_ca.crt                 Public server CA for the control plane.
#
# Production should use a proper CA/HSM instead of this script. The private
# CA keys must remain offline and must never be mounted into any container.
#
# Usage: generate_certs.sh [--force] [OUTPUT_DIR]
# Default OUTPUT_DIR: ./runtime-host-certs
set -euo pipefail

FORCE=0
if [ "${1:-}" = "--force" ]; then
    FORCE=1
    shift
fi
OUT_DIR="${1:-./runtime-host-certs}"

CA_DIR="$OUT_DIR/ca"
SERVER_DIR="$OUT_DIR/server"
CLIENT_DIR="$OUT_DIR/client"
CRL_DIR="$OUT_DIR/crl"

if [ "$FORCE" -ne 1 ]; then
    for existing in \
        "$CA_DIR/client_ca.key" "$CA_DIR/client_ca.crt" \
        "$CA_DIR/server_ca.key" "$CA_DIR/server_ca.crt" \
        "$SERVER_DIR/server.key" "$SERVER_DIR/server.crt" \
        "$CLIENT_DIR/client.key" "$CLIENT_DIR/client.crt"
    do
        if [ -e "$existing" ]; then
            echo "Refusing to overwrite existing certificate material: $existing" >&2
            echo "Move it aside or pass --force if you are rotating certificates." >&2
            exit 1
        fi
    done
fi

umask 077
mkdir -p "$CA_DIR" "$SERVER_DIR" "$CLIENT_DIR" "$CRL_DIR"
chmod 700 "$CA_DIR"
chmod 755 "$SERVER_DIR" "$CLIENT_DIR" "$CRL_DIR"

gen_ca() {
    name="$1"
    common_name="$2"
    echo "Generating $name CA..."
    openssl genrsa -out "$CA_DIR/$name.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "$CA_DIR/$name.key" -sha256 -days 3650 \
        -subj "/CN=$common_name" \
        -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -addext "subjectKeyIdentifier=hash" \
        -out "$CA_DIR/$name.crt" 2>/dev/null
    chmod 600 "$CA_DIR/$name.key"
    chmod 644 "$CA_DIR/$name.crt"
}

gen_ca client_ca "SENTINEL-X Runtime Client CA"
gen_ca server_ca "SENTINEL-X Runtime Server CA"

echo "Generating server key and certificate..."
openssl genrsa -out "$SERVER_DIR/server.key" 2048 2>/dev/null
openssl req -new -key "$SERVER_DIR/server.key" \
    -subj "/CN=runtime-host" -out "$SERVER_DIR/server.csr" 2>/dev/null

cat > "$SERVER_DIR/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:runtime-host,DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -in "$SERVER_DIR/server.csr" \
    -CA "$CA_DIR/server_ca.crt" -CAkey "$CA_DIR/server_ca.key" \
    -CAcreateserial -out "$SERVER_DIR/server.crt" -days 825 -sha256 \
    -extfile "$SERVER_DIR/server.ext" 2>/dev/null

echo "Generating client key and certificate..."
openssl genrsa -out "$CLIENT_DIR/client.key" 2048 2>/dev/null
openssl req -new -key "$CLIENT_DIR/client.key" \
    -subj "/CN=sentinelx-control-plane" -out "$CLIENT_DIR/client.csr" 2>/dev/null

cat > "$CLIENT_DIR/client.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

openssl x509 -req -in "$CLIENT_DIR/client.csr" \
    -CA "$CA_DIR/client_ca.crt" -CAkey "$CA_DIR/client_ca.key" \
    -CAcreateserial -out "$CLIENT_DIR/client.crt" -days 825 -sha256 \
    -extfile "$CLIENT_DIR/client.ext" 2>/dev/null

# Publish only the public trust anchors alongside the leaf material.
cp "$CA_DIR/client_ca.crt" "$SERVER_DIR/client_ca.crt"
cp "$CA_DIR/server_ca.crt" "$CLIENT_DIR/server_ca.crt"
chmod 644 "$SERVER_DIR/client_ca.crt" "$CLIENT_DIR/server_ca.crt"

# Clean up intermediates that are not needed at runtime.
rm -f "$SERVER_DIR/server.csr" "$SERVER_DIR/server.ext"
rm -f "$CLIENT_DIR/client.csr" "$CLIENT_DIR/client.ext"
rm -f "$CA_DIR"/*.srl

chmod 600 "$SERVER_DIR/server.key" "$CLIENT_DIR/client.key"
chmod 644 "$SERVER_DIR/server.crt" "$CLIENT_DIR/client.crt"

cat <<EOF
Certificates generated in $OUT_DIR

  CA (keep offline, never mount ca/):
    ca/client_ca.crt / ca/client_ca.key
    ca/server_ca.crt / ca/server_ca.key

  Proxy (mount individual files):
    server/server.crt
    server/server.key
    server/client_ca.crt

  Control plane (keep client.key private):
    client/client.crt
    client/client.key
    client/server_ca.crt

  CRL directory (optional):
    crl/

The Runtime Host also requires an Ed25519 public verification key at
RUNTIME_HOST_PUBLIC_KEY_PATH. It is produced by the control plane, not here.
EOF
