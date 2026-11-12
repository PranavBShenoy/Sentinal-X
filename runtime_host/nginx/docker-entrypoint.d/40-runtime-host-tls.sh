#!/bin/sh
# Runtime Host mTLS proxy startup validation.
#
# Runs after the official nginx image has rendered templates and before nginx
# starts. Fails closed when required TLS material or the proxy token is
# missing, unreadable, or invalid.
#
# The proxy token is read from a protected file (Docker secret) when
# RUNTIME_HOST_PROXY_TOKEN_FILE is set, otherwise from RUNTIME_HOST_PROXY_TOKEN.
# It is written to a mode-0600 include file instead of the served config.
set -eu

RUNTIME_DIR="${NGINX_RUNTIME_DIR:-/etc/nginx/runtime}"

fail() {
    echo "runtime-host-proxy: $*" >&2
    exit 1
}

require_readable() {
    name="$1"
    path="$2"
    if [ -z "$path" ] || [ ! -r "$path" ]; then
        fail "$name is missing or unreadable: $path"
    fi
}

require_readable "NGINX_SERVER_CERT" "${NGINX_SERVER_CERT:-}"
require_readable "NGINX_SERVER_KEY" "${NGINX_SERVER_KEY:-}"
require_readable "NGINX_CLIENT_CA" "${NGINX_CLIENT_CA:-}"

# Validate that the mounted material is parseable before handing it to nginx.
openssl x509 -in "$NGINX_SERVER_CERT" -noout >/dev/null 2>&1 \
    || fail "NGINX_SERVER_CERT is not a valid certificate"
openssl x509 -in "$NGINX_CLIENT_CA" -noout >/dev/null 2>&1 \
    || fail "NGINX_CLIENT_CA is not a valid certificate"
openssl pkey -in "$NGINX_SERVER_KEY" -noout >/dev/null 2>&1 \
    || fail "NGINX_SERVER_KEY is not a valid private key"

TOKEN_FILE="${RUNTIME_HOST_PROXY_TOKEN_FILE:-}"
if [ -n "$TOKEN_FILE" ]; then
    require_readable "RUNTIME_HOST_PROXY_TOKEN_FILE" "$TOKEN_FILE"
    PROXY_TOKEN=$(cat "$TOKEN_FILE")
else
    PROXY_TOKEN="${RUNTIME_HOST_PROXY_TOKEN:-}"
fi

if [ -z "$PROXY_TOKEN" ]; then
    fail "RUNTIME_HOST_PROXY_TOKEN or RUNTIME_HOST_PROXY_TOKEN_FILE is required"
fi
if [ "${#PROXY_TOKEN}" -lt 32 ]; then
    fail "RUNTIME_HOST_PROXY_TOKEN must be at least 32 characters"
fi
case "$PROXY_TOKEN" in
    *[!A-Za-z0-9_-]*)
        fail "RUNTIME_HOST_PROXY_TOKEN may contain only A-Z, a-z, 0-9, '_' and '-'"
        ;;
esac
UPPER_TOKEN=$(printf '%s' "$PROXY_TOKEN" | tr '[:lower:]' '[:upper:]')
case "$UPPER_TOKEN" in
    *CHANGE_ME*|*CHANGEME*|*REPLACE_ME*|*PLACEHOLDER*)
        fail "RUNTIME_HOST_PROXY_TOKEN must not contain a placeholder value"
        ;;
esac

umask 077
mkdir -p "$RUNTIME_DIR"
chmod 700 "$RUNTIME_DIR"
rm -f "$RUNTIME_DIR/crl"*.conf "$RUNTIME_DIR/token.conf"

TOKEN_TMP="$RUNTIME_DIR/token.conf.tmp.$$"
printf 'set $runtime_proxy_token "%s";\n' "$PROXY_TOKEN" > "$TOKEN_TMP"
chmod 600 "$TOKEN_TMP"
mv "$TOKEN_TMP" "$RUNTIME_DIR/token.conf"

if [ -n "${NGINX_CLIENT_CRL:-}" ]; then
    require_readable "NGINX_CLIENT_CRL" "${NGINX_CLIENT_CRL}"
    openssl crl -in "$NGINX_CLIENT_CRL" -noout >/dev/null 2>&1 \
        || fail "NGINX_CLIENT_CRL is not a valid CRL"
    printf 'ssl_crl %s;\n' "${NGINX_CLIENT_CRL}" > "$RUNTIME_DIR/crl.conf"
    chmod 600 "$RUNTIME_DIR/crl.conf"
elif [ "${NGINX_REQUIRE_CRL:-false}" = "true" ]; then
    fail "NGINX_REQUIRE_CRL=true but NGINX_CLIENT_CRL is not set"
fi

# Validate the fully rendered configuration before nginx starts.
nginx -t
