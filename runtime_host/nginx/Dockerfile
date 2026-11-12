FROM nginx:1.27-bookworm

# Trusted mTLS terminator for the Runtime Host.
# Only Nginx is exposed; the Runtime Host backend has no published port.

ENV NGINX_LISTEN_PORT=8443 \
    NGINX_SERVER_NAME=runtime-host \
    NGINX_SERVER_CERT=/etc/nginx/tls/server.crt \
    NGINX_SERVER_KEY=/etc/nginx/tls/server.key \
    NGINX_CLIENT_CA=/etc/nginx/tls/client_ca.crt \
    NGINX_CLIENT_CRL="" \
    NGINX_REQUIRE_CRL=false \
    NGINX_VERIFY_DEPTH=2 \
    NGINX_RUNTIME_DIR=/etc/nginx/runtime \
    RUNTIME_HOST_PROXY_TOKEN_FILE=/run/secrets/runtime_host_proxy_token \
    NGINX_UPSTREAM=http://runtime_host:8443

COPY nginx.conf /etc/nginx/nginx.conf
COPY templates/ /etc/nginx/templates/
COPY docker-entrypoint.d/40-runtime-host-tls.sh /docker-entrypoint.d/40-runtime-host-tls.sh

# Remove the default plaintext server so only the rendered TLS listener exists.
RUN chmod +x /docker-entrypoint.d/40-runtime-host-tls.sh \
    && rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/runtime

EXPOSE 8443
