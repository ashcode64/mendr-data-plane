FROM openresty/openresty:alpine-fat

# log.lua async POSTs to Java control plane (/api/internal/failures, /api/internal/validate-response)
RUN opm get ledgetech/lua-resty-http

# Transparent ingress routing (O(K) radix tree; falls back to linear matcher if missing)
RUN opm get api7/lua-resty-radixtree || true

# In-edge ACME / Let's Encrypt (HTTP-01). Soft-fail if opm unavailable offline.
RUN opm get fffonion/lua-resty-openssl || true
RUN opm get fffonion/lua-resty-acme || true

# CA bundle for outbound ACME API TLS + fallback self-signed certs for :443 boot
RUN apk add --no-cache ca-certificates openssl \
    && mkdir -p /etc/nginx/acme /etc/nginx/conf.d \
    && printf '%s\n' '# placeholder so include /etc/nginx/conf.d/*.conf always matches' \
         > /etc/nginx/conf.d/00-placeholder.conf \
    && openssl req -x509 -newkey rsa:2048 -nodes \
         -keyout /etc/nginx/acme/fallback.key \
         -out /etc/nginx/acme/fallback.crt \
         -days 3650 -subj "/CN=mendr-edge-fallback" \
    && openssl genrsa -out /etc/nginx/acme/account.key 2048 \
    && update-ca-certificates

COPY https-acme.conf /etc/nginx/https-acme.conf
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80 443 8080
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["openresty", "-g", "daemon off;"]
