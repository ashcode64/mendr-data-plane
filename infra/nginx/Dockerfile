FROM openresty/openresty:alpine-fat

# Hot-path HTTP client (sync, log, JWKS, OTel)
RUN opm get ledgetech/lua-resty-http

# Transparent ingress routing
RUN opm get api7/lua-resty-radixtree || true

# TLS / ACME
RUN opm get fffonion/lua-resty-openssl || true
RUN opm get fffonion/lua-resty-acme || true

# Production JWT / OIDC (JWKS crypto verify)
RUN opm get cdbattags/lua-resty-jwt || true
RUN opm get bungle/lua-resty-session || true
RUN opm get zmartzone/lua-resty-openidc || true

# Optional Coraza WAF binding (requires libcoraza at runtime — soft-fail)
RUN opm get potats0/lua-resty-coraza || true

# CA bundle + fallback certs + WAF rule directory + mTLS CA placeholder
RUN apk add --no-cache ca-certificates openssl curl \
    && mkdir -p /etc/nginx/acme /etc/nginx/conf.d /etc/nginx/waf /etc/nginx/mtls \
    && printf '%s\n' '# placeholder so include /etc/nginx/conf.d/*.conf always matches' \
         > /etc/nginx/conf.d/00-placeholder.conf \
    && openssl req -x509 -newkey rsa:2048 -nodes \
         -keyout /etc/nginx/acme/fallback.key \
         -out /etc/nginx/acme/fallback.crt \
         -days 3650 -subj "/CN=mendr-edge-fallback" \
    && openssl genrsa -out /etc/nginx/acme/account.key 2048 \
    && update-ca-certificates

# OWASP CRS–compatible Coraza baseline (used when MENDR_WAF_CORAZA=true)
COPY waf/coraza.conf /etc/nginx/waf/coraza.conf
COPY waf/crs-setup.conf /etc/nginx/waf/crs-setup.conf
COPY waf/rules/ /etc/nginx/waf/rules/

COPY https-acme.conf /etc/nginx/https-acme.conf
COPY https-mtls.conf /etc/nginx/https-mtls.conf
COPY https-http3.conf /etc/nginx/https-http3.conf
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80 443 8080
# HTTP/3 QUIC uses UDP/443 when enabled
EXPOSE 443/udp
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["openresty", "-g", "daemon off;"]
