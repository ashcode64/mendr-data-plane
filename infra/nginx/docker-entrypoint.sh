#!/bin/sh
# Gate optional HTTPS listeners:
#   MENDR_ACME_ENABLED  → ACME HTTPS :443
#   MENDR_MTLS_ENABLED  → mTLS HTTPS :443 (takes precedence over ACME if both set)
#   MENDR_HTTP3_ENABLED → HTTP/3 QUIC :443 (validated with nginx -t; soft-fail)

set -e
mkdir -p /etc/nginx/conf.d /etc/nginx/mtls /etc/nginx/waf/rules
rm -f /etc/nginx/conf.d/https-acme.conf /etc/nginx/conf.d/https-mtls.conf /etc/nginx/conf.d/https-http3.conf

# Ensure mTLS placeholder certs exist so proxy_ssl_* directives don't break nginx -t
# when mTLS server is not installed but files are referenced elsewhere.
if [ ! -f /etc/nginx/mtls/client-ca.crt ]; then
  if [ -n "${MENDR_MTLS_CLIENT_CA:-}" ] && [ -f "${MENDR_MTLS_CLIENT_CA}" ]; then
    cp "${MENDR_MTLS_CLIENT_CA}" /etc/nginx/mtls/client-ca.crt
  else
    cp /etc/nginx/acme/fallback.crt /etc/nginx/mtls/client-ca.crt
  fi
fi
for f in upstream-client.crt upstream-ca.crt; do
  if [ ! -f "/etc/nginx/mtls/$f" ]; then
    cp /etc/nginx/acme/fallback.crt "/etc/nginx/mtls/$f"
  fi
done
if [ ! -f /etc/nginx/mtls/upstream-client.key ]; then
  if [ -n "${MENDR_UPSTREAM_MTLS_KEY:-}" ] && [ -f "${MENDR_UPSTREAM_MTLS_KEY}" ]; then
    cp "${MENDR_UPSTREAM_MTLS_KEY}" /etc/nginx/mtls/upstream-client.key
  else
    cp /etc/nginx/acme/fallback.key /etc/nginx/mtls/upstream-client.key
  fi
fi
if [ -n "${MENDR_UPSTREAM_MTLS_CERT:-}" ] && [ -f "${MENDR_UPSTREAM_MTLS_CERT}" ]; then
  cp "${MENDR_UPSTREAM_MTLS_CERT}" /etc/nginx/mtls/upstream-client.crt
fi
if [ -n "${MENDR_UPSTREAM_MTLS_CA:-}" ] && [ -f "${MENDR_UPSTREAM_MTLS_CA}" ]; then
  cp "${MENDR_UPSTREAM_MTLS_CA}" /etc/nginx/mtls/upstream-ca.crt
fi

HTTPS_INSTALLED=0

case "${MENDR_MTLS_ENABLED:-}" in
  true|1|TRUE|True)
    if [ -f /etc/nginx/https-mtls.conf ]; then
      cp /etc/nginx/https-mtls.conf /etc/nginx/conf.d/https-mtls.conf
      echo "mtls: enabled — client-cert HTTPS on :443"
      HTTPS_INSTALLED=1
    fi
    ;;
esac

if [ "$HTTPS_INSTALLED" = "0" ]; then
  case "${MENDR_HTTP3_ENABLED:-}" in
    true|1|TRUE|True)
      if [ -f /etc/nginx/https-http3.conf ]; then
        cp /etc/nginx/https-http3.conf /etc/nginx/conf.d/https-http3.conf
        if openresty -t 2>/tmp/mendr-nginx-t.log; then
          echo "http3: enabled — QUIC/HTTPS on :443"
          HTTPS_INSTALLED=1
        else
          echo "http3: binary lacks QUIC support — falling back (see /tmp/mendr-nginx-t.log)" >&2
          rm -f /etc/nginx/conf.d/https-http3.conf
        fi
      fi
      ;;
  esac
fi

if [ "$HTTPS_INSTALLED" = "0" ]; then
  case "${MENDR_ACME_ENABLED:-}" in
    true|1|TRUE|True)
      if [ -f /etc/nginx/https-acme.conf ]; then
        cp /etc/nginx/https-acme.conf /etc/nginx/conf.d/https-acme.conf
        echo "acme: enabled — HTTPS server installed on :443"
        HTTPS_INSTALLED=1
      else
        echo "acme: MENDR_ACME_ENABLED set but /etc/nginx/https-acme.conf missing" >&2
      fi
      ;;
    *)
      echo "https: disabled — :443 not listening (set MENDR_ACME_ENABLED / MENDR_MTLS_ENABLED / MENDR_HTTP3_ENABLED)"
      ;;
  esac
fi

# WAF mode banner
echo "waf: mode=${MENDR_WAF_MODE:-detect} coraza=${MENDR_WAF_CORAZA:-false} bot=${MENDR_BOT_MODE:-off}"
echo "otel: enabled=${MENDR_OTEL_ENABLED:-false}"
echo "upstream-http2-ready: ${MENDR_UPSTREAM_HTTP2:-false} (proxy_pass=HTTP/1.1 keepalive; grpc_pass=HTTP/2)"
echo "usage-metering: ${MENDR_USAGE_METERING:-true}"

# Optional brotli (only if module loaded in this OpenResty build)
case "${MENDR_BROTLI_ENABLED:-}" in
  true|1|TRUE|True)
    cat > /etc/nginx/conf.d/brotli.conf <<'EOF'
# Soft-installed when MENDR_BROTLI_ENABLED=true; removed if nginx -t fails.
brotli on;
brotli_comp_level 5;
brotli_types text/plain text/css application/json application/javascript application/xml;
EOF
    if ! openresty -t 2>/tmp/mendr-brotli-t.log; then
      echo "brotli: module unavailable — disabling" >&2
      rm -f /etc/nginx/conf.d/brotli.conf
    else
      echo "brotli: enabled"
    fi
    ;;
esac

exec "$@"
