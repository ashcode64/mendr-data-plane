#!/bin/sh
# Gate :443 / ACME server on MENDR_ACME_ENABLED. Without this flag, OpenResty
# only listens on :80/:8080 (no self-signed HTTPS dangling on 443).

set -e
mkdir -p /etc/nginx/conf.d
rm -f /etc/nginx/conf.d/https-acme.conf

case "${MENDR_ACME_ENABLED:-}" in
  true|1|TRUE|True)
    if [ -f /etc/nginx/https-acme.conf ]; then
      cp /etc/nginx/https-acme.conf /etc/nginx/conf.d/https-acme.conf
      echo "acme: enabled — HTTPS server installed on :443"
    else
      echo "acme: MENDR_ACME_ENABLED set but /etc/nginx/https-acme.conf missing" >&2
    fi
    ;;
  *)
    echo "acme: disabled — :443 not listening (set MENDR_ACME_ENABLED=true to enable)"
    ;;
esac

exec "$@"
