FROM openresty/openresty:alpine-fat

# log.lua async POSTs to Java control plane (/api/internal/failures, /api/internal/validate-response)
RUN opm get ledgetech/lua-resty-http

EXPOSE 8080
CMD ["openresty", "-g", "daemon off;"]
