FROM openresty/openresty:alpine-fat

# log.lua async POSTs to Java control plane (/api/internal/failures, /api/internal/validate-response)
RUN opm get ledgetech/lua-resty-http

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY proxy-control.conf /etc/nginx/proxy-control.conf
COPY lua/ /etc/nginx/lua/

EXPOSE 8080
CMD ["openresty", "-g", "daemon off;"]
