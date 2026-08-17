-- grpc_access.lua — Policy hooks for gRPC / gRPC-Web locations before grpc_pass.

local edge_policy = require("edge_policy")

local route_config = ngx.ctx.routeConfig
local ok, status, message = edge_policy.enforce(route_config, {
    raw_body = "",
})
if not ok then
    ngx.status = status
    ngx.header["Content-Type"] = "text/plain"
    ngx.say(message or "Request blocked")
    return ngx.exit(status)
end
