-- edge_policy.lua — Shared WAF / auth / rate-limit enforcement for non-proxy entry points.

local rate_limit = require("rate_limit")
local auth_jwt = require("auth_jwt")
local waf = require("waf")

local _M = {}

--- Enforce edge policies. Returns ok, http_status, message
function _M.enforce(route_config, ctx)
    ctx = ctx or {}
    if not rate_limit.abuse_allow() then
        return false, 429, "Too many requests"
    end
    if type(route_config) == "table" then
        local ok_w, werr = waf.inspect(route_config, ctx)
        if not ok_w then
            return false, 403, werr or "Blocked by WAF"
        end
        local ok_a, aerr = auth_jwt.enforce(route_config)
        if not ok_a then
            return false, 401, aerr or "Unauthorized"
        end
        local ok_rl, retry_after = rate_limit.allow(route_config, ctx)
        if not ok_rl then
            if retry_after then
                ngx.header["Retry-After"] = tostring(retry_after)
            end
            return false, 429, "Rate limit exceeded"
        end
    else
        local ok_w, werr = waf.inspect(nil, ctx)
        if not ok_w then
            return false, 403, werr or "Blocked by WAF"
        end
    end
    return true
end

return _M
