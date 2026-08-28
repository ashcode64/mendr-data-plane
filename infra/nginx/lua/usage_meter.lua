-- usage_meter.lua — Edge usage metering (success-path counters → Redis).
-- Control plane /billing/usage and SLO rollups read these keys.
-- Shared-dict increments run in log_by_lua*; Redis writes are deferred to a timer
-- (cosockets are forbidden in the log phase).

local redis = require("resty.redis")
local config = require("config")

local _M = {}

local dict = ngx.shared.mendr_rate_limit

local function redis_connect()
    local red = redis:new()
    red:set_timeouts(100, 100, 100)
    local ok, err = red:connect(config.redis_host(), config.redis_port())
    if not ok then return nil, err end
    return red
end

local function day_bucket()
    return os.date("!%Y%m%d", ngx.time())
end

local function hour_bucket()
    return os.date("!%Y%m%d%H", ngx.time())
end

local function flush_redis(premature, data)
    if premature then return end

    local ok, err = pcall(function()
        local red = redis_connect()
        if not red then return end

        local tenant_id = data.tenant_id
        local target = data.target
        local day = data.day
        local ok_class = data.ok_class
        local bytes = data.bytes
        local prefix = "mendr:usage:" .. tenant_id .. ":"

        red:init_pipeline()
        red:incr(prefix .. "day:" .. day)
        red:expire(prefix .. "day:" .. day, 172800)
        red:incr(prefix .. "day:" .. day .. ":" .. ok_class)
        red:expire(prefix .. "day:" .. day .. ":" .. ok_class, 172800)
        red:hincrby(prefix .. "svc:" .. day, target, 1)
        red:expire(prefix .. "svc:" .. day, 172800)
        if bytes and bytes > 0 then
            red:incrby(prefix .. "bytes:" .. day, bytes)
            red:expire(prefix .. "bytes:" .. day, 172800)
        end
        red:commit_pipeline()
        red:set_keepalive(10000, 50)
    end)

    if not ok then
        ngx.log(ngx.WARN, "usage_meter: redis flush failed: ", err)
    end
end

--- Record one request outcome. Called from log.lua.
function _M.record(tenant_id, target, endpoint, status, bytes, latency_ms)
    if os.getenv("MENDR_USAGE_METERING") == "false" then return end
    tenant_id = tenant_id or "default"
    target = target or "unknown"
    status = tonumber(status) or 0
    local day = day_bucket()
    local hour = hour_bucket()
    local ok_class = (status >= 200 and status < 400) and "ok" or "err"

    -- Shared-dict local rollup (fast; safe in log phase)
    if dict then
        dict:incr("usage:day:" .. tenant_id .. ":" .. day, 1, 0, 172800)
        dict:incr("usage:day:" .. tenant_id .. ":" .. day .. ":" .. ok_class, 1, 0, 172800)
        if latency_ms and latency_ms > 0 then
            dict:incr("usage:lat_sum:" .. tenant_id .. ":" .. hour, math.floor(latency_ms), 0, 7200)
            dict:incr("usage:lat_n:" .. tenant_id .. ":" .. hour, 1, 0, 7200)
        end
    end

    -- Redis distributed (cross-node billing) — deferred out of log phase
    local timer_ok, timer_err = ngx.timer.at(0, flush_redis, {
        tenant_id = tenant_id,
        target = target,
        day = day,
        ok_class = ok_class,
        bytes = bytes,
    })
    if not timer_ok then
        ngx.log(ngx.WARN, "usage_meter: failed to schedule redis flush: ", timer_err)
    end
end

return _M
