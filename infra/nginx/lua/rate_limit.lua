-- rate_limit.lua — Production rate limiting:
--   1) Edge-local abuse limit (per IP) — always applied from proxy_core
--   2) Route rateLimitPolicy (sliding window / token bucket) via shared dict + Redis
--   3) Tenant quota_rpm / quota_rpd from snapshot.tenantQuota

local redis = require("resty.redis")
local config = require("config")

local _M = {}

local dict = ngx.shared.mendr_rate_limit

local function window_key(bucket, window_sec)
    local slot = math.floor(ngx.time() / window_sec)
    return "rl:" .. bucket .. ":" .. slot
end

local function redis_connect()
    local red = redis:new()
    red:set_timeouts(200, 200, 200)
    local ok, err = red:connect(config.redis_host(), config.redis_port())
    if not ok then return nil, err end
    return red
end

--- Distributed fixed-window incr via Redis; falls back to shared dict.
local function incr(bucket, amount, window_sec, limit)
    amount = amount or 1
    local k = window_key(bucket, window_sec)
    local red = redis_connect()
    if red then
        local n = red:incrby(k, amount)
        if n == amount then
            red:expire(k, window_sec + 1)
        end
        red:set_keepalive(10000, 50)
        n = tonumber(n) or amount
        return n <= limit, n
    end
    if not dict then return true, 0 end
    local n = dict:incr(k, amount, 0, window_sec + 1) or amount
    return n <= limit, n
end

--- Token-bucket using shared dict (local) with optional Redis sync of tokens.
--- Stores "tokens:last_ms" as two keys; refill by elapsed time * rate.
local function token_bucket_allow(bucket, rate_per_sec, burst)
    rate_per_sec = tonumber(rate_per_sec) or 0
    burst = tonumber(burst) or rate_per_sec
    if rate_per_sec <= 0 then return true end
    if burst < rate_per_sec then burst = rate_per_sec end

    local tokens_key = "tb:tok:" .. bucket
    local ts_key = "tb:ts:" .. bucket
    local now_ms = ngx.now() * 1000

    -- Prefer shared dict for low latency; Redis for cross-worker consistency of counters
    if dict then
        local last = tonumber(dict:get(ts_key) or "0") or 0
        local tokens = tonumber(dict:get(tokens_key) or tostring(burst)) or burst
        if last > 0 and now_ms > last then
            local elapsed = (now_ms - last) / 1000
            tokens = math.min(burst, tokens + elapsed * rate_per_sec)
        end
        if tokens < 1 then
            dict:set(ts_key, now_ms, 120)
            dict:set(tokens_key, tokens, 120)
            return false, 1
        end
        tokens = tokens - 1
        dict:set(ts_key, now_ms, 120)
        dict:set(tokens_key, tokens, 120)
        return true, math.floor(tokens)
    end

    return incr(bucket, 1, 1, math.ceil(rate_per_sec) + burst)
end

local function tenant_quota_allow(route_config)
    local q = route_config and route_config.tenantQuota
    if type(q) ~= "table" then return true end
    local tenant = q.tenantId or ngx.ctx.tenant_id or "default"
    local rpm = tonumber(q.quotaRpm or q.quota_rpm)
    local rpd = tonumber(q.quotaRpd or q.quota_rpd)
    if rpm and rpm > 0 then
        local ok = incr("tq:rpm:" .. tenant, 1, 60, rpm)
        if not ok then
            ngx.header["Retry-After"] = "60"
            return false, 60, "tenant_quota_rpm"
        end
    end
    if rpd and rpd > 0 then
        local ok = incr("tq:rpd:" .. tenant, 1, 86400, rpd)
        if not ok then
            ngx.header["Retry-After"] = "3600"
            return false, 3600, "tenant_quota_rpd"
        end
    end
    return true
end

--- Returns ok, err_or_retry_after [, reason]
function _M.allow(route_config, opts)
    opts = opts or {}

    -- Always enforce abuse layer first
    local abuse_max = tonumber(os.getenv("MENDR_ABUSE_RPS")) or 100
    if not _M.abuse_allow(abuse_max) then
        ngx.header["Retry-After"] = "1"
        return false, 1, "abuse"
    end

    local ok_q, retry_q, reason_q = tenant_quota_allow(route_config)
    if not ok_q then
        return false, retry_q, reason_q
    end

    local policy = route_config and route_config.rateLimitPolicy
    if type(policy) ~= "table" then
        return true
    end

    local rpm = tonumber(policy.requestsPerMinute)
    local rps = tonumber(policy.requestsPerSecond)
    local burst = tonumber(policy.burst) or 0
    if not rpm and not rps then
        return true
    end

    local key_by = tostring(policy.keyBy or "ip"):lower()
    local ident
    if key_by == "consumer" then
        ident = opts.consumer or ngx.req.get_headers()["X-Api-Key"] or ngx.var.remote_addr
    elseif key_by == "route" then
        ident = tostring(route_config.targetService or "") .. ":" .. tostring(route_config.endpoint or "")
    else
        ident = ngx.var.remote_addr or "unknown"
    end
    if policy.consumerKey and policy.consumerKey ~= "" then
        ident = ident .. ":" .. policy.consumerKey
    end

    local algo = tostring(policy.algorithm or "SLIDING_WINDOW"):upper()
    if algo == "TOKEN_BUCKET" and rps and rps > 0 then
        local ok, rem = token_bucket_allow("pol:" .. ident, rps, burst > 0 and burst or (rps * 2))
        if not ok then
            ngx.header["Retry-After"] = "1"
            ngx.header["RateLimit-Limit"] = tostring(math.ceil(rps))
            ngx.header["RateLimit-Remaining"] = "0"
            return false, 1
        end
        ngx.header["RateLimit-Limit"] = tostring(math.ceil(rps))
        ngx.header["RateLimit-Remaining"] = tostring(math.max(0, rem or 0))
        return true
    end

    local limit, window
    if rps and rps > 0 then
        limit = math.ceil(rps) + burst
        window = 1
    else
        limit = (rpm or 60) + burst
        window = 60
    end

    local ok, n = incr("pol:" .. ident, 1, window, limit)
    if not ok then
        ngx.header["Retry-After"] = tostring(window)
        ngx.header["RateLimit-Limit"] = tostring(limit)
        ngx.header["RateLimit-Remaining"] = "0"
        return false, window
    end

    ngx.header["RateLimit-Limit"] = tostring(limit)
    ngx.header["RateLimit-Remaining"] = tostring(math.max(0, limit - n))
    return true
end

--- Coarse abuse limit independent of control-plane policy (per IP / second).
function _M.abuse_allow(max_per_sec)
    if not dict and not redis_connect() then return true end
    max_per_sec = tonumber(max_per_sec) or 100
    local ok = incr("abuse:" .. (ngx.var.remote_addr or "x"), 1, 1, max_per_sec)
    return ok
end

return _M
