-- circuit_breaker.lua — Passive passive circuit breaker with single-flight half-open.

local _M = {}

local dict = ngx.shared.mendr_circuit_breaker

local function cfg(cb)
    cb = cb or {}
    return {
        failure_threshold = tonumber(cb.failureThreshold) or 5,
        success_threshold = tonumber(cb.successThreshold) or 2,
        open_seconds = tonumber(cb.openSeconds) or 30,
        window_seconds = tonumber(cb.windowSeconds) or 60,
    }
end

local function state_key(url) return "cb:state:" .. url end
local function fail_key(url) return "cb:fail:" .. url end
local function ok_key(url) return "cb:ok:" .. url end
local function open_until_key(url) return "cb:until:" .. url end
local function probe_key(url) return "cb:probe:" .. url end

--- Returns is_open, is_half_open_available
function _M.is_open(base_url, cb_cfg)
    if not dict or not base_url then return false, false end
    local until_ts = tonumber(dict:get(open_until_key(base_url)) or "0") or 0
    if until_ts > ngx.time() then
        return true, false
    end
    if until_ts > 0 and until_ts <= ngx.time() then
        -- Expired open → eligible for half-open if no probe in flight
        return false, true
    end
    return false, false
end

--- Atomically claim the single half-open probe slot (returns true if this worker owns it).
function _M.try_half_open_probe(base_url, cb_cfg)
    if not dict or not base_url then return false end
    local c = cfg(cb_cfg)
    local until_ts = tonumber(dict:get(open_until_key(base_url)) or "0") or 0
    if until_ts > ngx.time() then
        return false  -- still fully open
    end
    if until_ts <= 0 then
        return true  -- closed
    end
    -- try set probe key with short TTL (only first worker succeeds with add)
    local ok, err, forcible = dict:add(probe_key(base_url), 1, 5)
    if ok then
        dict:set(state_key(base_url), "half_open")
        return true
    end
    return false
end

function _M.record_failure(base_url, cb_cfg)
    if not dict or not base_url then return end
    local c = cfg(cb_cfg)
    dict:delete(probe_key(base_url))
    local fails = dict:incr(fail_key(base_url), 1, 0, c.window_seconds) or 1
    if fails >= c.failure_threshold then
        dict:set(open_until_key(base_url), ngx.time() + c.open_seconds)
        dict:set(state_key(base_url), "open")
        dict:set(fail_key(base_url), 0)
        ngx.log(ngx.WARN, "circuit_breaker: OPEN for ", base_url, " after ", fails, " failures")
    end
end

function _M.record_success(base_url, cb_cfg)
    if not dict or not base_url then return end
    local c = cfg(cb_cfg)
    dict:delete(probe_key(base_url))
    local state = dict:get(state_key(base_url))
    if state == "half_open" or state == "open" then
        local oks = dict:incr(ok_key(base_url), 1, 0, c.window_seconds) or 1
        if oks >= c.success_threshold then
            dict:delete(open_until_key(base_url))
            dict:set(state_key(base_url), "closed")
            dict:set(fail_key(base_url), 0)
            dict:set(ok_key(base_url), 0)
            ngx.log(ngx.INFO, "circuit_breaker: CLOSED for ", base_url)
        end
    else
        dict:set(fail_key(base_url), 0)
    end
end

return _M
