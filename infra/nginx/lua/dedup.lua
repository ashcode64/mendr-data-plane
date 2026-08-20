-- dedup.lua — Shared deduplication helper
-- Uses ngx.shared.dedup_cache to rate-limit fire-and-forget reports.
-- Commit uses dict:add (atomic) to avoid TOCTOU double-sends across workers.

local _M = {}

local shared = ngx.shared and ngx.shared.dedup_cache

local function key_of(category, source, target, endpoint, class)
    local base = category .. ":" .. source .. ":" .. target .. ":" .. endpoint
    if class and class ~= "" then
        return base .. ":" .. class
    end
    return base
end

local function suppressed_key(key)
    return "suppressed:" .. key
end

--- Non-mutating look at whether the window is open. Safe to call from
-- header_filter when deciding whether to retain a response body.
-- Returns true when the key is absent (would process) or when the dict
-- is unavailable (fail-open: assume we need the body).
-- @param class optional failure class (e.g. SCHEMA_MISMATCH) for fail keys
function _M.peek(category, source, target, endpoint, window_secs, class)
    if not shared then
        return true
    end
    local existing = shared:get(key_of(category, source, target, endpoint, class))
    return existing == nil
end

--- Check whether a category+route(+class) combination should be processed.
-- Returns true the first time it is called within `window_secs`, false
-- for all subsequent calls until the key expires. Commits via atomic add.
--
-- @param category   string  e.g. "fail" or "validate"
-- @param source     string  sourceService name
-- @param target     string  targetService name
-- @param endpoint   string  request endpoint (prefer template)
-- @param window_secs number  dedup window in seconds (default 60)
-- @param class      string|nil  failure class for fail keys (e.g. "SPLICE")
-- @return boolean, number|nil  should_process, suppressed_count (when true)
function _M.should_process(category, source, target, endpoint, window_secs, class)
    if not shared then
        return true, 0
    end
    local ttl = window_secs or 60
    local key = key_of(category, source, target, endpoint, class)
    local ok, err = shared:add(key, true, ttl)
    if ok then
        local sk = suppressed_key(key)
        local suppressed = tonumber(shared:get(sk)) or 0
        shared:delete(sk)
        return true, suppressed
    end
    if err == "exists" then
        shared:incr(suppressed_key(key), 1, 0, ttl)
        return false, nil
    end
    ngx.log(ngx.WARN, "dedup: failed to add key ", key, ": ", tostring(err))
    -- Allow processing even if dedup tracking fails
    return true, 0
end

return _M
