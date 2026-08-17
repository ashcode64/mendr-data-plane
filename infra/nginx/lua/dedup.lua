-- dedup.lua — Shared deduplication helper
-- Uses ngx.shared.dedup_cache to rate-limit fire-and-forget reports

local _M = {}

local shared = ngx.shared and ngx.shared.dedup_cache

local function key_of(category, source, target, endpoint)
    return category .. ":" .. source .. ":" .. target .. ":" .. endpoint
end

--- Non-mutating look at whether the window is open. Safe to call from
-- header_filter when deciding whether to retain a response body.
-- Returns true when the key is absent (would process) or when the dict
-- is unavailable (fail-open: assume we need the body).
function _M.peek(category, source, target, endpoint, window_secs)
    if not shared then
        return true
    end
    local existing = shared:get(key_of(category, source, target, endpoint))
    return existing == nil
end

--- Check whether a category+route combination should be processed.
-- Returns true the first time it is called within `window_secs`, false
-- for all subsequent calls until the key expires. Commits the window.
--
-- @param category   string  e.g. "fail" or "validate"
-- @param source     string  sourceService name
-- @param target     string  targetService name
-- @param endpoint   string  request endpoint
-- @param window_secs number  dedup window in seconds (default 60)
-- @return boolean
function _M.should_process(category, source, target, endpoint, window_secs)
    if not shared then
        return true
    end
    local key = key_of(category, source, target, endpoint)
    local existing = shared:get(key)
    if existing then
        return false
    end
    -- safe_set avoids errors when the shared dict is full (evicts LRU)
    local ok, err, forcible = shared:set(key, true, window_secs or 60)
    if not ok then
        ngx.log(ngx.WARN, "dedup: failed to set key ", key, ": ", err)
        -- Allow processing even if dedup tracking fails
        return true
    end
    if forcible then
        ngx.log(ngx.WARN, "dedup: evicted existing key(s) to store ", key)
    end
    return true
end

return _M
