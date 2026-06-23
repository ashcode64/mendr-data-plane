-- dedup.lua — Shared deduplication helper
-- Uses ngx.shared.dedup_cache to rate-limit fire-and-forget reports

local _M = {}

local shared = ngx.shared.dedup_cache

--- Check whether a category+route combination should be processed.
-- Returns true the first time it is called within `window_secs`, false
-- for all subsequent calls until the key expires.
--
-- @param category   string  e.g. "fail" or "validate"
-- @param source     string  sourceService name
-- @param target     string  targetService name
-- @param endpoint   string  request endpoint
-- @param window_secs number  dedup window in seconds (default 60)
-- @return boolean
function _M.should_process(category, source, target, endpoint, window_secs)
    local key = category .. ":" .. source .. ":" .. target .. ":" .. endpoint
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
