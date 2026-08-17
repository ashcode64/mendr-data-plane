-- response_cache.lua — GET/HEAD response cache: shared dict L1 + Redis L2.

local cjson = require("cjson.safe")
local redis = require("resty.redis")
local config = require("config")

local _M = {}

local dict = ngx.shared.mendr_response_cache

local function cache_key(route_config, method)
    local vary = ""
    local policy = route_config.cachePolicy or {}
    if type(policy.varyHeaders) == "table" then
        local headers = ngx.req.get_headers()
        local parts = {}
        for _, h in ipairs(policy.varyHeaders) do
            parts[#parts + 1] = tostring(headers[h] or headers[string.lower(h)] or "")
        end
        vary = table.concat(parts, "|")
    end
    return "rc:" .. tostring(route_config.targetService) .. ":"
        .. tostring(route_config.endpoint) .. ":" .. method .. ":" .. ngx.var.request_uri
        .. ":" .. vary
end

local function redis_connect()
    local red = redis:new()
    red:set_timeouts(100, 100, 100)
    local ok, err = red:connect(config.redis_host(), config.redis_port())
    if not ok then return nil, err end
    return red
end

function _M.should_cache(route_config, method)
    local policy = route_config and route_config.cachePolicy
    if type(policy) ~= "table" or not policy.enabled then return false end
    method = (method or "GET"):upper()
    local methods = policy.methods or { "GET", "HEAD" }
    for _, m in ipairs(methods) do
        if tostring(m):upper() == method then return true end
    end
    return false
end

function _M.get(route_config, method)
    if not _M.should_cache(route_config, method) then return nil end
    local key = cache_key(route_config, method)
    if dict then
        local raw = dict:get(key)
        if raw then
            return cjson.decode(raw)
        end
    end
    -- Redis L2
    local red = redis_connect()
    if red then
        local raw = red:get("mendr:" .. key)
        red:set_keepalive(10000, 50)
        if raw and raw ~= ngx.null then
            if dict then
                local policy = route_config.cachePolicy
                local ttl = tonumber(policy and policy.ttlSeconds) or 60
                dict:set(key, raw, math.min(ttl, 30))
            end
            return cjson.decode(raw)
        end
    end
    return nil
end

function _M.put(route_config, method, status, body, content_type)
    if not _M.should_cache(route_config, method) then return end
    if status < 200 or status >= 300 then return end
    local policy = route_config.cachePolicy
    local ttl = tonumber(policy.ttlSeconds) or 60
    if ttl <= 0 then return end
    local body_str = body
    if type(body) == "table" then
        body_str = cjson.encode(body)
        if not body_str then return end
    elseif type(body) ~= "string" then
        body_str = tostring(body)
    end
    local entry = cjson.encode({
        status = status,
        body = body_str,
        content_type = content_type or "application/json",
    })
    if not entry then return end
    local key = cache_key(route_config, method)
    if dict then
        dict:set(key, entry, ttl)
    end
    local red = redis_connect()
    if red then
        red:setex("mendr:" .. key, ttl, entry)
        red:set_keepalive(10000, 50)
    end
end

function _M.invalidate_all()
    if dict then dict:flush_all() end
    -- Redis: best-effort scan delete of mendr:rc:*
    local red = redis_connect()
    if not red then return end
    local cursor = "0"
    for _ = 1, 20 do
        local res = red:scan(cursor, "MATCH", "mendr:rc:*", "COUNT", 100)
        if type(res) ~= "table" then break end
        cursor = tostring(res[1] or "0")
        for _, k in ipairs(res[2] or {}) do
            red:del(k)
        end
        if cursor == "0" then break end
    end
    red:set_keepalive(10000, 50)
end

return _M
