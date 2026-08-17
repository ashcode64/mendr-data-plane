-- identity_resolver.lua — Resolve calling service identity for ingress.
-- Primary: X-Mendr-Key as <prefix>.<secret> (mirrors ApiKeyService.authenticate).
-- Fallback: Host → mendr:hostident:{host} when key absent (Phase 6).
-- Defense-in-depth: resolved tenant must match config.tenant_id() when set.
-- Failures are always 401 (or IDENTITY_UNRESOLVED at the caller).

local cjson  = require("cjson.safe")
local config = require("config")
local resty_sha256 = require("resty.sha256")
local str = require("resty.string")

local bitlib
do
    local ok, mod = pcall(require, "bit")
    if ok then
        bitlib = mod
    else
        ok, mod = pcall(require, "bit32")
        if ok then bitlib = mod end
    end
end

local _M = {}

local ok_lrucache, lrucache = pcall(require, "resty.lrucache")
local HIT_CACHE_SIZE = 4096
local NEG_CACHE_SIZE = 512
local HIT_TTL_SEC    = 30
local NEG_TTL_SEC    = 10

local hit_cache, neg_cache, host_cache
if ok_lrucache then
    hit_cache = lrucache.new(HIT_CACHE_SIZE)
    neg_cache = lrucache.new(NEG_CACHE_SIZE)
    host_cache = lrucache.new(512)
end

local function sha256_hex(s)
    local sha = resty_sha256:new()
    if not sha then
        return nil, "sha256 init failed"
    end
    sha:update(s)
    return str.to_hex(sha:final())
end

function _M.constant_time_equals(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then return false end
    if #a ~= #b then return false end
    local diff = 0
    if bitlib then
        for i = 1, #a do
            diff = bitlib.bor(diff, bitlib.bxor(a:byte(i), b:byte(i)))
        end
        return diff == 0
    end
    for i = 1, #a do
        if a:byte(i) ~= b:byte(i) then
            diff = 1
        end
    end
    return diff == 0
end

local function extract_key(headers)
    if not headers then return nil end
    return headers["X-Mendr-Key"] or headers["x-mendr-key"]
end

function _M.split_key(presented)
    if type(presented) ~= "string" or presented == "" then
        return nil, nil, "missing key"
    end
    local rev = presented:reverse()
    local rev_dot = rev:find("%.", 1, true)
    if not rev_dot then
        return nil, nil, "malformed key format"
    end
    local sep = #presented - rev_dot
    if sep <= 0 or sep >= #presented - 1 then
        return nil, nil, "malformed key format"
    end
    local prefix = presented:sub(1, sep)
    local secret = presented:sub(sep + 2)
    if #prefix < 8 or #secret < 16 then
        return nil, nil, "malformed key format"
    end
    return prefix, secret, nil
end

function _M.shape_ok(key)
    local prefix, secret = _M.split_key(key)
    return prefix ~= nil and secret ~= nil
end

function _M.hit_ttl_sec()
    return HIT_TTL_SEC
end

function _M.neg_cache_size()
    return NEG_CACHE_SIZE
end

--- Tenant cross-check against this edge's configured tenant (one-edge-per-tenant).
--- Exported for tests. Returns true when no edge tenant configured, or when match.
function _M.check_tenant(resolved_tenant)
    local expected = config.tenant_id()
    if not expected or expected == "" then
        return true
    end
    if not resolved_tenant or tostring(resolved_tenant) ~= tostring(expected) then
        return false
    end
    return true
end

local function redis_connect()
    local ok, proxy_core = pcall(require, "proxy_core")
    if ok and proxy_core and proxy_core.redis_connect then
        return proxy_core.redis_connect()
    end
    local redis = require("resty.redis")
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000)
    local cok, err = red:connect(config.redis_host(), config.redis_port())
    if not cok then
        return nil, err
    end
    return red
end

local function redis_close(red)
    local ok, proxy_core = pcall(require, "proxy_core")
    if ok and proxy_core and proxy_core.redis_close then
        return proxy_core.redis_close(red)
    end
    red:set_keepalive(10000, 100)
end

local function finish(source, tenant)
    if not _M.check_tenant(tenant) then
        ngx.log(ngx.CRIT, "identity_resolver: TENANT MISMATCH — key/host resolved to tenant ",
            tostring(tenant), " but this edge is configured for ", tostring(config.tenant_id()))
        return nil, nil, "tenant mismatch"
    end
    return source, tenant, nil
end

local function resolve_by_key(key)
    local prefix, secret, serr = _M.split_key(key)
    if not prefix then
        return nil, nil, serr or "malformed X-Mendr-Key"
    end

    local presented_hash, herr = sha256_hex(secret)
    if not presented_hash then
        return nil, nil, herr or "hash failed"
    end

    if hit_cache then
        local cached = hit_cache:get(prefix)
        if cached then
            if not _M.constant_time_equals(presented_hash, cached.key_hash) then
                return nil, nil, "secret mismatch"
            end
            if type(cached.scopes) == "table" then
                ngx.ctx.api_key_scopes = cached.scopes
            end
            return finish(cached.source, cached.tenant)
        end
        if neg_cache and neg_cache:get(prefix) then
            return nil, nil, "unknown X-Mendr-Key"
        end
    end

    local red, rerr = redis_connect()
    if not red then
        ngx.log(ngx.WARN, "identity_resolver: redis unavailable: ", rerr)
        return nil, nil, "identity lookup unavailable"
    end

    local raw, get_err = red:get("mendr:apikey:" .. prefix)
    redis_close(red)

    if get_err then
        ngx.log(ngx.WARN, "identity_resolver: GET failed: ", get_err)
        return nil, nil, "identity lookup unavailable"
    end

    if not raw or raw == ngx.null then
        if neg_cache then
            neg_cache:set(prefix, true, NEG_TTL_SEC)
        end
        return nil, nil, "unknown X-Mendr-Key"
    end

    local record, decode_err = cjson.decode(raw)
    if not record or type(record) ~= "table"
       or not record.keyHash or not record.sourceService then
        ngx.log(ngx.WARN, "identity_resolver: bad apikey record: ", decode_err)
        if neg_cache then
            neg_cache:set(prefix, true, NEG_TTL_SEC)
        end
        return nil, nil, "identity record invalid"
    end

    if record.revokedAt then
        if neg_cache then
            neg_cache:set(prefix, true, NEG_TTL_SEC)
        end
        return nil, nil, "revoked or expired"
    end
    if record.expiresAt and tonumber(record.expiresAt)
       and tonumber(record.expiresAt) < ngx.time() then
        if neg_cache then
            neg_cache:set(prefix, true, NEG_TTL_SEC)
        end
        return nil, nil, "revoked or expired"
    end

    if hit_cache then
        hit_cache:set(prefix, {
            key_hash = record.keyHash,
            source   = record.sourceService,
            tenant   = record.tenantId or record.tenant,
            scopes   = record.scopes,
        }, HIT_TTL_SEC)
    end

    if not _M.constant_time_equals(presented_hash, record.keyHash) then
        return nil, nil, "secret mismatch"
    end

    if type(record.scopes) == "table" then
        ngx.ctx.api_key_scopes = record.scopes
    elseif type(record.scopes) == "string" then
        local decoded = cjson.decode(record.scopes)
        ngx.ctx.api_key_scopes = type(decoded) == "table" and decoded or {}
    end

    return finish(record.sourceService, (record.tenantId or record.tenant))
end

--- Public: verify presented API key (prefix.secret) against synced Redis projection.
function _M.resolve_by_api_key(presented)
    return resolve_by_key(presented)
end

--- Host → {sourceService, tenantId} from synced mendr:hostident:{host}.
function _M.resolve_by_host(host)
    if not host or host == "" then
        return nil, nil, "missing host"
    end
    host = string.lower(host)

    if host_cache then
        local cached = host_cache:get(host)
        if cached == false then
            return nil, nil, "unknown host identity"
        end
        if cached then
            return finish(cached.source, cached.tenant)
        end
    end

    local red, rerr = redis_connect()
    if not red then
        ngx.log(ngx.WARN, "identity_resolver: redis unavailable (host): ", rerr)
        return nil, nil, "identity lookup unavailable"
    end

    local raw, get_err = red:get("mendr:hostident:" .. host)
    redis_close(red)
    if get_err then
        return nil, nil, "identity lookup unavailable"
    end
    if not raw or raw == ngx.null then
        if host_cache then
            host_cache:set(host, false, NEG_TTL_SEC)
        end
        return nil, nil, "unknown host identity"
    end

    local record = cjson.decode(raw)
    if not record or not record.sourceService then
        if host_cache then
            host_cache:set(host, false, NEG_TTL_SEC)
        end
        return nil, nil, "malformed host identity"
    end

    local tenant = record.tenantId or record.tenant or config.tenant_id()
    if host_cache then
        host_cache:set(host, { source = record.sourceService, tenant = tenant }, HIT_TTL_SEC)
    end
    return finish(record.sourceService, tenant)
end

--- Resolve inbound identity. Order: X-Mendr-Key → Host (when fallback enabled).
--- opts.host optional (defaults to ngx.var.host when available).
function _M.resolve(headers, opts)
    opts = opts or {}
    local key = extract_key(headers)
    if key and key ~= "" then
        return resolve_by_key(key)
    end

    if config.host_identity_fallback_enabled() then
        local host = opts.host
        if (not host or host == "") and ngx and ngx.var then
            host = ngx.var.host
        end
        if host and host ~= "" then
            return _M.resolve_by_host(host)
        end
    end

    return nil, nil, "missing X-Mendr-Key"
end

function _M.set_www_authenticate()
    ngx.header["WWW-Authenticate"] = 'MendrKey realm="mendr", charset="UTF-8"'
end

return _M
