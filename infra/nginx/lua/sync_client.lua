-- sync_client.lua — Long-poll route-config sync from control plane into edge Redis.
-- One non-overlapping loop per worker 0; immediate sync on worker start.

local cjson  = require("cjson.safe")
local http   = require("resty.http")
local redis  = require("resty.redis")
local config = require("config")

local sync_dict = ngx.shared.mendr_sync_state

local POLL_TIMEOUT_MS   = 35000  -- control plane holds up to 30s
local ERROR_BACKOFF_SEC = 5
local FULL_RESYNC_KEY   = "last_full_resync_at"

-- Capabilities this edge advertises to the control plane (Gap 10). "v2" means this
-- build runs the closed-opcode MendrScript interpreter (snapshot v2 `ops[]`). The
-- control plane withholds v2-only (DSL) routes from edges that do NOT advertise it,
-- rather than shipping a snapshot the edge would silently no-op.
-- "v2" = MendrScript closed-opcode interpreter; "ingress" = transparent HTTP
-- ingress + radixtree routing tables. Control plane withholds features the edge
-- does not advertise.
local EDGE_CAPS = "v2,ingress,traffic,ratelimit,authz,cache,metrics,ai,waf,splice"

local function redis_connect()
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000)
    local ok, err = red:connect(config.redis_host(), config.redis_port())
    if not ok then
        return nil, "redis connect failed: " .. (err or "unknown")
    end
    return red
end

local function redis_close(red)
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        ngx.log(ngx.WARN, "sync_client: redis set_keepalive failed: ", err)
    end
end

local function apply_sync_payload(payload)
    if type(payload) ~= "table" then
        return false, "payload is not a table"
    end

    local version = payload.version
    if version == nil then
        return false, "payload missing version"
    end

    local red, err = redis_connect()
    if not red then
        return false, err
    end

    local routes = payload.routes
    if type(routes) == "table" then
        for key, value in pairs(routes) do
            if type(key) == "string" and type(value) == "string" then
                local ok_set, set_err = red:set(key, value)
                if not ok_set then
                    redis_close(red)
                    return false, "redis SET " .. key .. " failed: " .. (set_err or "unknown")
                end
            end
        end
    end

    local removed = payload.removed
    if type(removed) == "table" then
        for _, key in ipairs(removed) do
            if type(key) == "string" then
                red:del(key)
            end
        end
    end

    -- Ingress tables: apply BEFORE bumping last_version so the radixtree and
    -- routeconfig snapshots stay atomic on the same sync version.
    local ingress_tables = payload.ingressTables
    if type(ingress_tables) == "table" then
        local encoded = cjson.encode(ingress_tables)
        if encoded then
            local ok_set, set_err = red:set("mendr:ingress:tables", encoded)
            if not ok_set then
                redis_close(red)
                return false, "redis SET mendr:ingress:tables failed: " .. (set_err or "unknown")
            end
        end
    end

    -- Ingress API keys (prefix → {keyHash, sourceService, tenantId, ...})
    local api_keys = payload.apiKeys
    if type(api_keys) == "table" then
        for key, value in pairs(api_keys) do
            if type(key) == "string" and type(value) == "string" then
                red:set(key, value)
            end
        end
    end

    -- Host identity fallback (host → {sourceService, tenantId})
    local host_ident = payload.hostIdentity
    if type(host_ident) == "table" then
        for key, value in pairs(host_ident) do
            if type(key) == "string" and type(value) == "string" then
                red:set(key, value)
            end
        end
    end

    -- AI gateway routes (virtual_path → policy JSON)
    local ai_routes = payload.aiRoutes
    if type(ai_routes) == "table" then
        for key, value in pairs(ai_routes) do
            if type(key) == "string" and type(value) == "string" then
                red:set(key, value)
            end
        end
    end

    redis_close(red)

    -- Rebuild radixtrees from the just-written tables + route keys
    -- (last-known-good on failure).
    local ok_req, ingress_rt = pcall(require, "ingress_routing")
    if ok_req and ingress_rt then
        if type(ingress_tables) == "table" then
            local ok_rebuild, rebuild_err = ingress_rt.rebuild(ingress_tables, version)
            if not ok_rebuild then
                ngx.log(ngx.WARN, "sync_client: ingress radixtree rebuild failed (keeping last-known-good): ",
                    tostring(rebuild_err))
            end
        end
        -- Pair trees for envelope-path template lookup (retire KEYS scan).
        if type(routes) == "table" then
            local ok_pairs, pairs_err = ingress_rt.rebuild_pairs_from_route_keys(routes, version)
            if not ok_pairs then
                ngx.log(ngx.WARN, "sync_client: pair radixtree rebuild failed (keeping last-known-good): ",
                    tostring(pairs_err))
            end
        end
    end

    sync_dict:set("last_version", tostring(version))
    -- Invalidate response/semantic cache on route sync so stale HIT bodies cannot linger
    local ok_rc, response_cache = pcall(require, "response_cache")
    if ok_rc and response_cache and response_cache.invalidate_all then
        pcall(response_cache.invalidate_all)
    end
    ngx.log(ngx.INFO, "sync_client: applied routeconfig sync version ", version)
    return true
end

local function schedule_poll(delay_sec)
    local ok, err = ngx.timer.at(delay_sec or 0, function(premature)
        if premature then
            return
        end

        local last_version = sync_dict:get("last_version") or "0"
        local pending_full_resync = false
        local full_interval = config.full_resync_interval_sec()
        if full_interval > 0 then
            local now = ngx.time()
            local last_full = tonumber(sync_dict:get(FULL_RESYNC_KEY) or "0") or 0
            if now - last_full >= full_interval then
                last_version = "0"
                pending_full_resync = true
                ngx.log(ngx.INFO, "sync_client: forcing periodic full resync (interval=", full_interval, "s)")
            end
        end

        local url = config.control_plane_base()
            .. "/v1/sync/routeconfig?since=" .. ngx.escape_uri(last_version)
            .. "&caps=" .. ngx.escape_uri(EDGE_CAPS)

        local httpc = http.new()
        httpc:set_timeout(POLL_TIMEOUT_MS)

        local headers = { ["Accept"] = "application/json" }
        -- Per-tenant edge credential (SaaS): the control plane resolves the tenant
        -- from this key and scopes the sync payload to that tenant. Preferred.
        local edge_key = config.edge_api_key()
        if edge_key then
            headers["X-Api-Key"] = edge_key
        end
        -- Optional defense-in-depth cross-check; the key remains authoritative.
        local tenant = config.tenant_id()
        if tenant then
            headers["X-Tenant-Id"] = tenant
        end
        -- Shared internal key kept for backward compatibility during rollout (used
        -- by legacy/single-tenant edges that have no per-tenant key yet).
        local api_key = config.internal_api_key()
        if api_key then
            headers["X-Internal-Api-Key"] = api_key
        end

        local res, req_err = httpc:request_uri(url, {
            method  = "GET",
            headers = headers,
        })

        if not res then
            ngx.log(ngx.WARN, "sync_client: GET ", url, " failed: ", req_err)
            schedule_poll(ERROR_BACKOFF_SEC)
            return
        end

        if res.status == 200 then
            local payload, decode_err = cjson.decode(res.body)
            if not payload then
                ngx.log(ngx.WARN, "sync_client: invalid JSON body: ", decode_err or "unknown")
                schedule_poll(ERROR_BACKOFF_SEC)
                return
            end

            local ok_apply, apply_err = apply_sync_payload(payload)
            if not ok_apply then
                ngx.log(ngx.WARN, "sync_client: apply failed: ", apply_err)
                schedule_poll(ERROR_BACKOFF_SEC)
                return
            end

            if pending_full_resync then
                sync_dict:set(FULL_RESYNC_KEY, tostring(ngx.time()))
            end

            schedule_poll(0)
            return
        end

        if res.status == 304 then
            schedule_poll(0)
            return
        end

        ngx.log(ngx.WARN, "sync_client: GET ", url, " returned ", res.status)
        schedule_poll(ERROR_BACKOFF_SEC)
    end)

    if not ok then
        ngx.log(ngx.ERR, "sync_client: failed to schedule poll: ", err)
    end
end

local _M = {}

function _M.start()
    if ngx.worker.id() ~= 0 then
        return
    end

    schedule_poll(0)
    ngx.log(ngx.INFO, "sync_client: started routeconfig sync loop")
end

return _M
