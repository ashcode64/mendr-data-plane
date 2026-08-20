-- ingress_routing.lua — Per-host radixtree (or linear fallback) for transparent ingress.
-- Rebuild into a local tree, validate, atomic-swap module-level reference only on success.
-- Nil tree (never built) → caller must Java-fallback or 503; stale tree keeps serving.

local cjson  = require("cjson.safe")
local redis  = require("resty.redis")
local config = require("config")

local _M = {}

-- Module-level last-known-good state (Envoy "keep last known good config").
local trees_by_host = {}          -- host → radixtree (or linear table)
local trees_by_pair = {}          -- "source:target" → radixtree/linear of endpoint templates
local last_successful_build_at = 0
local last_sync_version = nil
local STALE_ALERT_SEC = 3600      -- alert if no successful rebuild for 1h

local ok_radix, radixtree = pcall(require, "resty.radixtree")
if not ok_radix then
    ngx.log(ngx.WARN, "ingress_routing: lua-resty-radixtree not available, using linear matcher")
    radixtree = nil
end

local function redis_connect()
    local ok, proxy_core = pcall(require, "proxy_core")
    if ok and proxy_core and proxy_core.redis_connect then
        return proxy_core.redis_connect()
    end
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000)
    local cok, err = red:connect(config.redis_host(), config.redis_port())
    if not cok then return nil, err end
    return red
end

local function redis_close(red)
    local ok, proxy_core = pcall(require, "proxy_core")
    if ok and proxy_core and proxy_core.redis_close then
        return proxy_core.redis_close(red)
    end
    red:set_keepalive(10000, 100)
end

-- Convert OpenAPI/Mendr "{id}" templates to radixtree ":id" style.
local function to_radix_path(path)
    if not path then return path end
    return path:gsub("{([^}]+)}", ":%1")
end

local function from_radix_path(path)
    if not path then return path end
    return path:gsub(":([%w_]+)", "{%1}")
end

-- Linear fallback matcher (most-specific-first), used when radixtree is unavailable.
local function build_linear(routes)
    local entries = {}
    for _, r in ipairs(routes) do
        local path = r.path or r.endpoint
        local method = (r.method or "*"):upper()
        local tmpl = path
        local pattern = "^" .. path:gsub("([%-%.%+%[%]%(%)%$%^%%%?%*])", "%%%1")
            :gsub("{[^}]+}", "[^/]+") .. "$"
        local specificity = 0
        for seg in path:gmatch("[^/]+") do
            if not seg:find("{", 1, true) then
                specificity = specificity + 10
            else
                specificity = specificity + 1
            end
        end
        table.insert(entries, {
            path = path,
            method = method,
            pattern = pattern,
            specificity = specificity,
            priority = tonumber(r.priority) or 0,
            target = r.targetService or r.target,
            endpoint_template = r.endpointTemplate or r.endpoint or path,
            enforce = r.enforce or "observe",
        })
    end
    table.sort(entries, function(a, b)
        if a.priority ~= b.priority then return a.priority > b.priority end
        return a.specificity > b.specificity
    end)
    return { kind = "linear", entries = entries }
end

local function build_radixtree(routes)
    local radix_routes = {}
    for _, r in ipairs(routes) do
        local path = to_radix_path(r.path or r.endpoint)
        local methods = r.methods
        if not methods then
            local m = (r.method or "GET"):upper()
            if m == "*" then
                methods = nil  -- match all methods
            else
                methods = { m }
            end
        elseif type(methods) == "string" then
            if methods == "*" then
                methods = nil
            else
                methods = { methods }
            end
        end
        local entry = {
            paths = { path },
            priority = tonumber(r.priority) or 0,
            metadata = {
                target = r.targetService or r.target,
                endpoint_template = r.endpointTemplate or from_radix_path(path),
                enforce = r.enforce or "observe",
            },
        }
        if methods then
            entry.methods = methods
        end
        table.insert(radix_routes, entry)
    end
    local rx = radixtree.new(radix_routes)
    return { kind = "radix", tree = rx }
end

local function match_linear(table_obj, method, uri)
    method = (method or "GET"):upper()
    for _, e in ipairs(table_obj.entries) do
        if (e.method == "*" or e.method == method) and uri:match(e.pattern) then
            return e.target, e.endpoint_template, e.enforce
        end
    end
    return nil
end

local function match_radix(table_obj, method, uri)
    local opts = { method = (method or "GET"):upper(), matched = {} }
    local meta = table_obj.tree:match(uri, opts)
    if not meta then return nil end
    return meta.target, meta.endpoint_template, meta.enforce
end

function _M.get_last_sync_version()
    return last_sync_version
end

--- Explicitly set (or clear) the worker-local sync version. Used by sync_client
--- to roll back after a pair-rebuild failure so worker 0 keeps retrying pairs
--- even though shared last_version was bumped for other workers.
function _M.set_last_sync_version(version)
    last_sync_version = version
end

--- Lazy catch-up: compare shared last_version to this worker's trees; reload from Redis on mismatch.
--- Uses an atomic shared-dict lock so N workers do not rebuild the same payload concurrently.
function _M.ensure_fresh()
    local sync_dict = ngx.shared.mendr_sync_state
    if not sync_dict then
        return true
    end
    local shared = tostring(sync_dict:get("last_version") or "0")
    local local_v = tostring(last_sync_version or "")
    if shared == local_v then
        return true
    end
    -- Version "0" with empty local is cold-start before first sync — nothing to load yet.
    if shared == "0" and (last_sync_version == nil or last_sync_version == "") then
        return true
    end

    local function try_reload_under_lock()
        local ok_lock, err_lock = sync_dict:add("ingress:rebuild_lock", 1, 5)
        if not ok_lock then
            return false, err_lock
        end
        -- Re-check under lock (another worker may have finished).
        local shared_now = tostring(sync_dict:get("last_version") or "0")
        if shared_now ~= tostring(last_sync_version or "") then
            local ok_reload, reload_err = _M.reload_from_redis(shared_now)
            if not ok_reload then
                ngx.log(ngx.WARN, "ingress_routing: ensure_fresh reload failed (keeping LKG): ",
                    tostring(reload_err))
                -- Do not advance last_sync_version — retry next request.
            end
        end
        sync_dict:delete("ingress:rebuild_lock")
        return true, nil
    end

    local ok_lock, err_lock = try_reload_under_lock()
    if ok_lock then
        return true
    end

    -- Loser: brief wait for winner, then one immediate reload attempt once the
    -- lock clears (reduces cold-worker NO_TREE on the same request).
    for _ = 1, 5 do
        ngx.sleep(0.01)
        if tostring(last_sync_version or "") == tostring(sync_dict:get("last_version") or "0") then
            return true
        end
        if not sync_dict:get("ingress:rebuild_lock") then
            break
        end
    end
    if tostring(last_sync_version or "") ~= tostring(sync_dict:get("last_version") or "0") then
        local ok_retry = try_reload_under_lock()
        if ok_retry then
            return true
        end
    end
    if err_lock and err_lock ~= "exists" then
        ngx.log(ngx.WARN, "ingress_routing: ensure_fresh lock: ", tostring(err_lock))
    end
    -- Still stale: serve LKG for this request (do not block indefinitely).
    return true
end

--- Match host + method + concrete path → targetService, endpointTemplate, enforce, err
function _M.match(host, method, uri)
    _M.ensure_fresh()

    if not host or host == "" then
        return nil, nil, nil, "missing host"
    end

    local table_obj = trees_by_host[host]
    if not table_obj then
        -- Try wildcard / default host table
        table_obj = trees_by_host["*"] or trees_by_host["default"]
    end

    if not table_obj then
        return nil, nil, nil, "NO_TREE"
    end

    local target, tmpl, enforce
    if table_obj.kind == "radix" then
        target, tmpl, enforce = match_radix(table_obj, method, uri)
    else
        target, tmpl, enforce = match_linear(table_obj, method, uri)
    end

    if not target then
        return nil, nil, nil, "NO_MATCH"
    end
    return target, tmpl, enforce or "observe", nil
end

--- Envelope-path template resolution: match concrete endpoint against templates
--- for a (source, target) pair. Returns the canonical endpoint template or nil.
function _M.match_pair(source_service, target_service, concrete_endpoint)
    _M.ensure_fresh()

    if not source_service or not target_service or not concrete_endpoint then
        return nil
    end
    local pair_key = source_service .. ":" .. target_service
    local table_obj = trees_by_pair[pair_key]
    if not table_obj then
        return nil
    end

    if table_obj.kind == "radix" then
        local opts = { matched = {} }
        local meta = table_obj.tree:match(concrete_endpoint, opts)
        if meta and meta.endpoint_template then
            return meta.endpoint_template
        end
        return nil
    end

    -- linear: only templated entries (exact was already tried via Redis GET)
    for _, e in ipairs(table_obj.entries) do
        if e.path and e.path:find("{", 1, true) then
            local ok = pcall(function()
                return concrete_endpoint:match(e.pattern)
            end)
            if ok and concrete_endpoint:match(e.pattern) then
                return e.endpoint_template or e.path
            end
        end
    end
    return nil
end

--- Rebuild pair trees from routeconfig key map:
--- keys like "mendr:routeconfig:src:tgt:/users/{id}" (or bare without prefix).
--- Atomic swap only on full success (last-known-good on failure).
function _M.rebuild_pairs_from_route_keys(routes_map, sync_version)
    if type(routes_map) ~= "table" then
        return false, "routes_map is not a table"
    end

    local by_pair = {}  -- "src:tgt" → list of {path=endpointTemplate}
    for key, _ in pairs(routes_map) do
        if type(key) == "string" then
            local rest = key
            local prefix = "mendr:routeconfig:"
            if rest:sub(1, #prefix) == prefix then
                rest = rest:sub(#prefix + 1)
            end
            -- rest = source:target:endpoint (endpoint may contain ':')
            local source, target, endpoint = rest:match("^([^:]+):([^:]+):(.+)$")
            if source and target and endpoint and endpoint:find("{", 1, true) then
                local pk = source .. ":" .. target
                by_pair[pk] = by_pair[pk] or {}
                table.insert(by_pair[pk], {
                    path = endpoint,
                    endpoint = endpoint,
                    endpointTemplate = endpoint,
                    method = "*",
                    targetService = target,
                    priority = 0,
                })
            end
        end
    end

    local new_trees = {}
    for pk, routes in pairs(by_pair) do
        local ok, built = pcall(function()
            if radixtree then
                return build_radixtree(routes)
            end
            return build_linear(routes)
        end)
        if not ok or not built then
            return false, "failed to build pair tree for " .. pk .. ": " .. tostring(built)
        end
        new_trees[pk] = built
    end

    trees_by_pair = new_trees
    ngx.log(ngx.INFO, "ingress_routing: rebuilt pair trees for ",
        tostring((function()
            local n = 0
            for _ in pairs(new_trees) do n = n + 1 end
            return n
        end)()),
        " source:target pair(s), version=", tostring(sync_version))
    return true
end

--- Pure fallthrough classification (unit-testable; no ngx).
--- Returns: "NO_TREE" | "SHADOW_ROUTE_ACCESSED" | "NO_MATCH"
function _M.classify_fallthrough(err_code, enforce)
    if err_code == "NO_TREE" then
        return "NO_TREE"
    end
    local mode = tostring(enforce or "observe"):lower()
    if mode == "observe" or mode == "shadow" or mode == "learning" then
        return "SHADOW_ROUTE_ACCESSED"
    end
    return "NO_MATCH"
end

--- Fallthrough when no route matches.
--- opts.enforce: observe|shadow|learning → SHADOW_ROUTE_ACCESSED (log + metric hook);
---                strict|enforcing → hard NO_MATCH.
--- Both still fail-closed at the HTTP layer (ingress returns 404); never invent a target.
function _M.handle_fallthrough(tenant, source_service, err_code, opts)
    opts = opts or {}
    local action = _M.classify_fallthrough(err_code, opts.enforce)
    if action == "SHADOW_ROUTE_ACCESSED" then
        ngx.log(ngx.INFO, "ingress_routing: SHADOW_ROUTE_ACCESSED tenant=",
            tostring(tenant), " source=", tostring(source_service),
            " method=", tostring(opts.method), " uri=", tostring(opts.uri))
    end
    return action
end

function _M.last_successful_build_at()
    return last_successful_build_at
end

function _M.is_stale(threshold_sec)
    if last_successful_build_at == 0 then return true end
    return (ngx.time() - last_successful_build_at) > (threshold_sec or STALE_ALERT_SEC)
end

--- Rebuild trees from a host→routes map. Atomic swap only on full success.
--- routes_by_host: { ["api.example.com"] = { {path, method, targetService, endpointTemplate, ...}, ... }, ... }
function _M.rebuild(routes_by_host, sync_version)
    if type(routes_by_host) ~= "table" then
        return false, "routes_by_host is not a table"
    end

    local new_trees = {}
    for host, routes in pairs(routes_by_host) do
        if type(host) == "string" and type(routes) == "table" then
            local ok, built = pcall(function()
                if radixtree then
                    return build_radixtree(routes)
                end
                return build_linear(routes)
            end)
            if not ok or not built then
                return false, "failed to build tree for host " .. host .. ": " .. tostring(built)
            end
            new_trees[host] = built
        end
    end

    -- Atomic swap of the whole map
    trees_by_host = new_trees
    last_successful_build_at = ngx.time()
    last_sync_version = sync_version
    ngx.log(ngx.INFO, "ingress_routing: rebuilt trees for ",
        tostring((function()
            local n = 0
            for _ in pairs(new_trees) do n = n + 1 end
            return n
        end)()),
        " host(s), version=", tostring(sync_version))
    return true
end

local function load_pair_keys_map(red)
    local raw = red:get("mendr:ingress:pair_keys")
    if not raw or raw == ngx.null then
        return nil
    end
    local keys, derr = cjson.decode(raw)
    if type(keys) ~= "table" then
        ngx.log(ngx.WARN, "ingress_routing: bad mendr:ingress:pair_keys: ", tostring(derr))
        return nil
    end
    local routes_map = {}
    for _, k in ipairs(keys) do
        if type(k) == "string" then
            routes_map[k] = true
        end
    end
    return routes_map
end

--- Fallback when mendr:ingress:pair_keys is absent (e.g. an edge upgraded before
--- the first post-upgrade sync wrote the index). Scans routeconfig keys directly
--- so envelope pair trees can still be rebuilt. KEYS is O(N) but this path is
--- rare (only until the next sync writes pair_keys).
local function scan_routeconfig_pair_keys(red)
    local keys = red:keys("mendr:routeconfig:*")
    if not keys or keys == ngx.null then
        return nil
    end
    local routes_map = {}
    for _, k in ipairs(keys) do
        if type(k) == "string" and k:find("mendr:routeconfig:", 1, true) then
            routes_map[k] = true
        end
    end
    if next(routes_map) == nil then
        return nil
    end
    return routes_map
end

--- Load ingress table(s) from Redis key mendr:ingress:{host} (JSON routes array)
--- or mendr:ingress:tables (JSON map host→routes). Also reloads pair trees from
--- mendr:ingress:pair_keys (or a routeconfig SCAN fallback when that index is
--- missing). Called after sync apply and from ensure_fresh.
function _M.reload_from_redis(sync_version)
    local red, err = redis_connect()
    if not red then
        return false, err
    end

    local pair_map = load_pair_keys_map(red)
    if not pair_map then
        -- pair_keys index missing (pre-first-sync upgrade): scan routeconfig keys.
        pair_map = scan_routeconfig_pair_keys(red)
    end

    -- Capture pre-rebuild version so a later pair failure can roll it back.
    -- Host trees may still be swapped (newer hosts + LKG pairs is safe); we
    -- must not advance last_sync_version or envelope catch-up stops forever.
    local prev_version = last_sync_version

    local raw = red:get("mendr:ingress:tables")
    local host_ok, host_err
    if raw and raw ~= ngx.null then
        local tables, derr = cjson.decode(raw)
        if not tables then
            redis_close(red)
            return false, "decode mendr:ingress:tables failed: " .. tostring(derr)
        end
        host_ok, host_err = _M.rebuild(tables, sync_version)
    else
        -- Fallback: scan individual host keys (dev / small deployments)
        local keys = red:keys("mendr:ingress:*")
        local tables = {}
        if keys and keys ~= ngx.null then
            for _, key in ipairs(keys) do
                if key ~= "mendr:ingress:tables" and key ~= "mendr:ingress:pair_keys"
                    and type(key) == "string" and key:sub(1, #"mendr:ingress:") == "mendr:ingress:" then
                    local host = key:sub(#"mendr:ingress:" + 1)
                    if host ~= "pair_keys" and host ~= "tables" then
                        local v = red:get(key)
                        if v and v ~= ngx.null then
                            local routes = cjson.decode(v)
                            if type(routes) == "table" then
                                tables[host] = routes
                            end
                        end
                    end
                end
            end
        end
        if next(tables) == nil then
            host_ok, host_err = _M.rebuild({}, sync_version)
        else
            host_ok, host_err = _M.rebuild(tables, sync_version)
        end
    end

    if not host_ok then
        redis_close(red)
        return false, host_err
    end

    if pair_map then
        local ok_pairs, pairs_err = _M.rebuild_pairs_from_route_keys(pair_map, sync_version)
        if not ok_pairs then
            -- Roll back version so the next ensure_fresh retries pair rebuild.
            last_sync_version = prev_version
            ngx.log(ngx.WARN, "ingress_routing: pair reload failed (keeping LKG pairs; version not advanced): ",
                tostring(pairs_err))
            redis_close(red)
            return false, "pair reload failed: " .. tostring(pairs_err)
        end
    end

    redis_close(red)
    return true
end

return _M
