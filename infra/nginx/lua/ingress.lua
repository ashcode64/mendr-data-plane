-- ingress.lua — Transparent HTTP ingress front-end.
-- Order: identity (key → host) → radixtree match → THEN read body → proxy_core.run(ctx).
-- Hybrid large-body: JSON spill → 413; non-JSON spill → nginx passthrough.
-- Fail-closed 404 on no match; 401 on identity failure; 503 if no tree.

local cjson          = require("cjson.safe")
local proxy_core     = require("proxy_core")
local identity       = require("identity_resolver")
local ingress_rt     = require("ingress_routing")
local config         = require("config")

local BODYLESS = { GET = true, HEAD = true, DELETE = true, OPTIONS = true }

local function is_json_ct(headers)
    local ct = headers and (headers["Content-Type"] or headers["content-type"]) or ""
    return type(ct) == "string" and ct:lower():find("application/json", 1, true) ~= nil
end

--- Returns: raw_body|nil, has_body, body_spilled, is_json, err_table|nil
local function read_body_for_ingress(headers)
    ngx.req.read_body()
    local body_data = ngx.req.get_body_data()
    local body_file = ngx.req.get_body_file()
    local json = is_json_ct(headers)

    -- Spilled to temp file and not fully in memory
    if body_file and (not body_data or body_data == "") then
        if json then
            return nil, false, false, false, {
                status = 413,
                code = "PAYLOAD_TOO_LARGE",
                message = "Request body exceeds buffered size limit; JSON decode/transform of spilled bodies is not supported",
            }
        end
        -- Non-JSON: leave nginx temp-file buffer alone — do not load into Lua.
        return nil, true, true, false, nil
    end

    if body_data and body_data ~= "" then
        return body_data, true, false, json, nil
    end

    return nil, false, false, false, nil
end

-- Optional TLS-required gate for public ingress (when terminated in this process).
if config.tls_required() and not ngx.var.https and ngx.var.scheme ~= "https" then
    -- Allow ACME HTTP-01 challenges through on port 80/8080.
    local uri = ngx.var.uri or ""
    if not uri:find("^/%.well%-known/acme%-challenge/") then
        return proxy_core.json_error(403, "TLS_REQUIRED",
            "HTTPS is required for Mendr ingress on this edge", false)
    end
end

-- 1. Identity: X-Mendr-Key first, then Host fallback (Phase 6)
local headers = ngx.req.get_headers()
local source_service, tenant, ierr = identity.resolve(headers, { host = ngx.var.host })
if not source_service then
    identity.set_www_authenticate()
    return proxy_core.json_error(401, "IDENTITY_UNRESOLVED", ierr or "unauthorized", false)
end

-- 2. Radixtree match (host + method + concrete path)
local host   = ngx.var.host
local method = ngx.req.get_method()
local uri    = ngx.var.uri

local target_service, endpoint_template, enforce, merr =
    ingress_rt.match(host, method, uri)

if not target_service then
    local fallthrough = ingress_rt.handle_fallthrough(tenant, source_service, merr, {
        enforce = config.ingress_undeclared_enforce(),
        method = method,
        uri = uri,
    })
    if fallthrough == "NO_TREE" then
        if config.java_fallback_enabled() then
            ngx.ctx.javaFallback = true
            ngx.var.target_upstream = config.control_plane_base() .. "/api/gateway/proxy"
            local envelope = {
                sourceService = source_service,
                targetService = "unknown",
                endpoint = uri,
                method = method,
                payload = {},
                headers = {},
            }
            local body = cjson.encode(envelope)
            ngx.req.set_method(ngx.HTTP_POST)
            ngx.req.set_body_data(body)
            ngx.req.set_header("Content-Type", "application/json")
            ngx.req.set_header("Content-Length", #body)
            return
        end
        return proxy_core.json_error(503, "INGRESS_NOT_READY",
            "Ingress routing table not yet available", false)
    end
    if fallthrough == "SHADOW_ROUTE_ACCESSED" then
        ngx.ctx.shadowRouteAccessed = true
    end
    return proxy_core.json_error(404, "ROUTE_NOT_FOUND",
        "No route for " .. method .. " " .. uri, false)
end

if ingress_rt.is_stale() then
    ngx.log(ngx.WARN, "ingress: routing table is stale (last successful build too old)")
end

-- 3. Method-aware body (only after auth + match)
local payload = {}
local raw_body = nil
local has_body = false
local body_spilled = false
local is_json = false
local upper = method:upper()

if not BODYLESS[upper] then
    local err
    raw_body, has_body, body_spilled, is_json, err = read_body_for_ingress(headers)
    if err then
        return proxy_core.json_error(err.status, err.code, err.message, false)
    end
    if has_body and not body_spilled and raw_body and is_json then
        local decoded, derr = cjson.decode(raw_body)
        if not decoded then
            return proxy_core.json_error(400, "BAD_REQUEST",
                "Invalid JSON: " .. (derr or "unknown"), false)
        end
        payload = decoded
    end
end

local ctx = {
    source_service = source_service,
    target_service = target_service,
    endpoint       = endpoint_template,
    method         = method,
    payload        = payload,
    headers        = headers,
    mode           = "ingress",
    concrete_path  = uri,
    raw_body       = raw_body,
    has_body       = has_body,
    body_spilled   = body_spilled,
    is_json        = is_json,
    tenant         = tenant,
    enforce        = enforce or "observe",
}

ngx.header["X-Mendr-Data-Plane"] = "lua"
proxy_core.run(ctx)
