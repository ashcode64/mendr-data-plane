-- access.lua — Request parsing, CORS check, request transforms, upstream routing

local cjson     = require("cjson.safe")
local redis     = require("resty.redis")
local config    = require("config")
local transform = require("transform")

local PASSTHROUGH_HEADERS = {
    authorization = true, ["x-api-key"] = true, ["x-correlation-id"] = true,
    ["x-request-id"] = true, ["x-trace-id"] = true, origin = true,
}

-- ── Redis ───────────────────────────────────────────────────────────────────

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
        ngx.log(ngx.WARN, "access: redis set_keepalive failed: ", err)
    end
end

-- ── Helpers ─────────────────────────────────────────────────────────────────

local function origin_allowed(allowed_origins, origin)
    if not allowed_origins or not origin then
        return false
    end
    if type(allowed_origins) == "table" then
        for _, o in ipairs(allowed_origins) do
            if o == "*" or o == origin then return true end
        end
        for _, o in pairs(allowed_origins) do
            if o == "*" or o == origin then return true end
        end
    end
    return false
end

-- Build a Lua pattern from a templated endpoint, e.g. "/menu-items/{id}" ->
-- "^/menu%-items/[^/]+$". Used to match concrete paths to templated route keys.
local function template_to_pattern(template)
    local escaped = template:gsub("([%-%.%+%[%]%(%)%$%^%%%?%*])", "%%%1")
    escaped = escaped:gsub("{[^}]+}", "[^/]+")
    return "^" .. escaped .. "$"
end

-- Look up a route snapshot, first by exact key, then by matching the concrete
-- endpoint against any templated ({param}) route key for the same service pair.
local function lookup_route(red, source_service, target_service, endpoint)
    local exact_key = "mendr:routeconfig:" .. source_service .. ":" .. target_service .. ":" .. endpoint
    local res = red:get(exact_key)
    if res and res ~= ngx.null then
        return res
    end

    local prefix = "mendr:routeconfig:" .. source_service .. ":" .. target_service .. ":"
    local keys, kerr = red:keys(prefix .. "*")
    if not keys or keys == ngx.null then
        if kerr then ngx.log(ngx.WARN, "access: route keys lookup failed: ", kerr) end
        return nil
    end

    for _, key in ipairs(keys) do
        local tmpl = key:sub(#prefix + 1)
        if tmpl:find("{", 1, true) then
            local ok = pcall(function()
                return endpoint:match(template_to_pattern(tmpl))
            end)
            if ok and endpoint:match(template_to_pattern(tmpl)) then
                local v = red:get(key)
                if v and v ~= ngx.null then
                    ngx.log(ngx.DEBUG, "access: matched templated route ", tmpl, " for ", endpoint)
                    return v
                end
            end
        end
    end

    return nil
end

local function delegate_to_java(envelope, reason)
    ngx.log(ngx.INFO, "access: delegating to Java control plane — ", reason or "unspecified")
    ngx.ctx.javaFallback = true
    ngx.ctx.responseProgram = nil
    ngx.ctx.hasResponseContract = false

    local original_body = cjson.encode(envelope)
    ngx.var.target_upstream = config.control_plane_base() .. "/api/gateway/proxy"
    ngx.req.set_method(ngx.HTTP_POST)
    ngx.req.set_body_data(original_body)
    ngx.req.set_header("Content-Type", "application/json")
    ngx.req.set_header("Content-Length", #original_body)
end

local function json_error(status, error_type, message, healing)
    ngx.status = status
    ngx.header.content_type = "application/json"
    ngx.header["X-Mendr-Data-Plane"] = "lua"
    ngx.say(cjson.encode({
        error = error_type,
        status = status,
        message = message,
        selfHealingTriggered = healing == true,
    }))
    return ngx.exit(status)
end

local function apply_auth(route_config, headers)
    if not route_config or not route_config.authType or route_config.authType == "NONE" then
        return
    end

    local auth_type = route_config.authType
    local header_name = route_config.authHeaderName or "Authorization"

    if auth_type == "JWT_BEARER" then
        local existing = headers and (headers[header_name] or headers[string.lower(header_name)])
        if existing and existing ~= "" then
            ngx.req.set_header(header_name, existing)
        end
    elseif auth_type == "API_KEY_HEADER" then
        header_name = route_config.authHeaderName or "X-Api-Key"
        local existing = headers and (headers[header_name] or headers[string.lower(header_name)])
        if existing and existing ~= "" then
            ngx.req.set_header(header_name, existing)
        end
    end
end

-- ── Main ────────────────────────────────────────────────────────────────────

ngx.req.read_body()
local body_data = ngx.req.get_body_data()
if not body_data then
    return json_error(400, "BAD_REQUEST", "Empty request body", false)
end

local envelope, err = cjson.decode(body_data)
if not envelope then
    return json_error(400, "BAD_REQUEST", "Invalid JSON: " .. (err or "unknown"), false)
end

local source_service = envelope.sourceService
local target_service = envelope.targetService
local endpoint       = envelope.endpoint
local method         = envelope.method or "GET"
local payload        = envelope.payload or {}
local headers        = envelope.headers or {}

if not source_service or not target_service or not endpoint then
    return json_error(400, "BAD_REQUEST",
        "Missing required fields: sourceService, targetService, endpoint", false)
end

ngx.ctx.envelope = envelope
ngx.ctx.requestPayload = payload
ngx.header["X-Mendr-Data-Plane"] = "lua"

-- Load route snapshot
local red, redis_err = redis_connect()
local route_config = nil

if red then
    local res = lookup_route(red, source_service, target_service, endpoint)

    if res and res ~= ngx.null then
        route_config, err = cjson.decode(res)
        if not route_config then
            ngx.log(ngx.WARN, "access: failed to decode route config: ", err)
        end
    else
        ngx.log(ngx.DEBUG, "access: no route config in Redis for ",
            source_service, "->", target_service, endpoint)
    end

    redis_close(red)
else
    ngx.log(ngx.WARN, "access: ", redis_err)
end

-- Per-route sync validation always uses Java (even when global fallback is off)
if route_config and route_config.syncValidation then
    delegate_to_java(envelope, "syncValidation route")
    return
end

if (not route_config or not route_config.targetBaseUrl) and config.java_fallback_enabled() then
    delegate_to_java(envelope, "missing snapshot")
    return
end

if not route_config or not route_config.targetBaseUrl then
    return json_error(503, "SNAPSHOT_MISSING",
        "No route snapshot in Redis for " .. source_service .. "->" .. target_service .. endpoint
        .. ". Register services or POST /api/internal/refresh-snapshots", false)
end

ngx.ctx.routeConfig = route_config
ngx.ctx.hasResponseContract = route_config.hasResponseContract or false
ngx.ctx.syncValidation = route_config.syncValidation or false
ngx.ctx.registeredBaseUrl = route_config.registeredBaseUrl

local origin = headers.Origin or headers.origin or ngx.req.get_headers()["Origin"]
ngx.ctx.requestOrigin = origin
ngx.ctx.realRequestOrigin = origin

-- CORS gate (Lua data plane) — uses REAL caller origin
if route_config.corsActive and route_config.allowedOrigins then
    if origin and not origin_allowed(route_config.allowedOrigins, origin) then
        ngx.ctx.failureCategory = "CORS"
        ngx.ctx.corsBlockedAt = "EDGE"
        ngx.ctx.failureMessage = "CORS policy blocked origin '" .. origin .. "' for '" .. target_service .. "'"
        return json_error(403, "CORS_FAILURE", ngx.ctx.failureMessage, true)
    end
    if origin then
        ngx.ctx.corsAllowed = true
    end
end

-- Upstream Origin override (approved CORS_ORIGIN_OVERRIDE rules in snapshot)
ngx.ctx.outboundOrigin = origin
ngx.ctx.originOverrideActive = false
if origin and route_config.originOverrides and type(route_config.originOverrides) == "table" then
    for _, ov in ipairs(route_config.originOverrides) do
        if ov.callerOriginMatch == origin and ov.outboundOriginOverride then
            ngx.ctx.outboundOrigin = ov.outboundOriginOverride
            ngx.ctx.originOverrideActive = true
            ngx.ctx.rewriteResponseAcao = ov.rewriteResponseAcao ~= false
            break
        end
    end
end

-- Request transforms — independent protected-path backstop (§3) + fail-open (§4.11)
if route_config.requestProgram then
    local violation = transform.protected_violation(
        route_config.requestProgram, route_config.protectedPaths)
    if violation then
        -- Defense-in-depth: refuse the WHOLE program and forward the original
        -- payload unmodified. Independent of the control-plane guardrail.
        ngx.log(ngx.ERR, "access: REFUSING request program — touches protected path '",
            violation, "' for ", source_service, "->", target_service, endpoint)
        ngx.ctx.protectedPathViolation = violation
    else
        local ok, result = pcall(transform.apply_program,
            transform.shallow_copy(payload), route_config.requestProgram)
        if ok and result ~= nil then
            payload = result
            ngx.ctx.requestPayload = payload
        else
            -- Fail-open: a malformed/erroring program must never block live traffic.
            ngx.log(ngx.ERR, "access: request transform errored, forwarding original "
                .. "(fail-open): ", tostring(result))
            ngx.ctx.patchApplyError = true
        end
    end
end

local target_base = config.rewrite_localhost(route_config.targetBaseUrl)
if not target_base or target_base == "" then
    if config.java_fallback_enabled() then
        delegate_to_java(envelope, "unresolved target URL")
        return
    end
    return json_error(502, "ROUTING_FAILURE",
        "No target URL resolved for service '" .. target_service .. "'", true)
end

if target_base:sub(-1) == "/" then
    target_base = target_base:sub(1, -2)
end

local target_url = target_base .. endpoint
ngx.var.target_upstream = target_url
ngx.ctx.targetServiceUrl = target_url

ngx.req.set_method(ngx["HTTP_" .. method:upper()] or ngx.HTTP_GET)

local transformed_body = cjson.encode(payload)
ngx.req.set_body_data(transformed_body)
ngx.req.set_header("Content-Type", "application/json")
ngx.req.set_header("Content-Length", #transformed_body)
ngx.req.set_header("X-Mendr-Gateway", "true")
ngx.req.set_header("X-Mendr-Data-Plane", "lua")
ngx.req.set_header("X-Source-Service", source_service)
ngx.req.set_header("X-Resolved-URL", target_base)

apply_auth(route_config, headers)

if headers then
    for k, v in pairs(headers) do
        local lower_k = k:lower()
        if not PASSTHROUGH_HEADERS[lower_k]
           and lower_k ~= "content-type" and lower_k ~= "content-length" and lower_k ~= "host" then
            ngx.req.set_header(k, v)
        end
    end
end

if ngx.ctx.outboundOrigin then
    ngx.req.set_header("Origin", ngx.ctx.outboundOrigin)
end

if route_config.responseProgram and not route_config.responseProgram.empty then
    ngx.ctx.responseProgram = route_config.responseProgram
end
