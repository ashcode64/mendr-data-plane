-- proxy_core.lua — Shared hot path for envelope (/api/gateway/proxy) and
-- transparent ingress. Extracted from access.lua with content-type/method-
-- aware body handling and header hygiene for public-facing ingress traffic.

local cjson     = require("cjson.safe")
local redis     = require("resty.redis")
local config    = require("config")
local transform = require("transform")
local peer_resolver = require("peer_resolver")
local rate_limit = require("rate_limit")
local auth_jwt = require("auth_jwt")
local response_cache = require("response_cache")
local metrics = require("metrics")
local circuit = require("circuit_breaker")
local waf = require("waf")
local otel = require("otel")
local ai_gateway = require("ai_gateway")

local _M = {}

-- Headers the edge may forward from the client (envelope.headers or real HTTP).
-- W3C trace-context (traceparent/tracestate) and B3 headers are propagated so a
-- caller->callee edge can be attributed by trace context across hops (init_v14
-- topology observation) — never by timing proximity.
local PASSTHROUGH_HEADERS = {
    authorization = true, ["x-api-key"] = true, ["x-correlation-id"] = true,
    ["x-request-id"] = true, ["x-trace-id"] = true, origin = true,
    traceparent = true, tracestate = true,
    ["x-b3-traceid"] = true, ["x-b3-spanid"] = true, ["x-b3-parentspanid"] = true,
    ["x-b3-sampled"] = true, ["x-b3-flags"] = true, b3 = true,
}

-- Never forward these to upstream (edge credentials / identity spoof surface).
local STRIP_HEADERS = {
    ["x-mendr-key"] = true,
    ["x-source-service"] = true,
    ["x-mendr-gateway"] = true,
    ["x-mendr-data-plane"] = true,
    ["x-resolved-url"] = true,
    ["x-tenant-id"] = true,
    ["x-internal-api-key"] = true,
}

-- RFC 2616 / 7230 hop-by-hop headers — must not be forwarded upstream.
local HOP_BY_HOP = {
    connection = true, ["keep-alive"] = true, ["proxy-authenticate"] = true,
    ["proxy-authorization"] = true, te = true, trailers = true,
    ["transfer-encoding"] = true, upgrade = true,
}

local BODYLESS_METHODS = {
    GET = true, HEAD = true, DELETE = true, OPTIONS = true,
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
        ngx.log(ngx.WARN, "proxy_core: redis set_keepalive failed: ", err)
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

local function template_to_pattern(template)
    local escaped = template:gsub("([%-%.%+%[%]%(%)%$%^%%%?%*])", "%%%1")
    escaped = escaped:gsub("{[^}]+}", "[^/]+")
    return "^" .. escaped .. "$"
end

local function lookup_route(red, source_service, target_service, endpoint)
    local exact_key = "mendr:routeconfig:" .. source_service .. ":" .. target_service .. ":" .. endpoint
    local res = red:get(exact_key)
    if res and res ~= ngx.null then
        return res
    end

    -- Radixtree-first template match (O(K) in path length) — prefer over KEYS.
    local ok_rt, ingress_rt = pcall(require, "ingress_routing")
    if ok_rt and ingress_rt and ingress_rt.match_pair then
        local tmpl = ingress_rt.match_pair(source_service, target_service, endpoint)
        if tmpl and tmpl ~= endpoint then
            local tmpl_key = "mendr:routeconfig:" .. source_service .. ":" .. target_service .. ":" .. tmpl
            local v = red:get(tmpl_key)
            if v and v ~= ngx.null then
                ngx.log(ngx.DEBUG, "proxy_core: radixtree matched ", tmpl, " for ", endpoint)
                return v
            end
        end
    end

    -- Last-resort compatibility: Redis KEYS scan (O(N) on the pair). Kept only
    -- for edges whose pair tree has not been rebuilt yet after upgrade.
    local prefix = "mendr:routeconfig:" .. source_service .. ":" .. target_service .. ":"
    local keys, kerr = red:keys(prefix .. "*")
    if not keys or keys == ngx.null then
        if kerr then ngx.log(ngx.WARN, "proxy_core: route keys lookup failed: ", kerr) end
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
                    ngx.log(ngx.DEBUG, "proxy_core: KEYS fallback matched templated route ",
                        tmpl, " for ", endpoint)
                    return v
                end
            end
        end
    end

    return nil
end

local function delegate_to_java(ctx, reason)
    ngx.log(ngx.INFO, "proxy_core: delegating to Java control plane — ", reason or "unspecified")
    ngx.ctx.javaFallback = true
    ngx.ctx.responseProgram = nil
    ngx.ctx.hasResponseContract = false

    local synthetic_envelope = {
        sourceService = ctx.source_service,
        targetService = ctx.target_service,
        endpoint      = ctx.endpoint,
        method        = ctx.method,
        payload       = ctx.payload or {},
        headers       = ctx.headers or {},
    }
    local original_body = cjson.encode(synthetic_envelope)
    ngx.var.target_upstream = config.control_plane_base() .. "/api/gateway/proxy"
    ngx.req.set_method(ngx.HTTP_POST)
    ngx.req.set_body_data(original_body)
    ngx.req.set_header("Content-Type", "application/json")
    ngx.req.set_header("Content-Length", #original_body)
end

function _M.json_error(status, error_type, message, healing)
    -- RFC 9457 Problem Details for Mendr-native blocks (identity/TLS/route/CORS/etc.)
    -- so clients always see application/problem+json whether upstream or Mendr rejects.
    local pd_mod = require("problem_detail")
    local corr = ngx.ctx.correlationId
    if not corr or corr == "" then
        local headers = ngx.req.get_headers()
        corr = headers["X-Correlation-Id"] or headers["x-correlation-id"]
            or headers["X-Request-Id"] or headers["x-request-id"]
        if not corr or corr == "" then
            corr = ngx.var.request_id or (tostring(ngx.now()) .. "-" .. tostring(math.random(100000, 999999)))
        end
        ngx.ctx.correlationId = corr
    end
    local req_id = ngx.ctx.requestId
    if not req_id or req_id == "" then
        local headers = ngx.req.get_headers()
        req_id = headers["X-Request-Id"] or headers["x-request-id"] or corr
        ngx.ctx.requestId = req_id
    end

    local env = ngx.ctx.envelope
    local instance = (env and env.endpoint and env.endpoint ~= "" and env.endpoint)
        or ngx.var.request_uri or ngx.var.uri

    local problem = pd_mod.native_problem({
        status = status,
        error_type = error_type,
        message = message,
        healing = healing,
        instance = instance,
        correlation_id = corr,
        request_id = req_id,
    })
    ngx.ctx.mendrProblemDetail = problem
    ngx.ctx.upstreamProblemDetail = problem

    ngx.status = status
    ngx.header.content_type = "application/problem+json"
    ngx.header["X-Mendr-Data-Plane"] = "lua"
    ngx.header["X-Correlation-Id"] = corr
    ngx.header["X-Request-Id"] = req_id
    ngx.say(cjson.encode(problem))
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

local function is_json_content_type(headers)
    if not headers then return false end
    local ct = headers["Content-Type"] or headers["content-type"]
    if not ct or type(ct) ~= "string" then return false end
    return ct:lower():find("application/json", 1, true) ~= nil
end

local function is_bodyless(method)
    return BODYLESS_METHODS[(method or "GET"):upper()] == true
end

--- Decide upstream body write mode without touching ngx (unit-testable).
--- Returns: "none" | "json" | "raw" | "spilled" | "error413"
--- Re-encode ONLY when a transform ran AND the body is JSON (ingress).
--- Envelope always encodes the payload object as JSON (that is the upstream body).
--- Hybrid large-body: JSON or transform-required spill → 413; non-JSON spill → passthrough.
function _M.body_output_mode(ctx, method, transformed, headers)
    ctx = ctx or {}
    method = method or "GET"
    headers = headers or {}

    if is_bodyless(method) then
        return "none"
    end

    -- Explicit has_body=false (empty POST/PUT/PATCH): do not synthesize {}.
    if ctx.has_body == false then
        return "none"
    end

    local is_json = ctx.is_json
    if is_json == nil then
        is_json = (ctx.mode == "envelope") or is_json_content_type(headers)
    end

    if ctx.body_spilled then
        -- Hybrid 413: JSON and/or would-transform spills cannot be handled safely in Lua.
        if is_json or transformed then
            return "error413"
        end
        return "spilled"
    end

    -- Ingress: only re-encode when a transform actually mutated a JSON body.
    if transformed and is_json then
        return "json"
    end

    -- Envelope: upstream body is the envelope.payload object (always JSON).
    if ctx.mode == "envelope" then
        return "json"
    end

    if ctx.has_body and ctx.raw_body and ctx.raw_body ~= "" then
        return "raw"
    end

    -- Body present but left for nginx (e.g. non-JSON without raw_body copy) or empty.
    if ctx.has_body and not is_json then
        return "spilled"  -- leave nginx buffer alone (same as non-JSON passthrough)
    end

    return "none"
end

-- Strict undeclared-surface check (x-mendr-enforce: strict).
-- Uses allowedSurface from the route snapshot (bodyPointers + queryParams).
local function check_strict_surface(route_config, ctx)
    if not route_config then return true end
    local enforce = route_config.enforceMode or "observe"
    if enforce ~= "strict" then return true end

    local surface = route_config.allowedSurface
    if type(surface) ~= "table" then
        -- No compiled surface (inferred-only / insufficient trust) → degrade to observe.
        return true
    end
    if surface.schemaSource and surface.schemaSource ~= "OPENAPI_DECLARED" then
        return true
    end
    if surface.specTrust and tonumber(surface.specTrust) and tonumber(surface.specTrust) < 0.5 then
        return true
    end

    -- Query params
    local allowed_qp = surface.queryParams
    if type(allowed_qp) == "table" then
        local args = ngx.req.get_uri_args() or {}
        local allow_set = {}
        for _, name in ipairs(allowed_qp) do
            allow_set[tostring(name)] = true
        end
        -- additionalProperties-style open query: skip if flagged
        if not surface.additionalQueryParams then
            for name, _ in pairs(args) do
                if not allow_set[name] then
                    -- "when known" diagnostics for A3 ProblemDetail extensions
                    ngx.ctx.json_path = "query:" .. tostring(name)
                    return false, "Undeclared query parameter: " .. tostring(name)
                end
            end
        end
    end

    -- Body top-level keys (shallow; nested pointers when provided)
    local payload = ctx.payload
    if type(payload) == "table" and type(surface.bodyPointers) == "table"
       and not surface.additionalProperties then
        local allow_body = {}
        for _, ptr in ipairs(surface.bodyPointers) do
            -- "/foo" or "foo" → top-level key "foo"
            local key = tostring(ptr):gsub("^/", ""):match("^([^/]+)")
            if key then allow_body[key] = true end
        end
        for k, _ in pairs(payload) do
            if type(k) == "string" and not allow_body[k] then
                ngx.ctx.json_path = "/" .. k
                return false, "Undeclared request field: " .. k
            end
        end
    end

    return true
end

-- ── Main hot path ───────────────────────────────────────────────────────────

function _M.run(ctx)
    local source_service = ctx.source_service
    local target_service = ctx.target_service
    local endpoint       = ctx.endpoint
    local method         = ctx.method or "GET"
    local payload        = ctx.payload or {}
    local headers        = ctx.headers or {}
    local concrete_path  = ctx.concrete_path or endpoint  -- for upstream URL on ingress

    ngx.ctx.requestPayload = payload
    ngx.header["X-Mendr-Data-Plane"] = "lua"

    -- Load route snapshot
    local red, redis_err = redis_connect()
    local route_config = nil
    local err

    if red then
        local res = lookup_route(red, source_service, target_service, endpoint)

        if res and res ~= ngx.null then
            route_config, err = cjson.decode(res)
            if not route_config then
                ngx.log(ngx.WARN, "proxy_core: failed to decode route config: ", err)
            end
        else
            ngx.log(ngx.DEBUG, "proxy_core: no route config in Redis for ",
                source_service, "->", target_service, endpoint)
        end

        redis_close(red)
    else
        ngx.log(ngx.WARN, "proxy_core: ", redis_err)
    end

    if route_config and route_config.syncValidation then
        delegate_to_java(ctx, "syncValidation route")
        return
    end

    if (not route_config or not route_config.targetBaseUrl) and config.java_fallback_enabled() then
        delegate_to_java(ctx, "missing snapshot")
        return
    end

    if not route_config or not route_config.targetBaseUrl then
        return _M.json_error(503, "SNAPSHOT_MISSING",
            "No route snapshot in Redis for " .. source_service .. "->" .. target_service .. endpoint
            .. ". Register services or POST /api/internal/refresh-snapshots", false)
    end

    ngx.ctx.routeConfig = route_config
    ngx.ctx.hasResponseContract = route_config.hasResponseContract or false
    ngx.ctx.syncValidation = route_config.syncValidation or false
    ngx.ctx.registeredBaseUrl = route_config.registeredBaseUrl
    ngx.ctx.request_start_ms = ngx.now() * 1000

    -- API version negotiation (Accept-Version / X-API-Version vs snapshot.versioning)
    local ver = route_config.versioning
    if type(ver) == "table" and ver.apiVersion then
        local hdr_name = ver.acceptVersionHeader or "Accept-Version"
        local requested = headers[hdr_name] or headers[string.lower(hdr_name)]
            or headers["X-API-Version"] or headers["x-api-version"]
        if requested and tostring(requested) ~= ""
                and tostring(requested) ~= tostring(ver.apiVersion) then
            metrics.inc("mendr_edge_requests_total", { status = "406", reason = "version" }, 1)
            return _M.json_error(406, "API_VERSION_MISMATCH",
                "Requested version '" .. tostring(requested) .. "' does not match route version '"
                    .. tostring(ver.apiVersion) .. "'"
                    .. (ver.successorEndpoint and ("; try " .. tostring(ver.successorEndpoint)) or ""),
                false)
        end
        -- Hard-close deprecated routes past sunset (RFC 8594 Sunset header date)
        if (ver.deprecated == true or tostring(ver.deprecated) == "true")
                and ver.sunsetAt and tostring(ver.sunsetAt) ~= "" then
            -- Best-effort: if sunset parses as epoch or ISO date before now, return 410
            local sunset = tostring(ver.sunsetAt)
            local ok_p, parsed = pcall(function()
                -- ngx.parse_http_time for IMF-fix dates
                return ngx.parse_http_time(sunset)
            end)
            if ok_p and parsed and parsed > 0 and parsed < ngx.time() then
                metrics.inc("mendr_edge_requests_total", { status = "410", reason = "sunset" }, 1)
                return _M.json_error(410, "API_SUNSET",
                    "API version " .. tostring(ver.apiVersion) .. " was sunset at " .. sunset
                        .. (ver.successorEndpoint and ("; use " .. tostring(ver.successorEndpoint)) or ""),
                    false)
            end
        end
    end

    otel.start_span(route_config)

    -- WAF / geo / IP / payload caps (before auth to stop obvious attacks early)
    local ok_waf, waf_err = waf.inspect(route_config, ctx)
    if not ok_waf then
        metrics.inc("mendr_edge_requests_total", { status = "403", reason = "waf" }, 1)
        return _M.json_error(403, "WAF_BLOCKED", waf_err or "Blocked by WAF", false)
    end

    -- Edge consumer auth (capability authz) — cryptographic JWKS when configured
    local ok_auth, auth_err = auth_jwt.enforce(route_config)
    if not ok_auth then
        metrics.inc("mendr_edge_requests_total", { status = "401", reason = "auth" }, 1)
        return _M.json_error(401, "AUTH_FAILURE", auth_err or "Unauthorized", false)
    end

    -- Control-plane rate limit policy (capability ratelimit)
    local ok_rl, retry_after = rate_limit.allow(route_config, {
        consumer = headers["X-Api-Key"] or headers["x-api-key"],
    })
    if not ok_rl then
        metrics.inc("mendr_edge_requests_total", { status = "429", reason = "ratelimit" }, 1)
        return _M.json_error(429, "RATE_LIMITED",
            "Rate limit exceeded; retry after " .. tostring(retry_after) .. "s", false)
    end

    -- AI gateway: TPM/RPM, prompt firewall, semantic cache
    local ok_ai, ai_extra = ai_gateway.enforce(route_config, ctx)
    if not ok_ai then
        metrics.inc("mendr_edge_requests_total", { status = "429", reason = "ai" }, 1)
        local code = (tostring(ai_extra or ""):find("firewall", 1, true)) and 403 or 429
        return _M.json_error(code, code == 403 and "AI_FIREWALL" or "AI_RATE_LIMITED",
            ai_extra or "AI policy denied", false)
    end
    if type(ai_extra) == "table" and ai_extra.body then
        ngx.status = ai_extra.status or 200
        ngx.header.content_type = ai_extra.content_type or "application/json"
        ngx.header["X-Mendr-Cache"] = "SEMANTIC-HIT"
        ngx.say(ai_extra.body)
        return ngx.exit(ngx.status)
    end
    if ngx.ctx.ai_upstream_base then
        route_config.targetBaseUrl = ngx.ctx.ai_upstream_base
    end

    -- Response cache hit (capability cache)
    local cached = response_cache.get(route_config, method)
    if cached and cached.body then
        ngx.status = cached.status or 200
        ngx.header.content_type = cached.content_type or "application/json"
        ngx.header["X-Mendr-Cache"] = "HIT"
        ngx.say(cached.body)
        metrics.inc("mendr_edge_requests_total", { status = "cache_hit" }, 1)
        return ngx.exit(ngx.status)
    end

    -- Strict undeclared-surface enforcement (observe by default)
    local ok_surface, surface_err = check_strict_surface(route_config, ctx)
    if not ok_surface then
        return _M.json_error(400, "UNDECLARED_SURFACE", surface_err, false)
    end

    local origin = headers.Origin or headers.origin or ngx.req.get_headers()["Origin"]
    ngx.ctx.requestOrigin = origin
    ngx.ctx.realRequestOrigin = origin

    if route_config.corsActive and route_config.allowedOrigins then
        if origin and not origin_allowed(route_config.allowedOrigins, origin) then
            ngx.ctx.failureCategory = "CORS"
            ngx.ctx.corsBlockedAt = "EDGE"
            ngx.ctx.failureMessage = "CORS policy blocked origin '" .. origin .. "' for '" .. target_service .. "'"
            return _M.json_error(403, "CORS_FAILURE", ngx.ctx.failureMessage, true)
        end
        if origin then
            ngx.ctx.corsAllowed = true
        end
    end

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

    local transformed = false
    if route_config.requestProgram then
        local violation = transform.protected_violation(
            route_config.requestProgram, route_config.protectedPaths)
        if violation then
            ngx.log(ngx.ERR, "proxy_core: REFUSING request program — touches protected path '",
                violation, "' for ", source_service, "->", target_service, endpoint)
            ngx.ctx.protectedPathViolation = violation
        else
            local ok, result = pcall(transform.apply_program,
                transform.shallow_copy(payload), route_config.requestProgram)
            if ok and result ~= nil then
                payload = result
                ctx.payload = payload
                ngx.ctx.requestPayload = payload
                transformed = true
                ngx.ctx.transformApplied = true
            else
                ngx.log(ngx.ERR, "proxy_core: request transform errored, forwarding original "
                    .. "(fail-open): ", tostring(result))
                ngx.ctx.patchApplyError = true
            end
        end
    end

    local target_base = peer_resolver.prepare(route_config, {
        hash_key = headers["X-Correlation-Id"] or headers["x-correlation-id"] or ngx.var.remote_addr,
    })
    local use_balancer = ngx.ctx.use_dynamic_balancer == true
    if not use_balancer then
        target_base = config.rewrite_localhost(target_base or route_config.targetBaseUrl)
    end
    if not use_balancer and (not target_base or target_base == "") then
        if config.java_fallback_enabled() then
            delegate_to_java(ctx, "unresolved target URL")
            return
        end
        return _M.json_error(502, "ROUTING_FAILURE",
            "No target URL resolved for service '" .. target_service .. "'", true)
    end

    if not use_balancer and target_base:sub(-1) == "/" then
        target_base = target_base:sub(1, -2)
    end

    ngx.ctx.trafficPolicy = route_config.trafficPolicy
    if type(route_config.targetInstances) == "table" then
        ngx.ctx.balancer_peers = route_config.targetInstances
    end

    -- Upstream URL: named upstream for multi-instance (enables proxy_next_upstream),
    -- absolute URL for single-instance back-compat.
    local path_for_upstream = concrete_path
    if use_balancer then
        local path = path_for_upstream
        if path:sub(1, 1) ~= "/" then path = "/" .. path end
        ngx.var.target_upstream = "http://mendr_dynamic" .. path
        ngx.ctx.targetServiceUrl = (ngx.ctx.selected_peer or "mendr_dynamic") .. path
        ngx.ctx.selected_peer = ngx.ctx.selected_peer
    else
        local target_url = target_base .. path_for_upstream
        ngx.var.target_upstream = target_url
        ngx.ctx.targetServiceUrl = target_url
        ngx.ctx.selected_peer = target_base
    end

    ngx.req.set_method(ngx["HTTP_" .. method:upper()] or ngx.HTTP_GET)

    -- Body write gated by ctx.has_body + spill/transform policy (see body_output_mode).
    local body_mode = _M.body_output_mode(ctx, method, transformed, headers)
    if body_mode == "error413" then
        return _M.json_error(413, "PAYLOAD_TOO_LARGE",
            "Request body exceeds buffered size limit; JSON decode/transform of spilled bodies is not supported",
            false)
    elseif body_mode == "none" then
        ngx.req.set_header("Content-Length", 0)
    elseif body_mode == "json" then
        local transformed_body = cjson.encode(payload)
        ngx.req.set_body_data(transformed_body)
        ngx.req.set_header("Content-Type", "application/json")
        ngx.req.set_header("Content-Length", #transformed_body)
    elseif body_mode == "raw" then
        local raw = ctx.raw_body
        ngx.req.set_body_data(raw)
        ngx.req.set_header("Content-Length", #raw)
        local ct = headers["Content-Type"] or headers["content-type"]
        if ct then ngx.req.set_header("Content-Type", ct) end
    elseif body_mode == "spilled" then
        -- Leave nginx temp-file body as-is; do not set_body_data({}) .
        local ct = headers["Content-Type"] or headers["content-type"]
        if ct then ngx.req.set_header("Content-Type", ct) end
    end

    -- Client headers first (strip mendr-internal / hop-by-hop / identity spoof vectors)
    if headers then
        for k, v in pairs(headers) do
            local lower_k = k:lower()
            if STRIP_HEADERS[lower_k] or HOP_BY_HOP[lower_k] then
                -- never forward
            elseif not PASSTHROUGH_HEADERS[lower_k]
               and lower_k ~= "content-type" and lower_k ~= "content-length" and lower_k ~= "host" then
                ngx.req.set_header(k, v)
            elseif PASSTHROUGH_HEADERS[lower_k] then
                ngx.req.set_header(k, v)
            end
        end
    end

    -- Identity / mendr headers AFTER client loop (unspoofable)
    ngx.req.set_header("X-Mendr-Gateway", "true")
    ngx.req.set_header("X-Mendr-Data-Plane", "lua")
    ngx.req.set_header("X-Source-Service", source_service)
    if use_balancer then
        ngx.req.set_header("X-Resolved-URL", ngx.ctx.selected_peer or "mendr_dynamic")
    else
        ngx.req.set_header("X-Resolved-URL", target_base)
    end
    -- Path A1: opportunistically request RFC 9457 when client did not set Accept.
    local existing_accept = headers and (headers["Accept"] or headers["accept"])
    if not existing_accept or existing_accept == "" then
        ngx.req.set_header("Accept", "application/problem+json, application/json;q=0.9, */*;q=0.1")
    end

    apply_auth(route_config, headers)

    if ngx.ctx.outboundOrigin then
        ngx.req.set_header("Origin", ngx.ctx.outboundOrigin)
    end

    if route_config.responseProgram and not route_config.responseProgram.empty then
        ngx.ctx.responseProgram = route_config.responseProgram
        ngx.ctx.programHash = route_config.programHash
    end
end

-- Exported for envelope path, identity_resolver, ingress_routing, and tests
_M.lookup_route = lookup_route
_M.delegate_to_java = delegate_to_java
_M.redis_connect = redis_connect
_M.redis_close = redis_close

return _M
