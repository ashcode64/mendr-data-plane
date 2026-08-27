-- header_filter.lua — CORS, correlation echo, upstream response header capture

local real_origin = ngx.ctx.realRequestOrigin or ngx.ctx.requestOrigin

if ngx.ctx.originOverrideActive and ngx.ctx.rewriteResponseAcao ~= false and real_origin then
    ngx.header["Access-Control-Allow-Origin"] = real_origin
    ngx.header["Access-Control-Allow-Credentials"] = "true"
    ngx.header["Vary"] = "Origin"
elseif real_origin and ngx.ctx.corsAllowed then
    ngx.header["Access-Control-Allow-Origin"] = real_origin
    ngx.header["Access-Control-Allow-Credentials"] = "true"
    ngx.header["Vary"] = "Origin"
end

-- Conditional body retention + Content-Length.
-- CL is kept on PASSTHROUGH. It is cleared when planClass may rewrite the
-- body (including PREFILTERABLE: a miss is not knowable here, and a hit
-- would truncate if CL stayed).
do
    local envelope = ngx.ctx.envelope
    local source = envelope and (envelope.sourceService or "") or ""
    local target = envelope and (envelope.targetService or "") or ""
    local ep = envelope and (envelope.endpoint or "") or ""

    local peek_validate = false
    if ngx.ctx.hasResponseContract and not ngx.ctx.syncValidation then
        local ok_d, dedup = pcall(require, "dedup")
        if ok_d and dedup and dedup.peek then
            peek_validate = dedup.peek("validate", source, target, ep, 60) and true or false
        else
            peek_validate = true
        end
    end

    local should_cache = false
    local ok_rc, response_cache = pcall(require, "response_cache")
    if ok_rc and response_cache and response_cache.should_cache then
        local method = ngx.req.get_method()
        should_cache = response_cache.should_cache(ngx.ctx.routeConfig, method) and true or false
    end

    local body_policy = require("body_policy")
    local need, will_transform = body_policy.need_response_body({
        program = ngx.ctx.responseProgram,
        status = ngx.status or 0,
        hasResponseContract = ngx.ctx.hasResponseContract,
        syncValidation = ngx.ctx.syncValidation,
        peek_validate = peek_validate,
        should_cache = should_cache,
        ai_semantic_cache_key = ngx.ctx.ai_semantic_cache_key,
    })

    ngx.ctx.need_response_body = need
    ngx.ctx.will_transform = will_transform or false

    if will_transform then
        ngx.header.content_length = nil
        -- Plan, not outcome: body_filter may still miss/spill/abort after headers flush.
        ngx.header["X-Mendr-Transform-Planned"] = "true"
    end
end

-- Capture selected upstream response headers for log.lua failure reporting
local function hdr(name)
    -- ngx.resp.get_headers() available in header_filter
    local h = ngx.resp.get_headers()
    if not h then return nil end
    return h[name] or h[string.lower(name)]
end

local captured = {
    ["Content-Type"] = hdr("Content-Type"),
    ["X-Correlation-Id"] = hdr("X-Correlation-Id"),
    ["X-Request-Id"] = hdr("X-Request-Id"),
    ["Location"] = hdr("Location"),
}
ngx.ctx.upstreamResponseHeaders = captured
if captured["Content-Type"] then
    ngx.ctx.upstreamContentType = tostring(captured["Content-Type"])
end

-- Ensure correlation / request ids exist and echo to client
local req_headers = ngx.req.get_headers()
local corr = ngx.ctx.correlationId
    or (req_headers and (req_headers["X-Correlation-Id"] or req_headers["x-correlation-id"]))
    or captured["X-Correlation-Id"]
    or (req_headers and (req_headers["X-Request-Id"] or req_headers["x-request-id"]))
    or ngx.var.request_id

if not corr or corr == "" then
    corr = tostring(ngx.now()) .. "-" .. tostring(math.random(100000, 999999))
end
ngx.ctx.correlationId = corr

local req_id = ngx.ctx.requestId
    or (req_headers and (req_headers["X-Request-Id"] or req_headers["x-request-id"]))
    or captured["X-Request-Id"]
    or corr
ngx.ctx.requestId = req_id

ngx.header["X-Correlation-Id"] = corr
ngx.header["X-Request-Id"] = req_id

-- RFC 8594 Deprecation / Sunset headers from route versioning snapshot
local route = ngx.ctx.routeConfig
local ver = route and route.versioning
if type(ver) == "table" then
    if ver.deprecated == true or tostring(ver.deprecated) == "true" then
        ngx.header["Deprecation"] = "true"
        if ver.sunsetAt and ver.sunsetAt ~= "" then
            ngx.header["Sunset"] = tostring(ver.sunsetAt)
        end
        if ver.successorEndpoint and ver.successorEndpoint ~= "" then
            ngx.header["Link"] = "<" .. tostring(ver.successorEndpoint) .. ">; rel=\"successor-version\""
        end
    end
    if ver.apiVersion and ver.apiVersion ~= "" then
        ngx.header["X-API-Version"] = tostring(ver.apiVersion)
    end
end

if ngx.ctx.canary_routed then
    ngx.header["X-Mendr-Canary"] = "1"
end
