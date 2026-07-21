-- log.lua — Async failure reporting + async response contract validation
-- Uses ngx.timer.at for fire-and-forget POST to Java control plane.
-- Two-layer dedup: Lua shared_dict (first), Java Redis TTL (safety net).

local cjson  = require("cjson.safe")
local http   = require("resty.http")
local dedup  = require("dedup")
local config = require("config")
local pd_mod = require("problem_detail")

local CONTROL_PLANE_BASE = config.control_plane_base()

-- ── HTTP POST helper (runs inside ngx.timer.at callback) ────────────────────

local function post_json(url, body_table)
    local httpc = http.new()
    httpc:set_timeout(5000)

    local json_body = cjson.encode(body_table)
    if not json_body then
        ngx.log(ngx.ERR, "log.lua: failed to encode POST body")
        return
    end

    local res, err = httpc:request_uri(url, {
        method  = "POST",
        body    = json_body,
        headers = (function()
            local h = { ["Content-Type"] = "application/json" }
            local api_key = config.internal_api_key()
            if api_key then
                h["X-Internal-Api-Key"] = api_key
            end
            return h
        end)(),
    })

    if not res then
        ngx.log(ngx.WARN, "log.lua: POST to ", url, " failed: ", err)
    elseif res.status >= 400 then
        ngx.log(ngx.WARN, "log.lua: POST to ", url, " returned ", res.status)
    end
end

-- ── Failure classification ──────────────────────────────────────────────────

local function extract_error_message(status, envelope)
    if ngx.ctx.failureMessage then
        return ngx.ctx.failureMessage
    end

    local upstream = ngx.ctx.upstreamErrorBody
    if upstream and type(upstream) == "table" then
        local raw = upstream.raw
        if type(raw) == "table" then
            local preferred = pd_mod.prefer_detail_message(raw)
            if preferred then
                return preferred
            end
        elseif type(raw) == "string" and raw ~= "" then
            return raw
        end
    end

    local pd = ngx.ctx.upstreamProblemDetail or ngx.ctx.mendrProblemDetail
    if type(pd) == "table" and pd.detail and tostring(pd.detail) ~= "" then
        return tostring(pd.detail)
    end

    return "HTTP " .. status .. " from " .. (envelope.targetService or "") .. (envelope.endpoint or "")
end

local function classify_failure(status, envelope)
    if ngx.ctx.failureCategory then
        return ngx.ctx.failureCategory
    end
    -- Mendr-native problem title / error code
    local pd = ngx.ctx.mendrProblemDetail or ngx.ctx.upstreamProblemDetail
    if type(pd) == "table" and pd.error then
        local code = tostring(pd.error)
        if code == "CORS_FAILURE" then return "CORS" end
        if code == "ROUTING_FAILURE" or code == "SNAPSHOT_MISSING" then return "ROUTING" end
        if code == "IDENTITY_UNRESOLVED" or code == "TLS_REQUIRED"
            or code == "ROUTE_NOT_FOUND" or code == "INGRESS_NOT_READY"
            or code == "BAD_REQUEST" or code == "UNDECLARED_SURFACE"
            or code == "PAYLOAD_TOO_LARGE" then
            return "MENDR_NATIVE"
        end
    end
    if status == 502 or status == 503 or status == 504 then
        return "ROUTING"
    end
    if status == 403 then
        local origin = envelope and envelope.headers and
            (envelope.headers.Origin or envelope.headers.origin)
        if origin then
            if ngx.ctx.corsBlockedAt == "EDGE" then
                return "CORS"
            end
            return "CORS_UPSTREAM"
        end
    end
    if status == 400 or status == 422 then
        return "SCHEMA_MISMATCH"
    end
    return "UNKNOWN"
end

-- ── Timer callback: report failure ──────────────────────────────────────────

local function report_failure(premature, data)
    if premature then return end

    local ok, err = pcall(post_json,
        CONTROL_PLANE_BASE .. "/api/internal/failures", data)
    if not ok then
        ngx.log(ngx.ERR, "log.lua: report_failure error: ", err)
    end
end

-- ── Timer callback: validate response ───────────────────────────────────────

local function validate_response(premature, data)
    if premature then return end

    local ok, err = pcall(post_json,
        CONTROL_PLANE_BASE .. "/api/internal/validate-response", data)
    if not ok then
        ngx.log(ngx.ERR, "log.lua: validate_response error: ", err)
    end
end

local function build_problem_detail(status, envelope, category, source, target, ep)
    local upstream = ngx.ctx.upstreamProblemDetail or ngx.ctx.mendrProblemDetail
    local corr = ngx.ctx.correlationId
        or (envelope.headers and (envelope.headers["X-Correlation-Id"]
            or envelope.headers["x-correlation-id"]
            or envelope.headers["X-Request-Id"]
            or envelope.headers["x-request-id"]))
    local req_id = ngx.ctx.requestId
        or (envelope.headers and (envelope.headers["X-Request-Id"] or envelope.headers["x-request-id"]))
        or corr
    local detail_msg = extract_error_message(status, envelope)

    return pd_mod.merge_a3(upstream, {
        category = category,
        status = status,
        source = source,
        target = target,
        endpoint = ep,
        correlation_id = corr,
        request_id = req_id,
        detail_fallback = detail_msg,
        request_uri = ngx.var.request_uri,
        template_id = ngx.ctx.templateId or ngx.ctx.template_id,
        json_path = ngx.ctx.jsonPath or ngx.ctx.json_path,
    }), corr, req_id
end

--- Best-effort envelope for early Mendr-native exits (identity/TLS/bad body).
local function resolve_envelope()
    if ngx.ctx.envelope then
        return ngx.ctx.envelope
    end
    if not (ngx.ctx.mendrProblemDetail or ngx.ctx.upstreamProblemDetail) then
        return nil
    end
    local headers = ngx.req.get_headers() or {}
    return {
        sourceService = ngx.ctx.reportSource or "unknown",
        targetService = ngx.ctx.reportTarget or "unknown",
        endpoint      = ngx.ctx.reportEndpoint or ngx.var.uri or "/",
        method        = ngx.req.get_method() or "GET",
        payload       = {},
        headers       = headers,
    }
end

-- ── Main ────────────────────────────────────────────────────────────────────

if ngx.ctx.javaFallback then
    return
end

local envelope = resolve_envelope()
if not envelope then
    return
end

local source  = envelope.sourceService or ""
local target  = envelope.targetService or ""
local ep      = envelope.endpoint or ""
local method  = envelope.method or "GET"
local status  = ngx.status

-- ── 1. Failure reporting (status >= 400 or upstream error) ───────────────────

if status >= 400 then
    -- Dedup: first-occurrence MUST escalate, only suppress repeats
    if dedup.should_process("fail", source, target, ep, 60) then
        local category = classify_failure(status, envelope)

        local cors_blocked_at = ngx.ctx.corsBlockedAt
        if category == "CORS_UPSTREAM" then
            cors_blocked_at = "UPSTREAM"
        elseif category == "CORS" and cors_blocked_at == nil then
            cors_blocked_at = "EDGE"
        end

        local problem_detail, corr, req_id = build_problem_detail(status, envelope, category, source, target, ep)

        -- Prefer problem detail text when richer than synthetic message
        local err_msg = extract_error_message(status, envelope)
        if problem_detail.detail and problem_detail.detail ~= "" then
            err_msg = problem_detail.detail
        end

        local failure_data = {
            sourceService      = source,
            targetService      = target,
            endpoint           = ep,
            httpMethod         = method,
            errorCode          = status,
            errorType          = category .. "_FAILURE",
            failureCategory    = category,
            errorMessage       = err_msg,
            requestPayload     = ngx.ctx.requestPayload,
            attemptedUrl       = ngx.var.target_upstream,
            targetServiceUrl   = ngx.ctx.targetServiceUrl,
            registeredBaseUrl  = ngx.ctx.registeredBaseUrl,
            requestOrigin      = envelope.headers and (envelope.headers.Origin or envelope.headers.origin),
            upstreamOriginSent = ngx.ctx.outboundOrigin,
            corsBlockedAt      = cors_blocked_at,
            responsePayload    = ngx.ctx.upstreamErrorBody,
            correlationId      = corr,
            requestId          = req_id,
            responseHeaders    = ngx.ctx.upstreamResponseHeaders,
            problemDetail      = problem_detail,
        }

        local ok, err = ngx.timer.at(0, report_failure, failure_data)
        if not ok then
            ngx.log(ngx.ERR, "log.lua: failed to schedule failure report timer: ", err)
        end
    end
end

-- ── 2. Async response contract validation (status < 400, hasResponseContract) ──

if status < 400 and ngx.ctx.hasResponseContract then
    -- Skip async validation if this route uses per-route sync validation
    -- (syncValidation is handled by the Java proxy path, not OpenResty)
    if not ngx.ctx.syncValidation then
        if dedup.should_process("validate", source, target, ep, 60) then
            local raw_resp         = ngx.ctx.rawResponseBody
            local transformed_resp = ngx.ctx.transformedResponseBody

            -- Only send if we have bodies to validate
            if raw_resp or transformed_resp then
                local corr = ngx.ctx.correlationId
                    or (envelope.headers and (envelope.headers["X-Correlation-Id"]
                        or envelope.headers["x-correlation-id"]))
                local req_id = ngx.ctx.requestId
                    or (envelope.headers and (envelope.headers["X-Request-Id"]
                        or envelope.headers["x-request-id"]))
                    or corr
                -- When a ProblemDetail was captured, merge A3 Mendr extensions (same as failures).
                local upstream_pd = ngx.ctx.upstreamProblemDetail or ngx.ctx.mendrProblemDetail
                local problem_detail = nil
                if type(upstream_pd) == "table" then
                    problem_detail = pd_mod.merge_a3(upstream_pd, {
                        category = "RESPONSE",
                        status = status,
                        source = source,
                        target = target,
                        endpoint = ep,
                        correlation_id = corr,
                        request_id = req_id,
                        detail_fallback = upstream_pd.detail,
                        request_uri = ngx.var.request_uri,
                        template_id = ngx.ctx.templateId or ngx.ctx.template_id,
                        json_path = ngx.ctx.jsonPath or ngx.ctx.json_path,
                    })
                end

                local validate_data = {
                    sourceService       = source,
                    targetService       = target,
                    endpoint            = ep,
                    httpMethod          = method,
                    httpStatus          = status,
                    requestPayload      = ngx.ctx.requestPayload,
                    rawResponse         = raw_resp,
                    transformedResponse = transformed_resp,
                    requestHeaders      = envelope.headers,
                    correlationId       = corr,
                    requestId           = req_id,
                    responseHeaders     = ngx.ctx.upstreamResponseHeaders,
                    problemDetail       = problem_detail,
                }

                local ok, err = ngx.timer.at(0, validate_response, validate_data)
                if not ok then
                    ngx.log(ngx.ERR, "log.lua: failed to schedule validate timer: ", err)
                end
            end
        end
    end
end
