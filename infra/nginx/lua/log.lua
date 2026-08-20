-- log.lua — Async failure reporting + async response contract validation
-- Uses ngx.timer.at for fire-and-forget POST to Java control plane.
-- Two-layer dedup: Lua shared_dict (first), Java Redis TTL (safety net).

local cjson  = require("cjson.safe")
local http   = require("resty.http")
local dedup  = require("dedup")
local config = require("config")
local pd_mod = require("problem_detail")
local pii    = require("pii_redact")

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

-- ── Timer callback: report a batch of observed topology edges ────────────────

local function report_edge_observations(premature, data)
    if premature then return end

    local ok, err = pcall(post_json,
        CONTROL_PLANE_BASE .. "/api/internal/edge-observations", data)
    if not ok then
        ngx.log(ngx.ERR, "log.lua: report_edge_observations error: ", err)
    end
end

--- Propagated W3C/B3 trace context, preferred over Mendr's correlationId for
--- cross-hop caller->callee attribution (never timing).
local function resolve_traceparent(envelope)
    if ngx.ctx.traceparent and ngx.ctx.traceparent ~= "" then
        return ngx.ctx.traceparent
    end
    local h = (envelope and envelope.headers) or ngx.req.get_headers() or {}
    return h["traceparent"] or h["Traceparent"]
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

-- Envelope-path endpoints may be concrete; canonicalize to the route template
-- (when the pair tree knows it) so failure dedup + reporting key on the template,
-- matching the ingress path (which already reports endpoint_template).
if source ~= "" and target ~= "" and ep ~= "" and ep:find("{", 1, true) == nil then
    local ok_rt, ingress_rt = pcall(require, "ingress_routing")
    if ok_rt and ingress_rt and ingress_rt.match_pair then
        local ok_m, tmpl = pcall(ingress_rt.match_pair, source, target, ep)
        if ok_m and tmpl and tmpl ~= "" then
            ep = tmpl
            ngx.ctx.reportEndpoint = tmpl
        end
    end
end

-- Circuit breaker + Prometheus metrics + OTel export (Phases 1 / 5)
do
    local ok_m, metrics = pcall(require, "metrics")
    if ok_m and metrics then
        metrics.inc("mendr_edge_requests_total", {
            status = tostring(status),
            target = target ~= "" and target or "unknown",
        }, 1)
        local start = tonumber(ngx.ctx.request_start_ms)
        if start then
            metrics.observe_latency((ngx.now() * 1000) - start, { target = target })
        end
    end
    local peer = ngx.ctx.selected_peer
    local tp = ngx.ctx.trafficPolicy
    local cb = tp and tp.circuitBreaker
    local ok_c, circuit = pcall(require, "circuit_breaker")
    if ok_c and circuit and peer then
        if status >= 500 or status == 0 then
            circuit.record_failure(peer, cb)
        elseif status < 400 then
            circuit.record_success(peer, cb)
        end
    end
    -- Usage metering (success + error paths)
    do
        local ok_u, usage = pcall(require, "usage_meter")
        if ok_u and usage then
            local start = tonumber(ngx.ctx.request_start_ms)
            local lat = start and ((ngx.now() * 1000) - start) or nil
            local bytes = tonumber(ngx.var.bytes_sent) or 0
            local tenant = ngx.ctx.tenant_id or ngx.ctx.tenantId
                or os.getenv("MENDR_TENANT_ID") or "default"
            usage.record(tenant, target, ep, status, bytes, lat)
        end
    end
    -- Bot error-burst counter
    if status >= 400 and status < 500 then
        local ok_b, bot = pcall(require, "bot_detect")
        if ok_b and bot and bot.record_error then
            bot.record_error(status)
        end
    end
    -- Response cache store on success
    if status >= 200 and status < 300 and ngx.ctx.routeConfig then
        local ok_rc, response_cache = pcall(require, "response_cache")
        if ok_rc and response_cache and ngx.ctx.rawResponseBody then
            local cache_body = ngx.ctx.rawResponseBody
            if type(ngx.ctx.transformedResponseBody) == "table" then
                local enc = cjson.encode(ngx.ctx.transformedResponseBody)
                if enc then cache_body = enc end
            end
            response_cache.put(ngx.ctx.routeConfig, method, status,
                cache_body, ngx.header.content_type)
        end
        local ok_ai, ai_gateway = pcall(require, "ai_gateway")
        if ok_ai and ai_gateway and ngx.ctx.ai_semantic_cache_key and ngx.ctx.rawResponseBody then
            ai_gateway.store_semantic_cache(ngx.ctx.rawResponseBody, ngx.header.content_type)
        end
    end
    local ok_o, otel = pcall(require, "otel")
    if ok_o and otel then
        otel.end_and_export(status)
    end
end

-- ── 1. Failure reporting (status >= 400, or splice abort after flush) ────────

local function schedule_failure_report(category, error_code, err_msg, response_payload, status_override)
    local suppressed
    local should, supp = dedup.should_process("fail", source, target, ep, 60, category)
    if not should then
        return
    end
    suppressed = supp or 0

    local report_status = status_override or status

    local cors_blocked_at = ngx.ctx.corsBlockedAt
    if category == "CORS_UPSTREAM" then
        cors_blocked_at = "UPSTREAM"
    elseif category == "CORS" and cors_blocked_at == nil then
        cors_blocked_at = "EDGE"
    end

    local problem_detail, corr, req_id = build_problem_detail(report_status, envelope, category, source, target, ep)
    if not err_msg or err_msg == "" then
        err_msg = extract_error_message(status, envelope)
        if problem_detail.detail and problem_detail.detail ~= "" then
            err_msg = problem_detail.detail
        end
    end

    local failure_data = {
        sourceService      = source,
        targetService      = target,
        endpoint           = ep,
        httpMethod         = method,
        errorCode          = error_code or report_status,
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
        responsePayload    = response_payload or ngx.ctx.upstreamErrorBody,
        correlationId      = corr,
        requestId          = req_id,
        traceparent        = resolve_traceparent(envelope),
        responseHeaders    = ngx.ctx.upstreamResponseHeaders,
        problemDetail      = problem_detail,
        suppressedCount    = suppressed > 0 and suppressed or nil,
    }
    failure_data = pii.scrub(failure_data)

    local ok, err = ngx.timer.at(0, report_failure, failure_data)
    if not ok then
        ngx.log(ngx.ERR, "log.lua: failed to schedule failure report timer: ", err)
    end
end

if status >= 400 then
    schedule_failure_report(classify_failure(status, envelope), status, nil, nil)
elseif ngx.ctx.splice_abort_after_flush then
    local reason = ngx.ctx.spliceAbortReason or "after_flush"
    -- Use 502 for problem-detail + errorCode even when ngx.status is still 200.
    schedule_failure_report(
        "SPLICE",
        502,
        "Splice fault after flush; connection aborted (incomplete response): " .. tostring(reason),
        { spliceAbort = true, reason = reason },
        502
    )
end

-- ── 2. Async response contract validation (status < 400, hasResponseContract) ──

if status < 400 and ngx.ctx.hasResponseContract then
    -- Skip async validation if this route uses per-route sync validation
    -- (syncValidation is handled by the Java proxy path, not OpenResty)
    if not ngx.ctx.syncValidation then
        if dedup.should_process("validate", source, target, ep, 60) then
            local raw_resp         = ngx.ctx.rawResponseTable or ngx.ctx.rawResponseBody
            local transformed_resp = ngx.ctx.transformedResponseBody

            -- Only send if we have bodies to validate
            if raw_resp or transformed_resp then
                -- Prefer decoded tables; decode string cache body if needed
                if type(raw_resp) == "string" then
                    local decoded = cjson.decode(raw_resp)
                    if decoded then raw_resp = decoded end
                end
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

-- ── 3. Sampled edge observation (TRAFFIC_OBSERVED topology tier) ─────────────
-- An edge exists whether or not this call failed, so this runs on any proxied
-- call with a resolved source+target. Attribution is Mendr's own routing envelope
-- (source->target) — reliable, not timing-based — while trace context rides along
-- for downstream causal correlation. Sampling + a per-edge dedup window cap volume;
-- the endpoint accepts a batch so this can later flush from a shared dict.

if config.edge_observation_enabled() and source ~= "" and target ~= "" then
    local sample_rate = config.edge_observation_sample_rate()
    if math.random() < sample_rate then
        -- Dedup window caps to at most one observation per edge per 5 min.
        if dedup.should_process("edgeobs", source, target, ep, 300) then
            local corr = ngx.ctx.correlationId
                or (envelope.headers and (envelope.headers["X-Correlation-Id"]
                    or envelope.headers["x-correlation-id"]
                    or envelope.headers["X-Request-Id"]
                    or envelope.headers["x-request-id"]))
            local observation = {
                sourceService = source,
                targetService = target,
                endpoint      = ep,
                httpMethod    = method,
                statusCode    = status,
                correlationId = corr,
                requestId     = ngx.ctx.requestId or corr,
                traceparent   = resolve_traceparent(envelope),
                observedAt    = ngx.utctime(),
            }
            -- Batch-shaped payload (list of one today; shared-dict batching can slot in here).
            local ok, err = ngx.timer.at(0, report_edge_observations, { observations = { observation } })
            if not ok then
                ngx.log(ngx.ERR, "log.lua: failed to schedule edge-observation timer: ", err)
            end
        end
    end
end
