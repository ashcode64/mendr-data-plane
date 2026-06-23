-- log.lua — Async failure reporting + async response contract validation
-- Uses ngx.timer.at for fire-and-forget POST to Java control plane.
-- Two-layer dedup: Lua shared_dict (first), Java Redis TTL (safety net).

local cjson  = require("cjson.safe")
local http   = require("resty.http")
local dedup  = require("dedup")
local config = require("config")

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
            if raw.message then return tostring(raw.message) end
            if raw.error then return tostring(raw.error) end
            if raw.detail then return tostring(raw.detail) end
        elseif type(raw) == "string" and raw ~= "" then
            return raw
        end
    end

    return "HTTP " .. status .. " from " .. (envelope.targetService or "") .. (envelope.endpoint or "")
end

local function classify_failure(status, envelope)
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

-- ── Main ────────────────────────────────────────────────────────────────────

if ngx.ctx.javaFallback then
    return
end

local envelope = ngx.ctx.envelope
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

        -- If CORS failure was already set in access.lua
        if ngx.ctx.failureCategory then
            category = ngx.ctx.failureCategory
        end

        local cors_blocked_at = ngx.ctx.corsBlockedAt
        if category == "CORS_UPSTREAM" then
            cors_blocked_at = "UPSTREAM"
        elseif category == "CORS" and cors_blocked_at == nil then
            cors_blocked_at = "EDGE"
        end

        local failure_data = {
            sourceService      = source,
            targetService      = target,
            endpoint           = ep,
            httpMethod         = method,
            errorCode          = status,
            errorType          = category .. "_FAILURE",
            failureCategory    = category,
            errorMessage       = extract_error_message(status, envelope),
            requestPayload     = ngx.ctx.requestPayload,
            attemptedUrl       = ngx.var.target_upstream,
            targetServiceUrl   = ngx.ctx.targetServiceUrl,
            registeredBaseUrl  = ngx.ctx.registeredBaseUrl,
            requestOrigin      = envelope.headers and (envelope.headers.Origin or envelope.headers.origin),
            upstreamOriginSent = ngx.ctx.outboundOrigin,
            corsBlockedAt      = cors_blocked_at,
            responsePayload    = ngx.ctx.upstreamErrorBody,
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
                }

                local ok, err = ngx.timer.at(0, validate_response, validate_data)
                if not ok then
                    ngx.log(ngx.ERR, "log.lua: failed to schedule validate timer: ", err)
                end
            end
        end
    end
end
