-- problem_detail.lua — RFC 9457 helpers for Mendr-native + A3 merge (pure Lua, testable).

local _M = {}

local STD = { type = true, title = true, status = true, detail = true, instance = true, extensions = true }

function _M.is_problem_content_type(ct)
    return type(ct) == "string"
        and ct:lower():find("application/problem+json", 1, true) ~= nil
end

--- Mendr-native rejection body (proxy_core.json_error).
function _M.native_problem(opts)
    local error_type = opts.error_type or "error"
    local healing = opts.healing == true
    return {
        type     = "https://mendr.dev/problems/" .. string.lower(tostring(error_type)),
        title    = error_type,
        status   = opts.status,
        detail   = opts.message,
        instance = opts.instance,
        error    = error_type,
        selfHealingTriggered = healing,
        correlationId = opts.correlation_id,
        requestId = opts.request_id,
    }
end

--- Prefer detail over message/error for dual-accept extractors.
function _M.prefer_detail_message(raw)
    if type(raw) ~= "table" then
        return nil
    end
    if raw.detail ~= nil and tostring(raw.detail) ~= "" then
        return tostring(raw.detail)
    end
    if raw.message ~= nil then
        return tostring(raw.message)
    end
    if raw.error ~= nil then
        return tostring(raw.error)
    end
    return nil
end

--- Parse upstream problem+json body into {standard fields + extensions}.
function _M.from_body(raw_body, http_status)
    if type(raw_body) ~= "table" then
        return nil
    end
    local pd = {
        type     = raw_body.type,
        title    = raw_body.title,
        status   = raw_body.status or http_status,
        detail   = raw_body.detail or raw_body.message,
        instance = raw_body.instance,
        extensions = {},
    }
    if type(raw_body.extensions) == "table" then
        for k, v in pairs(raw_body.extensions) do
            pd.extensions[k] = v
        end
    end
    for k, v in pairs(raw_body) do
        if not STD[k] then
            pd.extensions[k] = v
        end
    end
    return pd
end

--- Merge upstream/Mendr pd with Mendr A3 extensions (never overwrite upstream keys).
function _M.merge_a3(upstream, opts)
    local category = opts.category or "UNKNOWN"
    local status = opts.status or 500
    local source = opts.source
    local target = opts.target
    local ep = opts.endpoint or ""
    local corr = opts.correlation_id
    local req_id = opts.request_id
    local detail_fallback = opts.detail_fallback or ("HTTP " .. status)
    local instance_fallback = (ep ~= "" and ep) or opts.request_uri

    local pd
    if type(upstream) == "table" then
        pd = {
            type     = upstream.type or ("https://mendr.dev/problems/" .. string.lower(category)),
            title    = upstream.title or category,
            status   = upstream.status or status,
            detail   = upstream.detail or detail_fallback,
            instance = upstream.instance or instance_fallback,
            extensions = {},
        }
        if type(upstream.extensions) == "table" then
            for k, v in pairs(upstream.extensions) do
                pd.extensions[k] = v
            end
        end
        for k, v in pairs(upstream) do
            if not STD[k] and pd.extensions[k] == nil then
                pd.extensions[k] = v
            end
        end
    else
        pd = {
            type     = "https://mendr.dev/problems/" .. string.lower(category),
            title    = category,
            status   = status,
            detail   = detail_fallback,
            instance = instance_fallback,
            extensions = {},
        }
    end

    local ext = pd.extensions
    if ext.failureCategory == nil then ext.failureCategory = category end
    if ext.sourceService == nil then ext.sourceService = source end
    if ext.targetService == nil then ext.targetService = target end
    if ext.correlationId == nil then ext.correlationId = corr end
    if ext.requestId == nil then ext.requestId = req_id or corr end
    -- Optional diagnostics when known at the edge
    if ext.template_id == nil and opts.template_id ~= nil then
        ext.template_id = opts.template_id
    end
    if ext.json_path == nil and opts.json_path ~= nil then
        ext.json_path = opts.json_path
    end
    return pd
end

--- Simulate /failures payload fields after native json_error + A3 merge (no OpenResty).
function _M.failure_report_shape(native_opts, a3_opts)
    a3_opts = a3_opts or {}
    local problem = _M.native_problem(native_opts)
    local merged = _M.merge_a3(problem, {
        category = a3_opts.category or "MENDR_NATIVE",
        status = native_opts.status,
        source = a3_opts.source or "unknown",
        target = a3_opts.target or "unknown",
        endpoint = a3_opts.endpoint or native_opts.instance,
        correlation_id = native_opts.correlation_id,
        request_id = native_opts.request_id,
        detail_fallback = native_opts.message,
        template_id = a3_opts.template_id,
        json_path = a3_opts.json_path,
    })
    return {
        ContentType = "application/problem+json",
        errorMessage = merged.detail or native_opts.message,
        correlationId = native_opts.correlation_id,
        requestId = native_opts.request_id,
        problemDetail = merged,
    }
end

--- Lift localization keys from a parsed PD onto a ctx-like table (body_filter → ngx.ctx).
function _M.promote_localization(pd, ctx)
    if type(pd) ~= "table" or type(ctx) ~= "table" then
        return ctx
    end
    local ext = pd.extensions
    if type(ext) ~= "table" then
        return ctx
    end
    if ext.template_id ~= nil then ctx.template_id = ext.template_id end
    if ext.json_path ~= nil then ctx.json_path = ext.json_path end
    if ext.templateId ~= nil and ctx.template_id == nil then ctx.template_id = ext.templateId end
    if ext.jsonPath ~= nil and ctx.json_path == nil then ctx.json_path = ext.jsonPath end
    return ctx
end

return _M
