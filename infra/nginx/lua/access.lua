-- access.lua — Envelope front-end for POST /api/gateway/proxy.
-- Decodes the Mendr envelope, builds ctx, delegates to proxy_core.run.

local cjson      = require("cjson.safe")
local proxy_core = require("proxy_core")

local function stash_report_envelope(partial)
    -- Ensure log.lua can POST /failures for early native rejects.
    -- Always capture real request headers (Origin / corr) even when body never decoded.
    local headers = (partial and partial.headers)
        or ngx.req.get_headers()
        or {}
    ngx.ctx.envelope = {
        sourceService = (partial and partial.sourceService) or "unknown",
        targetService = (partial and partial.targetService) or "unknown",
        endpoint      = (partial and partial.endpoint) or ngx.var.uri or "/",
        method        = (partial and partial.method) or ngx.req.get_method() or "POST",
        payload       = (partial and partial.payload) or {},
        headers       = headers,
    }
    if partial and partial.payload then
        ngx.ctx.requestPayload = partial.payload
    end
end

ngx.req.read_body()
local body_data = ngx.req.get_body_data()
if not body_data then
    -- Large body may have spilled to a temp file
    local file_path = ngx.req.get_body_file()
    if file_path then
        local f = io.open(file_path, "rb")
        if f then
            body_data = f:read("*a")
            f:close()
        end
    end
end
if not body_data then
    stash_report_envelope(nil)
    return proxy_core.json_error(400, "BAD_REQUEST", "Empty request body", false)
end

local envelope, err = cjson.decode(body_data)
if not envelope then
    stash_report_envelope(nil)
    return proxy_core.json_error(400, "BAD_REQUEST", "Invalid JSON: " .. (err or "unknown"), false)
end

-- Stash before required-field checks so missing-field rejects still report.
stash_report_envelope(envelope)

local ctx = {
    source_service = envelope.sourceService,
    target_service = envelope.targetService,
    endpoint       = envelope.endpoint,
    method         = envelope.method or "GET",
    payload        = envelope.payload or {},
    headers        = envelope.headers or {},
    mode           = "envelope",
    concrete_path  = envelope.endpoint,  -- envelope already uses the path as-is
    has_body       = true,               -- envelope always carries a JSON payload object
    is_json        = true,               -- upstream body is always JSON (the payload)
}

if not ctx.source_service or not ctx.target_service or not ctx.endpoint then
    return proxy_core.json_error(400, "BAD_REQUEST",
        "Missing required fields: sourceService, targetService, endpoint", false)
end

ngx.ctx.requestPayload = ctx.payload
ngx.header["X-Mendr-Data-Plane"] = "lua"

proxy_core.run(ctx)
