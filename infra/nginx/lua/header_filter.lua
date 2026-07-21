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

if ngx.ctx.responseProgram or ngx.ctx.hasResponseContract then
    ngx.header.content_length = nil
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
