-- otel.lua — W3C Trace Context + OTLP/HTTP JSON span export.
-- Creates a SERVER span per request; propagates traceparent upstream;
-- exports asynchronously in log phase to MENDR_OTEL_ENDPOINT (OTLP/HTTP).

local cjson = require("cjson.safe")
local http  = require("resty.http")
local config = require("config")

local _M = {}

local function enabled()
    local flag = os.getenv("MENDR_OTEL_ENABLED")
    return flag == "true" or flag == "1"
end

local function endpoint()
    return os.getenv("MENDR_OTEL_ENDPOINT")
        or (config.control_plane_base() .. "/api/internal/otlp/v1/traces")
end

local function sample_rate()
    local n = tonumber(os.getenv("MENDR_OTEL_SAMPLE_RATE") or "1")
    if not n or n < 0 then return 1 end
    if n > 1 then return 1 end
    return n
end

local function hex_rand(n)
    local t = {}
    for i = 1, n do
        t[i] = string.format("%02x", math.random(0, 255))
    end
    return table.concat(t)
end

local function parse_traceparent(tp)
    if type(tp) ~= "string" then return nil end
    -- version-traceid-spanid-flags
    local ver, tid, sid, flags = tp:match("^(%x%x)%-(%x+)%-(%x+)%-(%x%x)$")
    if not ver or #tid ~= 32 or #sid ~= 16 then return nil end
    return { version = ver, trace_id = tid, parent_span_id = sid, flags = flags }
end

function _M.start_span(route_config)
    if not enabled() then return end
    if math.random() > sample_rate() then
        ngx.ctx.otel_sampled = false
        return
    end
    ngx.ctx.otel_sampled = true
    local headers = ngx.req.get_headers()
    local incoming = parse_traceparent(headers["traceparent"] or headers["Traceparent"])
    local trace_id, parent_span_id
    if incoming then
        trace_id = incoming.trace_id
        parent_span_id = incoming.parent_span_id
    else
        trace_id = hex_rand(16)
        parent_span_id = nil
    end
    local span_id = hex_rand(8)
    ngx.ctx.otel = {
        trace_id = trace_id,
        span_id = span_id,
        parent_span_id = parent_span_id,
        start_ns = ngx.now() * 1e9,
        name = (route_config and route_config.targetService or "mendr")
            .. " " .. (ngx.req.get_method() or "GET"),
        attributes = {
            ["http.method"] = ngx.req.get_method(),
            ["http.route"] = route_config and route_config.endpoint or ngx.var.uri,
            ["http.target"] = ngx.var.request_uri,
            ["net.peer.name"] = route_config and route_config.targetService,
            ["mendr.source"] = route_config and route_config.sourceService,
        },
    }
    -- Propagate W3C to upstream
    local flags = "01"
    local tp = string.format("00-%s-%s-%s", trace_id, span_id, flags)
    ngx.req.set_header("traceparent", tp)
    ngx.ctx.traceparent = tp
end

local function redacted_attrs(attrs)
    -- Never export Authorization / cookies / bodies
    local out = {}
    for k, v in pairs(attrs or {}) do
        local lk = string.lower(tostring(k))
        if not lk:find("auth", 1, true) and not lk:find("cookie", 1, true)
           and not lk:find("password", 1, true) and not lk:find("secret", 1, true)
           and not lk:find("token", 1, true) then
            out[#out + 1] = {
                key = tostring(k),
                value = { stringValue = tostring(v or "") },
            }
        end
    end
    return out
end

function _M.end_and_export(status)
    local span = ngx.ctx.otel
    if not span or not ngx.ctx.otel_sampled then return end
    local end_ns = ngx.now() * 1e9
    span.attributes["http.status_code"] = status or ngx.status
    local payload = {
        resourceSpans = {{
            resource = {
                attributes = {
                    { key = "service.name", value = { stringValue = "mendr-data-plane" } },
                    { key = "service.version", value = { stringValue = "1.0.0" } },
                },
            },
            scopeSpans = {{
                scope = { name = "mendr.edge", version = "1.0.0" },
                spans = {{
                    traceId = span.trace_id,
                    spanId = span.span_id,
                    parentSpanId = span.parent_span_id,
                    name = span.name,
                    kind = 2, -- SERVER
                    startTimeUnixNano = string.format("%.0f", span.start_ns),
                    endTimeUnixNano = string.format("%.0f", end_ns),
                    attributes = redacted_attrs(span.attributes),
                    status = {
                        code = (status and status >= 500) and 2 or 1,
                    },
                }},
            }},
        }},
    }

    local body = cjson.encode(payload)
    if not body then return end
    local url = endpoint()
    local ok, err = ngx.timer.at(0, function(premature)
        if premature then return end
        local httpc = http.new()
        httpc:set_timeout(3000)
        local headers = {
            ["Content-Type"] = "application/json",
        }
        local api_key = config.internal_api_key()
        if api_key then headers["X-Internal-Api-Key"] = api_key end
        local res, rerr = httpc:request_uri(url, {
            method = "POST",
            body = body,
            headers = headers,
        })
        if not res then
            ngx.log(ngx.WARN, "otel: export failed: ", rerr)
        elseif res.status >= 400 then
            ngx.log(ngx.WARN, "otel: export HTTP ", res.status)
        end
    end)
    if not ok then
        ngx.log(ngx.WARN, "otel: schedule failed: ", err)
    end
end

return _M
