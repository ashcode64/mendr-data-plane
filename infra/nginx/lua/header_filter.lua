-- header_filter.lua — CORS response headers + content-length fix for body transforms

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
