-- body_filter.lua — Response accumulation, transforms, and error-body capture

local cjson     = require("cjson.safe")
local transform = require("transform")

if ngx.ctx.javaFallback then
    return
end

local program = ngx.ctx.responseProgram
local has_contract = ngx.ctx.hasResponseContract
local status = ngx.status

local chunk = ngx.arg[1]
local eof   = ngx.arg[2]

if not ngx.ctx._resp_chunks then
    ngx.ctx._resp_chunks = {}
end

if chunk and chunk ~= "" then
    table.insert(ngx.ctx._resp_chunks, chunk)
    -- Always suppress the per-chunk passthrough. The full body is re-emitted once
    -- at EOF below; without this the response is sent twice (duplicated JSON).
    ngx.arg[1] = nil
end

if not eof then
    return
end

local full_body = table.concat(ngx.ctx._resp_chunks)
ngx.ctx._resp_chunks = nil

if full_body == "" then
    ngx.arg[1] = full_body
    return
end

local raw_body, decode_err = cjson.decode(full_body)
if not raw_body then
    ngx.log(ngx.WARN, "body_filter: response is not valid JSON, passing through: ", decode_err)
    if status >= 400 then
        ngx.ctx.upstreamErrorBody = { raw = full_body }
    end
    ngx.arg[1] = full_body
    return
end

ngx.ctx.rawResponseBody = raw_body

if status >= 400 then
    ngx.ctx.upstreamErrorBody = { raw = raw_body }
    ngx.arg[1] = full_body
    return
end

if not program then
    ngx.ctx.transformedResponseBody = raw_body
    ngx.arg[1] = full_body
    return
end

if not program.streamable and not program.wrapKey and not program.unwrapKey then
    local has_flat_ops = false
    if program.renames and next(program.renames) then has_flat_ops = true end
    if program.defaults and next(program.defaults) then has_flat_ops = true end
    if program.coercions and next(program.coercions) then has_flat_ops = true end
    if program.removals and type(program.removals) == "table" and #program.removals > 0 then has_flat_ops = true end
    if program.moves and type(program.moves) == "table" and #program.moves > 0 then has_flat_ops = true end
    if program.scales and type(program.scales) == "table" and #program.scales > 0 then has_flat_ops = true end
    if program.coalesce and type(program.coalesce) == "table" and #program.coalesce > 0 then has_flat_ops = true end
    if program.valueMaps and type(program.valueMaps) == "table" and #program.valueMaps > 0 then has_flat_ops = true end
    if program.dateFormats and type(program.dateFormats) == "table" and #program.dateFormats > 0 then has_flat_ops = true end
    if program.stripUnknown and type(program.stripUnknown) == "table" and #program.stripUnknown > 0 then has_flat_ops = true end
    if program.wrapArrays and type(program.wrapArrays) == "table" and #program.wrapArrays > 0 then has_flat_ops = true end
    if program.unwrapArrays and type(program.unwrapArrays) == "table" and #program.unwrapArrays > 0 then has_flat_ops = true end

    if not has_flat_ops then
        ngx.ctx.transformedResponseBody = raw_body
        ngx.arg[1] = full_body
        return
    end
end

-- Independent protected-path backstop (§3) + fail-open (§4.11), response side.
local route_config = ngx.ctx.routeConfig
local violation = transform.protected_violation(
    program, route_config and route_config.protectedPaths)
if violation then
    ngx.log(ngx.ERR, "body_filter: REFUSING response program — touches protected path '",
        violation, "'")
    ngx.ctx.protectedPathViolation = violation
    ngx.arg[1] = full_body
    return
end

local ok, transformed = pcall(transform.apply_program, transform.shallow_copy(raw_body), program)
if not ok or transformed == nil then
    ngx.log(ngx.ERR, "body_filter: response transform errored, passing original "
        .. "(fail-open): ", tostring(transformed))
    ngx.arg[1] = full_body
    return
end
ngx.ctx.transformedResponseBody = transformed

local encoded, encode_err = cjson.encode(transformed)
if not encoded then
    ngx.log(ngx.ERR, "body_filter: failed to re-encode transformed response: ", encode_err)
    ngx.arg[1] = full_body
    return
end

ngx.arg[1] = encoded
