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

    if not has_flat_ops then
        ngx.ctx.transformedResponseBody = raw_body
        ngx.arg[1] = full_body
        return
    end
end

local transformed = transform.apply_program(transform.shallow_copy(raw_body), program)
ngx.ctx.transformedResponseBody = transformed

local encoded, encode_err = cjson.encode(transformed)
if not encoded then
    ngx.log(ngx.ERR, "body_filter: failed to re-encode transformed response: ", encode_err)
    ngx.arg[1] = full_body
    return
end

ngx.arg[1] = encoded
