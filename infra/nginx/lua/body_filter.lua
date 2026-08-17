-- body_filter.lua — Response accumulation, transforms, and error-body capture.
-- P1: buffer only when header_filter set ngx.ctx.need_response_body.
-- P3/P4: PREFILTERABLE miss can passthrough a single-chunk body; FORWARD_ONLY
-- and BOUNDED_WINDOW use splice.feed (emit across chunks when structural).
-- UNBOUNDED and response-contract routes keep the DOM + undo-log path.

local cjson     = require("cjson.safe")
local transform = require("transform")

if ngx.ctx.javaFallback then
    return
end

local program = ngx.ctx.responseProgram
local status = ngx.status

local chunk = ngx.arg[1]
local eof   = ngx.arg[2]

local function rss_kb()
    local f = io.open("/proc/self/statm", "r")
    if f then
        local line = f:read("*l")
        f:close()
        if line then
            local pages = tonumber(line:match("^%S+%s+(%S+)"))
            if pages then return pages * 4 end
        end
    end
    return collectgarbage("count")
end

-- T0 is the first upstream body chunk seen in this filter. For passthrough
-- ngx.arg[1] is left untouched, so the first non-empty chunk is also the
-- first client byte (TTFB ≈ upstream TTFB).
local function mark_ttfb()
    if not ngx.ctx._up_body_t0 then
        ngx.ctx._up_body_t0 = ngx.now()
    end
end

local function note_client_first_byte()
    if ngx.ctx.ttfb_ms then return end
    local t0 = ngx.ctx._up_body_t0
    if t0 then
        ngx.ctx.ttfb_ms = (ngx.now() - t0) * 1000
    end
end

local need = ngx.ctx.need_response_body
if need == nil then
    need = true
end

if not need then
    mark_ttfb()
    if chunk and chunk ~= "" then
        if not ngx.ctx._passthrough_len then ngx.ctx._passthrough_len = 0 end
        ngx.ctx._passthrough_len = ngx.ctx._passthrough_len + #chunk
        note_client_first_byte()
    end
    if eof then
        ngx.ctx.rawResponseBody = nil
        ngx.ctx.transformedResponseBody = nil
        ngx.ctx.stream_passthrough = true
        if not ngx.ctx.ttfb_ms then note_client_first_byte() end
    end
    return
end

local ok_pc, plan_class = pcall(require, "plan_class")
local classified = (ok_pc and plan_class and plan_class.classify(program))
    or { planClass = "UNBOUNDED" }

local function splice_class(pc)
    return pc == "FORWARD_ONLY" or pc == "PREFILTERABLE" or pc == "BOUNDED_WINDOW"
end

-- Cap on the original body retained for a not-yet-flushed splice (value/window
-- programs that hold). Above this we spill to the DOM path (fail-open).
local PREFLUSH_CAP = 1024 * 1024

local function run_dom(full_body)
    local function emit_original()
        ngx.arg[1] = full_body
    end

    ngx.ctx.rawResponseBody = full_body

    local raw_body, decode_err = cjson.decode(full_body)
    if not raw_body then
        ngx.log(ngx.WARN, "body_filter: response is not valid JSON, passing through: ", decode_err)
        if status >= 400 then
            ngx.ctx.upstreamErrorBody = { raw = full_body }
            local ct = (ngx.ctx.upstreamContentType or ""):lower()
            if ct:find("application/problem+json", 1, true) then
                ngx.log(ngx.WARN, "body_filter: problem+json declared but body not valid JSON")
            end
        end
        emit_original()
        return
    end

    ngx.ctx.rawResponseTable = nil

    if status >= 400 then
        ngx.ctx.upstreamErrorBody = { raw = raw_body }
        local pd_mod = require("problem_detail")
        local ct = ngx.ctx.upstreamContentType or ""
        if type(raw_body) == "table" and pd_mod.is_problem_content_type(ct) then
            local pd = pd_mod.from_body(raw_body, status)
            ngx.ctx.upstreamProblemDetail = pd
            pd_mod.promote_localization(pd, ngx.ctx)
        end
        emit_original()
        return
    end

    if not program or program.empty then
        ngx.ctx.transformedResponseBody = raw_body
        emit_original()
        return
    end

    local ok_st, stream_xf = pcall(require, "streaming_transform")
    local flat_ok = ok_st and stream_xf and stream_xf.is_flat_eligible(program)
    if flat_ok then
        local route_config = ngx.ctx.routeConfig
        local violation = transform.protected_violation(
            program, route_config and route_config.protectedPaths)
        if violation then
            ngx.log(ngx.ERR, "body_filter: REFUSING response program — touches protected path '",
                violation, "'")
            ngx.ctx.protectedPathViolation = violation
            emit_original()
            return
        end
        local transformed = stream_xf.apply_flat(raw_body, program)
        if transformed then
            ngx.ctx.transformedResponseBody = transformed
            ngx.ctx.stream_flat_applied = true
            local encoded = stream_xf.encode(transformed)
            if encoded then
                ngx.arg[1] = encoded
                return
            end
        end
    end

    local route_config = ngx.ctx.routeConfig
    local violation = transform.protected_violation(
        program, route_config and route_config.protectedPaths)
    if violation then
        ngx.log(ngx.ERR, "body_filter: REFUSING response program — touches protected path '",
            violation, "'")
        ngx.ctx.protectedPathViolation = violation
        emit_original()
        return
    end

    local t0 = ngx.now()
    local rss0 = collectgarbage("count")
    local ok, transformed = pcall(transform.apply_program, raw_body, program)
    ngx.ctx.transform_ms = (ngx.now() - t0) * 1000
    ngx.ctx.transform_rss_kb = collectgarbage("count") - rss0
    if not ok or transformed == nil then
        ngx.log(ngx.ERR, "body_filter: response transform errored, passing original "
            .. "(fail-open): ", tostring(transformed))
        emit_original()
        return
    end
    ngx.ctx.transformedResponseBody = transformed

    local encoded, encode_err = cjson.encode(transformed)
    if not encoded then
        ngx.log(ngx.ERR, "body_filter: failed to re-encode transformed response: ", encode_err)
        emit_original()
        return
    end

    ngx.arg[1] = encoded
end

local will_splice = program and not program.empty and status < 400
    and splice_class(classified.planClass)
    -- Contract validation needs the upstream original (architecture: UNBOUNDED).
    and not ngx.ctx.hasResponseContract

if will_splice then
    local route_config = ngx.ctx.routeConfig
    if not ngx.ctx._splice_protected_checked then
        ngx.ctx._splice_protected_checked = true
        local violation = transform.protected_violation(
            program, route_config and route_config.protectedPaths)
        if violation then
            ngx.log(ngx.ERR, "body_filter: REFUSING response program — touches protected path '",
                violation, "'")
            ngx.ctx.protectedPathViolation = violation
            ngx.ctx._resp_chunks = ngx.ctx._resp_chunks or {}
            if chunk and chunk ~= "" then
                table.insert(ngx.ctx._resp_chunks, chunk)
            end
            ngx.arg[1] = nil
            if eof then
                run_dom(table.concat(ngx.ctx._resp_chunks))
            end
            return
        end
    end

    mark_ttfb()

    -- PREFILTERABLE single-chunk miss: skip the scanner entirely (O(chunk)).
    -- Multi-chunk miss streams through splice (verbatim copy, O(carry+depth)).
    if classified.planClass == "PREFILTERABLE" and not ngx.ctx._splice_state and eof then
        local ok_pf, prefilter = pcall(require, "prefilter")
        local pf_opts = {
            planClass = classified.planClass,
            prefilterable = true,
            prefilterLiterals = classified.prefilterLiterals or program.prefilterLiterals,
        }
        local body = chunk or ""
        if ok_pf and prefilter and prefilter.should_skip(body, pf_opts) then
            ngx.ctx.stream_prefilter_miss = true
            ngx.ctx.rawResponseBody = body
            note_client_first_byte()
            return
        end
    end

    local ok_sp, splice = pcall(require, "splice")
    if not ok_sp or not splice then
        ngx.ctx._resp_chunks = ngx.ctx._resp_chunks or {}
        if chunk and chunk ~= "" then table.insert(ngx.ctx._resp_chunks, chunk) end
        ngx.arg[1] = nil
        if eof then run_dom(table.concat(ngx.ctx._resp_chunks)) end
        return
    end

    local st = ngx.ctx._splice_state
    if not st then
        st = { program = program }
        ngx.ctx._splice_state = st
        ngx.ctx._splice_t0 = ngx.now()
        ngx.ctx._splice_rss0 = rss_kb()
    end

    if ngx.ctx._splice_spill then
        if st.flushed then
            ngx.arg[1] = nil
            return
        end
        st.buf = (st.buf or "") .. (chunk or "")
        ngx.arg[1] = nil
        if eof then
            ngx.ctx.rawResponseBody = st.buf
            run_dom(st.buf or "")
        end
        return
    end

    ngx.arg[1] = nil
    local _, err = splice.feed(st, chunk, eof)
    if err == "fail_closed" or st.fail_closed then
        if st.flushed then
            ngx.log(ngx.WARN, "body_filter: splice fail-closed after flush; leaving prefix")
            ngx.arg[1] = nil
            return
        end
        ngx.ctx.rawResponseBody = st.buf
        if eof then
            ngx.arg[1] = st.buf or ""
            note_client_first_byte()
        end
        return
    end
    if err then
        if st.flushed then
            ngx.log(ngx.WARN, "body_filter: splice error after flush (", tostring(err),
                "); not concatenating original")
            ngx.arg[1] = nil
            return
        end
        ngx.ctx._splice_spill = err
        ngx.log(ngx.WARN, "body_filter: splice failed, spilling to DOM: ", tostring(err))
        ngx.arg[1] = nil
        if eof then
            ngx.ctx.rawResponseBody = st.buf
            run_dom(st.buf or "")
        end
        return
    end
    if not eof then
        if not st.must_hold then
            local drained = splice.drain(st)
            if drained and drained ~= "" then
                ngx.arg[1] = drained
                note_client_first_byte()
            end
        end
        -- Bound pre-flush buffering: if we are holding (value/window) and the
        -- retained original exceeds the cap before any flush, spill to DOM
        -- (safe: nothing sent yet). Keeps memory O(cap), not O(N).
        if not st.flushed and st.buf and #st.buf > PREFLUSH_CAP then
            ngx.ctx._splice_spill = "preflush_cap"
            ngx.log(ngx.WARN, "body_filter: pre-flush buffer exceeded cap, spilling to DOM")
            ngx.arg[1] = nil
        end
        return
    end

    ngx.ctx.rawResponseBody = splice.output(st)
    ngx.ctx.splice_ms = ngx.ctx._splice_t0 and ((ngx.now() - ngx.ctx._splice_t0) * 1000) or 0
    ngx.ctx.splice_rss_kb = ngx.ctx._splice_rss0 and (rss_kb() - ngx.ctx._splice_rss0) or 0
    ngx.ctx.ttfb_ms = ngx.ctx.ttfb_ms or ngx.ctx.splice_ms

    local rest = splice.drain(st)
    ngx.arg[1] = rest or ""
    if rest and rest ~= "" then note_client_first_byte() end
    ngx.ctx.stream_splice_applied = true
    local encoded = splice.output(st)
    ngx.ctx.transformedResponseBody = (encoded and cjson.decode(encoded)) or encoded
    return
end

if not ngx.ctx._resp_chunks then
    ngx.ctx._resp_chunks = {}
end

if chunk and chunk ~= "" then
    table.insert(ngx.ctx._resp_chunks, chunk)
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

run_dom(full_body)
