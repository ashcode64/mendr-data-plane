-- body_policy.lua — Pure decision for whether body_filter must retain the
-- response (P1). Extracted so cache / validate / 4xx policy is unit-testable
-- without ngx.

local _M = {}

--- Returns need_body, will_transform.
-- opts: program, status, hasResponseContract, syncValidation,
--       peek_validate, should_cache, ai_semantic_cache_key
function _M.need_response_body(opts)
    opts = opts or {}
    local program = opts.program
    local will_transform = false
    if type(program) == "table" and not program.empty then
        local ok_pc, plan_class = pcall(require, "plan_class")
        if ok_pc and plan_class and plan_class.classify then
            local c = plan_class.classify(program)
            -- PASSTHROUGH keeps Content-Length. PREFILTERABLE still clears it:
            -- a hit rewrites bytes and a miss is not knowable in header_filter.
            will_transform = c.planClass ~= nil and c.planClass ~= "PASSTHROUGH"
        else
            will_transform = true
        end
    end
    if will_transform then
        return true, true
    end
    if (tonumber(opts.status) or 0) >= 400 then
        return true, false
    end
    if opts.hasResponseContract and not opts.syncValidation and opts.peek_validate then
        return true, false
    end
    if opts.should_cache then
        return true, false
    end
    if opts.ai_semantic_cache_key then
        return true, false
    end
    return false, false
end

return _M
