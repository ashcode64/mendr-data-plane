-- P1: cache / validate / 4xx body-retention policy.
--   cd infra/nginx/lua && lua spec/body_policy_spec.lua

package.path = package.path .. ";../?.lua;./?.lua"
local policy = require("body_policy")

local failures = 0
local function check(name, cond)
    if cond then
        print("ok   - " .. name)
    else
        failures = failures + 1
        print("FAIL - " .. name)
    end
end

do
    local need, will = policy.need_response_body({
        program = { empty = true }, status = 200,
    })
    check("empty program passthrough", need == false and will == false)
end

do
    local need, will = policy.need_response_body({
        program = { empty = false, ops = { { op = "rename" } } }, status = 200,
    })
    check("non-empty program buffers and transforms", need == true and will == true)
end

do
    local need, will = policy.need_response_body({
        program = { empty = false, ops = {} }, status = 200,
    })
    check("empty ops is PASSTHROUGH, keep CL", need == false and will == false)
end

do
    local need, will = policy.need_response_body({
        program = { empty = true }, status = 500,
    })
    check("4xx/5xx buffers without transform", need == true and will == false)
end

do
    local need, will = policy.need_response_body({
        program = { empty = true }, status = 200,
        hasResponseContract = true, syncValidation = false, peek_validate = true,
    })
    check("validate peek buffers", need == true and will == false)
end

do
    local need, will = policy.need_response_body({
        program = { empty = true }, status = 200,
        hasResponseContract = true, syncValidation = false, peek_validate = false,
    })
    check("validate already done does not buffer", need == false and will == false)
end

do
    local need, will = policy.need_response_body({
        program = { empty = true }, status = 200, should_cache = true,
    })
    check("response cache buffers", need == true and will == false)
end

do
    local need, will = policy.need_response_body({
        program = { empty = true }, status = 200, ai_semantic_cache_key = "k",
    })
    check("ai semantic cache buffers", need == true and will == false)
end

print(string.rep("-", 40))
if failures == 0 then
    print("ALL PASSED")
    os.exit(0)
else
    print(failures .. " FAILED")
    os.exit(1)
end
