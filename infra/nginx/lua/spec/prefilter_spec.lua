-- P3/P5: prefilter soundness + plan_class classification.
--   cd infra/nginx/lua && lua spec/prefilter_spec.lua

package.path = package.path .. ";../?.lua;./?.lua"
local prefilter = require("prefilter")
local plan_class = require("plan_class")

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
    local v = prefilter.scan('{"amt":1,"other":2}', { "amt" })
    check("unescaped present key is hit", v == "hit")
end

do
    local v = prefilter.scan('{"other":2}', { "amt" })
    check("absent literal is miss", v == "miss")
end

do
    local v = prefilter.scan('{"user\\u005fname":1}', { "user_name" })
    check("escaped key unescapes to hit", v == "hit")
    check("escaped miss is not skip", not prefilter.should_skip('{"user\\u005fname":1}', {
        planClass = "PREFILTERABLE", prefilterable = true, prefilterLiterals = { "user_name" },
    }))
end

do
    local v = prefilter.scan('{"x":"amt\\nvalue"}', { "amt" })
    check("backslash in string value is not a key hit", v == "miss")
    check("value escape still skippable", prefilter.should_skip('{"x":"amt\\nvalue"}', {
        planClass = "PREFILTERABLE", prefilterable = true, prefilterLiterals = { "amt" },
    }))
end

do
    check("should_skip on miss", prefilter.should_skip('{"x":1}', {
        planClass = "PREFILTERABLE", prefilterable = true, prefilterLiterals = { "amt" },
    }))
end

do
    local c = plan_class.classify({ empty = false, ops = {
        { op = "rename", from = "/amt", to = "/amount" },
    }})
    check("rename is PREFILTERABLE", c.planClass == "PREFILTERABLE")
end

do
    local c = plan_class.classify({ empty = false, ops = {
        { op = "wrap", key = "data" },
    }})
    check("wrap is FORWARD_ONLY", c.planClass == "FORWARD_ONLY")
    check("wrap not prefilterable", c.prefilterable == false)
end

do
    local c = plan_class.classify({ empty = false, ops = {
        { op = "move", from = "/a/b", to = "/c" },
    }})
    check("cross-parent move is UNBOUNDED", c.planClass == "UNBOUNDED")
end

do
    local c = plan_class.classify({ empty = false, ops = {
        { op = "move", from = "/user/amt", to = "/user/amount" },
    }})
    check("same-parent move is BOUNDED_WINDOW", c.planClass == "BOUNDED_WINDOW")
end

do
    local c = plan_class.resolve({
        empty = false,
        planClass = "UNBOUNDED",
        ops = { { op = "rename", from = "/amt", to = "/amount" } },
    })
    check("resolve always re-derives", c.planClass == "PREFILTERABLE")
end

do
    local c = plan_class.classify({ empty = false, ops = {
        { op = "conditional", predicate = { op = "exists", path = "/email" },
          ["then"] = { { op = "rename", from = "/a", to = "/b" } },
          otherwise = {} },
    }})
    check("rename-only conditional is PREFILTERABLE", c.planClass == "PREFILTERABLE")
end

print(string.rep("-", 40))
if failures == 0 then
    print("ALL PASSED")
    os.exit(0)
else
    print(failures .. " FAILED")
    os.exit(1)
end
