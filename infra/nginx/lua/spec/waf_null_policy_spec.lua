-- waf.lua must tolerate wafPolicy = JSON null (cjson.null userdata in OpenResty).
--   cd infra/nginx/lua && lua spec/waf_null_policy_spec.lua

package.path = package.path .. ";../?.lua;./?.lua"

local failures = 0
local function check(name, cond)
    if cond then
        print("ok   - " .. name)
    else
        failures = failures + 1
        print("FAIL - " .. name)
    end
end

-- Stand-in for cjson.null: truthy userdata that must not be indexed like a table.
local JSON_NULL = setmetatable({}, {
    __tostring = function() return "null" end,
    __index = function()
        error("attempt to index JSON null")
    end,
})

package.preload["metrics"] = function()
    return { inc = function() end }
end
package.preload["bot_detect"] = function()
    return { inspect = function() return true end }
end

_G.ngx = {
    var = {
        content_length = "128",
        request_uri = "/api/ship",
        args = "",
        remote_addr = "127.0.0.1",
    },
    req = { get_headers = function() return { ["user-agent"] = "test" } end },
    log = function() end,
    WARN = 4,
    re = { find = function() return nil end },
}

package.loaded["waf"] = nil
local waf = require("waf")

local ok, err = waf.inspect({ wafPolicy = JSON_NULL }, { payload = { mag_sent = true } })
check("inspect with null wafPolicy does not crash", ok == true)
check("inspect with null wafPolicy returns no error", err == nil)

ok = waf.inspect({ wafPolicy = nil }, { payload = { a = 1 } })
check("inspect with nil wafPolicy", ok == true)

ok = waf.inspect({ wafPolicy = { maxBodyBytes = 2048 } }, { payload = { a = 1 } })
check("inspect with table wafPolicy", ok == true)

if failures > 0 then
    os.exit(1)
end
print("All waf null-policy checks passed")
