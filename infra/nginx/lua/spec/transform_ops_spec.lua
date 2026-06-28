-- Functional spec for the MendrScript closed-opcode interpreter in transform.lua.
-- Runnable with a plain Lua interpreter (cjson is optional; transform.lua falls
-- back to a JSON_NULL sentinel). Mirrors the Java MendrScriptExecutorTest cases so
-- the two runtimes stay in lock-step — this is the seed of the differential
-- conformance suite (Gap 3 / cross-runtime parity).
--
--   cd infra/nginx/lua && lua spec/transform_ops_spec.lua

package.path = package.path .. ";../?.lua;./?.lua"
local T = require("transform")

local failures = 0
local function check(name, cond)
    if cond then
        print("ok   - " .. name)
    else
        failures = failures + 1
        print("FAIL - " .. name)
    end
end

local function prog(ops) return { empty = false, ops = ops } end

-- 1) rename + default
do
    local out = T.apply_program({ userName = "jo" }, prog({
        { op = "rename", from = "/userName", to = "/user_name" },
        { op = "default", path = "/active", value = true, on = "ABSENT" },
    }))
    check("rename moves value", out.user_name == "jo" and out.userName == nil)
    check("default fills absent", out.active == true)
end

-- 2) scale within bounds (2500 * 1/100 = 25, integral)
do
    local out = T.apply_program({ amount = 2500 }, prog({
        { op = "scale", path = "/amount", numerator = 1, denominator = 100,
          expectedMin = 0, expectedMax = 1000000 },
    }))
    check("scale applies rational factor", out.amount == 25)
end

-- 3) scale post-condition violation -> fail closed (original preserved)
do
    local out = T.apply_program({ amount = 50 }, prog({
        { op = "scale", path = "/amount", numerator = 1000, denominator = 1,
          expectedMin = 0, expectedMax = 100 },
    }))
    check("scale postcondition fails closed", out.amount == 50)
end

-- 4) conditional on matches_format email
do
    local mk = function() return prog({
        { op = "conditional",
          predicate = { op = "matches_format", path = "/email", format = "email" },
          ["then"] = { { op = "default", path = "/verified", value = true, on = "ABSENT" } },
          otherwise = { { op = "default", path = "/verified", value = false, on = "ABSENT" } } },
    }) end
    local ok = T.apply_program({ email = "a@b.com" }, mk())
    local bad = T.apply_program({ email = "nope" }, mk())
    check("conditional then-branch on format match", ok.verified == true)
    check("conditional else-branch on format miss", bad.verified == false)
end

-- 5) protected-path scan rejects an op touching /authorization
do
    local hit = T.protected_violation(prog({ { op = "rename", from = "/authorization", to = "/auth" } }))
    check("protected-path scan walks ops[]", hit == "authorization")
end

-- 5b) protected path hidden inside a conditional branch is still caught
do
    local hit = T.protected_violation(prog({
        { op = "conditional", predicate = { op = "exists", path = "/x" },
          ["then"] = { { op = "remove", path = "/credit_card_number" } },
          otherwise = {} },
    }))
    check("protected-path scan walks conditional branches", hit == "credit_card_number")
end

-- 6) map_value with unmapped value + reject -> fail closed
do
    local out = T.apply_program({ status = "WAT" }, prog({
        { op = "map_value", path = "/status", mapping = { PENDING = "pending" }, onUnmapped = "reject" },
    }))
    check("map_value reject fails closed on unmapped", out.status == "WAT")
end

-- 6b) map_value mapped value substitutes
do
    local out = T.apply_program({ status = "PENDING" }, prog({
        { op = "map_value", path = "/status", mapping = { PENDING = "pending" }, onUnmapped = "reject" },
    }))
    check("map_value substitutes mapped value", out.status == "pending")
end

-- 7) reformat_date epoch_s -> iso8601
do
    local out = T.apply_program({ ts = 1700000000 }, prog({
        { op = "reformat_date", path = "/ts", sourceFormat = "epoch_s", targetFormat = "iso8601" },
    }))
    check("reformat_date epoch_s->iso8601", out.ts == "2023-11-14T22:13:20Z")
end

-- 8) arith divide-by-zero fails closed (verifier blocks static, runtime guards too)
do
    local out = T.apply_program({ n = 10 }, prog({
        { op = "arith", path = "/n", operator = "/", operand = 0, expectedMin = 0, expectedMax = 100 },
    }))
    check("arith div-by-zero fails closed", out.n == 10)
end

-- 9) scale non-integral: (value * numerator) / denominator order (12345 /100 = 123.45)
do
    local out = T.apply_program({ amount = 12345 }, prog({
        { op = "scale", path = "/amount", numerator = 1, denominator = 100,
          expectedMin = 0, expectedMax = 1000000 },
    }))
    check("scale operation order matches Java", out.amount == 123.45)
end

-- 10) reformat_date date -> iso8601 (output always UTC)
do
    local out = T.apply_program({ d = "2023-01-01" }, prog({
        { op = "reformat_date", path = "/d", sourceFormat = "date",
          targetFormat = "iso8601", tzPolicy = "utc" },
    }))
    check("reformat_date date->iso8601 utc", out.d == "2023-01-01T00:00:00Z")
end

-- 11) reformat_date iso8601 WITHOUT a zone fails closed (no silent UTC assumption)
do
    local out = T.apply_program({ d = "2023-01-01T00:00:00" }, prog({
        { op = "reformat_date", path = "/d", sourceFormat = "iso8601",
          targetFormat = "epoch_s", tzPolicy = "utc" },
    }))
    check("reformat_date zone-less iso8601 fails closed", out.d == "2023-01-01T00:00:00")
end

-- 12) reformat_date date input assumes tzPolicy offset
do
    local out = T.apply_program({ d = "2023-01-01" }, prog({
        { op = "reformat_date", path = "/d", sourceFormat = "date",
          targetFormat = "epoch_ms", tzPolicy = "+05:30" },
    }))
    check("reformat_date date applies tzPolicy offset", out.d == 1672511400000)
end

-- 13) reformat_date out of validity window fails closed
do
    local out = T.apply_program({ d = "2200-01-01" }, prog({
        { op = "reformat_date", path = "/d", sourceFormat = "date",
          targetFormat = "epoch_ms", tzPolicy = "utc" },
    }))
    check("reformat_date out-of-window fails closed", out.d == "2200-01-01")
end

-- 14) coerce to double of an integer stays integral-encoded (no 5.0)
do
    local out = T.apply_program({ n = 5 }, prog({
        { op = "coerce", path = "/n", targetType = "double" },
    }))
    check("coerce double of integer is integral", out.n == 5)
end

-- 15) string trim removes ASCII whitespace only (U+00A0 NBSP preserved)
do
    local out = T.apply_program({ s = "  hi \t" }, prog({
        { op = "string", path = "/s", operation = "trim" },
    }))
    check("trim removes ascii whitespace", out.s == "hi")
    local nb = T.apply_program({ s = "\194\160hi\194\160" }, prog({
        { op = "string", path = "/s", operation = "trim" },
    }))
    check("trim leaves non-ascii whitespace (NBSP)", nb.s == "\194\160hi\194\160")
end

print(string.rep("-", 40))
if failures == 0 then
    print("ALL PASSED")
    os.exit(0)
else
    print(failures .. " FAILED")
    os.exit(1)
end
