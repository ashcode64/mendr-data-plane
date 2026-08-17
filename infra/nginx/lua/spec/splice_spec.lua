-- P4/P5: splice semantic parity vs apply_program (not byte-equality).
--   cd infra/nginx/lua && lua spec/splice_spec.lua

package.path = package.path .. ";../?.lua;./?.lua"

local ok_cjson, cjson = pcall(require, "cjson.safe")
if not ok_cjson or not cjson then
    print("SKIP - cjson.safe not available")
    os.exit(0)
end

local T = require("transform")
local splice = require("splice")

local failures = 0
local function check(name, cond)
    if cond then
        print("ok   - " .. name)
    else
        failures = failures + 1
        print("FAIL - " .. name)
    end
end

local function deep_eq(a, b)
    if a == b then return true end
    if type(a) ~= type(b) then return false end
    if type(a) ~= "table" then return false end
    for k, v in pairs(a) do
        if not deep_eq(v, b[k]) then return false end
    end
    for k in pairs(b) do
        if a[k] == nil then return false end
    end
    return true
end

local function prog(ops) return { empty = false, ops = ops } end

local function load_corpus()
    local paths = {
        "spec/corpus.json",
        "./spec/corpus.json",
        "infra/nginx/lua/spec/corpus.json",
    }
    for _, p in ipairs(paths) do
        local f = io.open(p, "r")
        if f then
            local raw = f:read("*a")
            f:close()
            local decoded = cjson.decode(raw)
            if type(decoded) == "table" then return decoded, p end
        end
    end
    return nil
end

local function oracle(body, program)
    local decoded = cjson.decode(body)
    local orig = T.deep_copy(decoded)
    local dom = T.apply_program(T.deep_copy(decoded), program)
    local streamed, err = splice.apply(body, program)
    if not streamed then
        -- Whole-program fail-closed: splice withholds the rewrite; DOM matches original.
        if deep_eq(dom, orig) then
            return true
        end
        return false, "splice failed: " .. tostring(err)
    end
    local got = cjson.decode(streamed)
    if not deep_eq(got, dom) then
        return false, "semantic mismatch splice=" .. tostring(streamed)
            .. " dom=" .. tostring(cjson.encode(dom))
    end
    return true
end

-- rename
do
    local body = '{"amt":10,"keep":true}'
    local p = prog({ { op = "rename", from = "/amt", to = "/amount" } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("rename semantic parity", ok)
end

-- coerce
do
    local body = '{"n":"5"}'
    local p = prog({ { op = "coerce", path = "/n", targetType = "integer" } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("coerce semantic parity", ok)
end

-- scale
do
    local body = '{"amount":2500}'
    local p = prog({ { op = "scale", path = "/amount", numerator = 1, denominator = 100,
        expectedMin = 0, expectedMax = 1000000 } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("scale semantic parity", ok)
end

-- scale fail-closed keeps original bytes' value
do
    local body = '{"amount":50}'
    local p = prog({ { op = "scale", path = "/amount", numerator = 1000, denominator = 1,
        expectedMin = 0, expectedMax = 100 } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("scale fail-closed semantic parity", ok)
end

-- wrap
do
    local body = '{"n":1}'
    local p = prog({ { op = "wrap", key = "data" } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("wrap semantic parity", ok)
end

-- default ABSENT
do
    local body = '{"n":1}'
    local p = prog({ { op = "default", path = "/active", value = true, on = "ABSENT" } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("default absent semantic parity", ok)
end

-- remove
do
    local body = '{"keep":1,"drop":2}'
    local p = prog({ { op = "remove", path = "/drop" } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("remove semantic parity", ok)
end

-- nested leaf
do
    local body = '{"user":{"name":"Jo"}}'
    local p = prog({ { op = "string", path = "/user/name", operation = "upper" } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("nested string upper semantic parity", ok)
end

-- key order variant (semantic, not byte)
do
    local body = '{"b":2,"a":1}'
    local p = prog({ { op = "rename", from = "/a", to = "/alpha" } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("key-order variant semantic parity", ok)
end

-- escaped key: splice unescapes, DOM cjson also unescapes
do
    local body = '{"user\\u005fname":1}'
    local p = prog({ { op = "rename", from = "/user_name", to = "/uname" } })
    local streamed = splice.apply(body, p)
    local decoded = cjson.decode(body)
    local dom = T.apply_program(T.deep_copy(decoded), p)
    local got = streamed and cjson.decode(streamed)
    check("escaped key rename semantic", got ~= nil and deep_eq(got, dom))
end

-- chunk boundaries
do
    local body = '{"amt":10,"keep":true}'
    local p = prog({ { op = "rename", from = "/amt", to = "/amount" } })
    local chunks = {}
    for i = 1, #body do chunks[i] = body:sub(i, i) end
    local streamed, err = splice.apply_chunked(body, p, chunks)
    local dom = T.apply_program(cjson.decode(body), p)
    local got = streamed and cjson.decode(streamed)
    if not got then print("  detail: " .. tostring(err)) end
    check("per-byte chunk boundaries", got ~= nil and deep_eq(got, dom))
end

-- duplicate keys: last occurrence wins (cjson); splice edits each matching key
-- Define: semantic oracle uses cjson.decode (last key). Splice should match that
-- after decode of its output.
do
    local body = '{"amt":1,"amt":2}'
    local p = prog({ { op = "rename", from = "/amt", to = "/amount" } })
    local streamed = splice.apply(body, p)
    local got = streamed and cjson.decode(streamed)
    -- After rename of both, last amount=2
    check("duplicate key last-wins after decode", got ~= nil and got.amount == 2 and got.amt == nil)
end

-- large int64: splice keeps original bytes when untouched
do
    local body = '{"id":9007199254740993,"amt":1}'
    local p = prog({ { op = "rename", from = "/amt", to = "/amount" } })
    local streamed = splice.apply(body, p)
    check("untouched int64 bytes preserved", streamed ~= nil
        and streamed:find("9007199254740993", 1, true) ~= nil)
end

-- rename then coerce (opcode order)
do
    local body = '{"amt":"5"}'
    local p = prog({
        { op = "rename", from = "/amt", to = "/amount" },
        { op = "coerce", path = "/amount", targetType = "integer" },
    })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("rename then coerce opcode order", ok)
end

-- program fail-closed on DOM is whole-document; splice is per-value (P4).
-- coerce /a succeeds, scale /b faults → splice keeps original /b bytes.
do
    local body = '{"a":"1","b":50}'
    local p = prog({
        { op = "coerce", path = "/a", targetType = "integer" },
        { op = "scale", path = "/b", numerator = 1000, denominator = 1,
          expectedMin = 0, expectedMax = 100 },
    })
    local streamed = splice.apply(body, p)
    local got = streamed and cjson.decode(streamed)
    check("per-value fail-closed streams coerced leaf", got ~= nil and got.a == 1 and got.b == 50)
    local dom = T.apply_program(cjson.decode(body), p)
    check("DOM whole-program fail-closed keeps original /a", dom.a == "1")
end

-- unwrap preserves int64 bytes (no cjson round-trip)
do
    local body = '{"data":{"id":9007199254740993}}'
    local p = prog({ { op = "unwrap", key = "data" } })
    local streamed = splice.apply(body, p)
    check("unwrap preserves int64 bytes", streamed ~= nil
        and streamed:find("9007199254740993", 1, true) ~= nil
        and streamed:find('"id"', 1, true) ~= nil)
end

-- deep nesting
do
    local body = '{"a":{"b":{"c":{"d":{"e":"jo"}}}}}'
    local p = prog({ { op = "string", path = "/a/b/c/d/e", operation = "upper" } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("deep nested string upper", ok)
end

-- escaped-key fuzz
do
    local cases = {
        '{"user\\u005fname":1}',
        '{"user\\/name":1}',
        '{"a\\\\b":1}',
    }
    for _, body in ipairs(cases) do
        local decoded = cjson.decode(body)
        if decoded then
            local from
            for k in pairs(decoded) do from = k end
            local p = prog({ { op = "rename", from = "/" .. from, to = "/out" } })
            local ok = oracle(body, p)
            check("escaped-key fuzz " .. body, ok)
        end
    end
end

-- same-parent move
do
    local body = '{"user":{"amt":1,"keep":true}}'
    local p = prog({ { op = "move", from = "/user/amt", to = "/user/amount" } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("same-parent move semantic parity", ok)
end

-- array-nested pointer
do
    local body = '{"items":[{"amt":1,"keep":true}]}'
    local p = prog({ { op = "rename", from = "/items/0/amt", to = "/items/0/amount" } })
    local ok, err = oracle(body, p)
    if not ok then print("  detail: " .. tostring(err)) end
    check("array-nested rename semantic parity", ok)
end

-- P5 shared corpus: spec/corpus.json is a copy of
-- api-gateway/src/test/resources/mendrscript/corpus.json (keep them identical).
do
    local corpus, from = load_corpus()
    check("corpus.json loaded", corpus ~= nil)
    if corpus then
        print("  corpus from " .. tostring(from) .. " (" .. #corpus .. " cases)")
        for _, c in ipairs(corpus) do
            local p = prog(c.ops)
            local ok, err = oracle(c.body, p)
            if not ok then print("  corpus " .. c.name .. ": " .. tostring(err)) end
            check("corpus " .. c.name, ok)
            if not c.failClosed and c.expected then
                local dom = T.apply_program(cjson.decode(c.body), p)
                check("corpus expected " .. c.name, deep_eq(dom, c.expected))
            end
            if c.perByte then
                local chunks = {}
                for i = 1, #c.body do chunks[i] = c.body:sub(i, i) end
                local streamed, serr = splice.apply_chunked(c.body, p, chunks)
                local dom = T.apply_program(cjson.decode(c.body), p)
                local got = streamed and cjson.decode(streamed)
                if not got then print("  perByte " .. c.name .. ": " .. tostring(serr)) end
                check("corpus perByte " .. c.name, got ~= nil and deep_eq(got, dom))
            end
        end
    end
end
do
    local body = '{ "keep" : 1, "amt" : 2 }'
    local p = prog({ { op = "rename", from = "/amt", to = "/amount" } })
    local streamed = splice.apply(body, p)
    check("verbatim unmatched whitespace", streamed ~= nil
        and streamed:find('"keep" : 1', 1, true) ~= nil)
end

-- wrap is prefix/suffix around original interior
do
    local body = '{"id":9007199254740993}'
    local p = prog({ { op = "wrap", key = "data" } })
    local streamed = splice.apply(body, p)
    check("wrap prefix/suffix preserves interior int64", streamed ~= nil
        and streamed:find('{"data":', 1, true) == 1
        and streamed:find("9007199254740993", 1, true) ~= nil)
end

-- P4/P5: 100KB–1MB sparse-edit HBM. Rename a tiny leading key; the rest is an
-- unmatched string streamed verbatim. feed+drain per chunk (the body_filter
-- path). Peak state.buf must stay O(chunk), not O(body); first drain must
-- happen before EOF (TTFB). RSS is recorded from /proc/self/statm.
do
    local function rss_kb()
        local f = io.open("/proc/self/statm", "r")
        if f then
            local line = f:read("*l")
            f:close()
            local pages = line and tonumber(line:match("^%S+%s+(%S+)"))
            if pages then return pages * 4 end
        end
        return collectgarbage("count")
    end
    local pad_len = 256 * 1024
    local body = '{"amt":1,"pad":"' .. string.rep("x", pad_len) .. '"}'
    check("hbm body in 100KB-1MB band", #body >= 100 * 1024 and #body <= 1024 * 1024)
    local p = prog({ { op = "rename", from = "/amt", to = "/amount" } })
    local chunk_size = 4096
    collectgarbage("collect")
    local rss0 = rss_kb()
    local peak_buf, peak_rss = 0, rss0
    local t0 = os.clock()
    local ttfb_ms
    local drained_before_eof = false
    local state = { program = p }
    local nchunks = math.ceil(#body / chunk_size)
    for i = 1, nchunks do
        local a = (i - 1) * chunk_size + 1
        local b = math.min(i * chunk_size, #body)
        local _, err = splice.feed(state, body:sub(a, b), i == nchunks)
        if err then
            print("  hbm feed err: " .. tostring(err))
            break
        end
        peak_buf = math.max(peak_buf, #(state.buf or ""))
        peak_rss = math.max(peak_rss, rss_kb())
        local drained = splice.drain(state)
        if drained and drained ~= "" then
            if not ttfb_ms then ttfb_ms = (os.clock() - t0) * 1000 end
            if i < nchunks then drained_before_eof = true end
        end
    end
    local elapsed_ms = (os.clock() - t0) * 1000
    local out = splice.output(state)
    local got = out and cjson.decode(out)
    local rss_delta = peak_rss - rss0
    print(string.format(
        "hbm sparse rename body=%d peak_buf=%d ttfb=%.3f ms total=%.3f ms rss_delta=%.1f KB",
        #body, peak_buf, ttfb_ms or -1, elapsed_ms, rss_delta))
    check("hbm drains before eof (TTFB)", drained_before_eof)
    check("hbm peak buf << body (not O(N) original)", peak_buf > 0 and peak_buf < 64 * 1024)
    check("hbm ttfb recorded before total", ttfb_ms ~= nil and ttfb_ms <= elapsed_ms)
    check("hbm sparse-edit semantic", got ~= nil and got.amount == 1 and type(got.pad) == "string" and #got.pad == pad_len)
end
do
    collectgarbage("collect")
    local rss0
    local f = io.open("/proc/self/statm", "r")
    if f then
        local line = f:read("*l")
        f:close()
        local pages = line and tonumber(line:match("^%S+%s+(%S+)"))
        rss0 = pages and (pages * 4) or collectgarbage("count")
    else
        rss0 = collectgarbage("count")
    end
    local t0 = os.clock()
    local n = 500
    local body = '{"amt":10,"keep":true}'
    local p = prog({ { op = "rename", from = "/amt", to = "/amount" } })
    for i = 1, n do
        splice.apply(body, p)
    end
    local elapsed_ms = (os.clock() - t0) * 1000 / n
    local rss1
    local f2 = io.open("/proc/self/statm", "r")
    if f2 then
        local line = f2:read("*l")
        f2:close()
        local pages = line and tonumber(line:match("^%S+%s+(%S+)"))
        rss1 = pages and (pages * 4) or collectgarbage("count")
    else
        rss1 = collectgarbage("count")
    end
    local rss_delta = rss1 - rss0
    print(string.format("bench splice rename %.4f ms/op rss_delta=%.1f KB (%d iters)",
        elapsed_ms, rss_delta, n))
    check("splice bench ran", elapsed_ms >= 0)
end
do
    local t0 = os.clock()
    local n = 2000
    for i = 1, n do
        T.apply_program({ amount = 2500 }, prog({
            { op = "scale", path = "/amount", numerator = 1, denominator = 100,
              expectedMin = 0, expectedMax = 1000000 },
        }))
    end
    local elapsed_ms = (os.clock() - t0) * 1000 / n
    print(string.format("bench scale apply_ops %.4f ms/op (%d iters)", elapsed_ms, n))
    check("bench ran", elapsed_ms >= 0)
end

print(string.rep("-", 40))
if failures == 0 then
    print("ALL PASSED")
    os.exit(0)
else
    print(failures .. " FAILED")
    os.exit(1)
end
