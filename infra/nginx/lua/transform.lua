-- Shared flat JSON transform primitives (mirrors Java TransformProgram / access.lua).

local _M = {}

-- cjson decodes JSON `null` to a sentinel (cjson.null), NOT Lua nil. We need that
-- sentinel to tell "present-but-null" (COALESCE fires) apart from "absent"
-- (ADD_DEFAULT fires). When cjson is unavailable (unit tests) fall back to a
-- unique table; tests reference it via _M.JSON_NULL.
local ok_cjson, cjson = pcall(require, "cjson.safe")
local JSON_NULL = (ok_cjson and cjson and cjson.null)
        or setmetatable({}, { __tostring = function() return "null" end })
_M.JSON_NULL = JSON_NULL

-- ── Independent protected-path backstop (plan §3 / §4.4) ─────────────────────
-- Defense-in-depth: the edge refuses to apply ANY program that touches a
-- protected field, INDEPENDENT of the control-plane Guardrails layer. This is a
-- hardcoded, version-controlled blacklist shipped with the data plane — if the
-- control plane is buggy, misconfigured, or bypassed, this still holds.
--
-- Matching is case-insensitive and checks both flat top-level keys (renames /
-- defaults / coercions / removals / wrap / unwrap) and every segment of a
-- JSON-Pointer move target. Kept deliberately narrow so legitimate healing
-- (e.g. moving /credentials/token -> /token) is never blocked.
local DEFAULT_PROTECTED = {
    ["authorization"]      = true,
    ["x-api-key"]          = true,
    ["credit_card_number"] = true,
    ["internal_routing_id"] = true,
}

local function norm(s)
    if type(s) ~= "string" then return nil end
    return s:lower()
end

-- Does a flat key or any pointer segment hit the protected set?
local function hits_protected(target, protected)
    local n = norm(target)
    if not n then return false end
    if protected[n] then return n end
    -- Pointer form: check each segment.
    if n:sub(1, 1) == "/" then
        for seg in n:gmatch("/([^/]*)") do
            local decoded = seg:gsub("~1", "/"):gsub("~0", "~")
            if protected[decoded] then return decoded end
        end
    end
    return false
end

-- Recursively scan a MendrScript ops[] AST (snapshot v2) for protected-path hits.
-- Walks path/from/to on every op, the predicate path, AND both conditional
-- branches (Gap 7) — a protected path hidden inside a branch that only fires on
-- certain inputs is still rejected. `then` is a Lua keyword, hence bracket access.
local function scan_ops(ops, protected)
    if type(ops) ~= "table" then return nil end
    for _, op in ipairs(ops) do
        if type(op) == "table" then
            local h = hits_protected(op.path, protected)
                or hits_protected(op.from, protected)
                or hits_protected(op.to, protected)
            if h then return h end
            if type(op.predicate) == "table" then
                h = hits_protected(op.predicate.path, protected)
                if h then return h end
            end
            h = scan_ops(op["then"], protected) or scan_ops(op.otherwise, protected)
            if h then return h end
        end
    end
    return nil
end

-- Returns the first protected target a program would touch, or nil if clean.
-- `extra` (optional array of strings) augments the hardcoded blacklist.
function _M.protected_violation(program, extra)
    if not program or type(program) ~= "table" then return nil end

    local protected = {}
    for k in pairs(DEFAULT_PROTECTED) do protected[k] = true end
    if type(extra) == "table" then
        for _, p in ipairs(extra) do
            local n = norm(p)
            if n then protected[n] = true end
        end
    end

    if type(program.renames) == "table" then
        for old_key, new_key in pairs(program.renames) do
            local h = hits_protected(old_key, protected) or hits_protected(new_key, protected)
            if h then return h end
        end
    end
    if type(program.defaults) == "table" then
        for key in pairs(program.defaults) do
            local h = hits_protected(key, protected)
            if h then return h end
        end
    end
    if type(program.coercions) == "table" then
        for key in pairs(program.coercions) do
            local h = hits_protected(key, protected)
            if h then return h end
        end
    end
    if type(program.removals) == "table" then
        for _, key in ipairs(program.removals) do
            local h = hits_protected(key, protected)
            if h then return h end
        end
    end
    if type(program.moves) == "table" then
        for _, mv in ipairs(program.moves) do
            if mv then
                local h = hits_protected(mv.from, protected) or hits_protected(mv.to, protected)
                if h then return h end
            end
        end
    end
    -- Path-bearing op lists (scales / valueMaps / dateFormats / stripUnknown /
    -- wrapArrays / unwrapArrays): every {path} is checked against the blacklist.
    -- Checked explicitly (not via an array of lists) because nil holes would make
    -- ipairs stop early and silently skip later lists.
    local function scan_path_list(lst)
        if type(lst) ~= "table" then return nil end
        for _, entry in ipairs(lst) do
            if entry then
                local h = hits_protected(entry.path, protected)
                if h then return h end
            end
        end
        return nil
    end
    local hp = scan_path_list(program.scales)
        or scan_path_list(program.valueMaps)
        or scan_path_list(program.dateFormats)
        or scan_path_list(program.stripUnknown)
        or scan_path_list(program.wrapArrays)
        or scan_path_list(program.unwrapArrays)
        or scan_path_list(program.coalesce)
    if hp then return hp end
    local h = hits_protected(program.wrapKey, protected) or hits_protected(program.unwrapKey, protected)
    if h then return h end

    -- Snapshot v2: closed-opcode AST (recursively, including conditional branches).
    local ho = scan_ops(program.ops, protected)
    if ho then return ho end

    return nil
end

-- ── JSON Pointer helpers (RFC 6901) for FIELD_MOVE / restructure ──────────────
-- Pointers are "/a/b/c". An empty token unescape handles ~1 (/) and ~0 (~).

local function unescape_token(tok)
    -- order matters: ~1 before ~0 per RFC 6901
    tok = tok:gsub("~1", "/")
    tok = tok:gsub("~0", "~")
    return tok
end

-- Split "/credentials/token" into {"credentials","token"}. Returns nil for
-- empty/invalid pointers (we only support absolute object pointers).
local function split_pointer(pointer)
    if type(pointer) ~= "string" or pointer == "" or pointer:sub(1, 1) ~= "/" then
        return nil
    end
    local tokens = {}
    for tok in pointer:gmatch("/([^/]*)") do
        tokens[#tokens + 1] = unescape_token(tok)
    end
    if #tokens == 0 then
        return nil
    end
    return tokens
end

-- Read the value at a pointer, or nil if any segment is missing / not an object.
function _M.get_path(payload, pointer)
    local tokens = split_pointer(pointer)
    if not tokens then return nil end
    local node = payload
    for i = 1, #tokens do
        if type(node) ~= "table" then return nil end
        node = node[tokens[i]]
        if node == nil then return nil end
    end
    return node
end

-- Set value at a pointer, creating intermediate objects as needed.
function _M.set_path(payload, pointer, value)
    local tokens = split_pointer(pointer)
    if not tokens then return false end
    local node = payload
    for i = 1, #tokens - 1 do
        local key = tokens[i]
        if type(node[key]) ~= "table" then
            node[key] = {}
        end
        node = node[key]
    end
    node[tokens[#tokens]] = value
    return true
end

-- Delete value at a pointer and prune now-empty parent objects.
function _M.delete_path(payload, pointer)
    local tokens = split_pointer(pointer)
    if not tokens then return false end
    -- Walk down, remembering the chain so we can prune empties on the way back up.
    local chain = { payload }
    local node = payload
    for i = 1, #tokens - 1 do
        if type(node) ~= "table" then return false end
        node = node[tokens[i]]
        if node == nil then return false end
        chain[#chain + 1] = node
    end
    if type(node) ~= "table" then return false end
    node[tokens[#tokens]] = nil
    -- Prune empty parents from the deepest upward (skip the root payload itself).
    for i = #chain, 2, -1 do
        if next(chain[i]) == nil then
            chain[i - 1][tokens[i - 1]] = nil
        else
            break
        end
    end
    return true
end

function _M.coerce_value(val, target_type)
    if target_type == "integer" or target_type == "long" then
        local n = tonumber(val)
        return n and math.floor(n) or val
    elseif target_type == "double" or target_type == "float" then
        return tonumber(val) or val
    elseif target_type == "boolean" then
        if type(val) == "string" then
            return val == "true" or val == "1"
        end
        return not not val
    elseif target_type == "string" then
        return tostring(val)
    end
    return val
end

-- ── Named-format date conversion (REFORMAT_DATE, §12/§13) ────────────────────
-- Closed set of named formats only (no free-form strptime), strict parse,
-- deterministic and locale-independent. The intermediate representation is
-- integer epoch MILLISECONDS (exact in a double below ~year 2100), so sub-second
-- precision survives an iso8601_ms round-trip. Naturally idempotent: a value
-- already in the target format will not strict-parse as the source format, so it
-- is left untouched (fail-closed). All month/weekday names use the hardcoded
-- English tables below — never os.date("%a"/"%b"), which are locale-dependent.

local MONTHS_ABBR = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                      "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" }
local MONTHS_BY_NAME = {}
for i, name in ipairs(MONTHS_ABBR) do MONTHS_BY_NAME[name] = i end
-- os.date("!%w") is 0=Sunday .. 6=Saturday.
local WEEKDAYS = { [0] = "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" }

local function days_from_civil(y, m, d)
    y = (m <= 2) and (y - 1) or y
    local era = math.floor((y >= 0 and y or (y - 399)) / 400)
    local yoe = y - era * 400
    local mp = (m > 2) and (m - 3) or (m + 9)
    local doy = math.floor((153 * mp + 2) / 5) + d - 1
    local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
    return era * 146097 + doe - 719468
end

-- Parse a fixed offset designator ("Z", "+05:30", "-0800", "+0530") to signed
-- milliseconds, or nil if malformed. "Z" and the empty string mean UTC (0).
local function parse_offset_ms(tz)
    if tz == nil or tz == "" or tz == "Z" or tz == "z" then return 0 end
    if type(tz) ~= "string" then return nil end
    local sign, hh, mm = tz:match("^([+-])(%d%d):?(%d%d)$")
    if not sign then return nil end
    hh, mm = tonumber(hh), tonumber(mm)
    if hh > 23 or mm > 59 then return nil end
    local mag = (hh * 3600 + mm * 60) * 1000
    return (sign == "-") and -mag or mag
end

local function ymd_ms(y, mo, d)
    if mo < 1 or mo > 12 or d < 1 or d > 31 then return nil end
    return days_from_civil(y, mo, d) * 86400 * 1000
end

-- Parse `v` in named `fmt` to epoch milliseconds, or nil on strict-parse failure.
-- `assume_off_ms` is the assumed UTC offset (ms) applied to TZ-LESS formats only;
-- zone-bearing formats parse their own offset and ignore it.
local function date_to_epoch_ms(v, fmt, assume_off_ms)
    assume_off_ms = assume_off_ms or 0
    if fmt == "epoch_s" then
        local n = tonumber(v)
        return n and (math.floor(n) * 1000) or nil
    elseif fmt == "epoch_ms" then
        local n = tonumber(v)
        return n and math.floor(n) or nil
    elseif fmt == "date" then
        if type(v) ~= "string" then return nil end
        local y, mo, d = v:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)$")
        if not y then return nil end
        local base = ymd_ms(tonumber(y), tonumber(mo), tonumber(d))
        return base and (base - assume_off_ms) or nil
    elseif fmt == "date_slash" then
        if type(v) ~= "string" then return nil end
        local y, mo, d = v:match("^(%d%d%d%d)/(%d%d)/(%d%d)$")
        if not y then return nil end
        local base = ymd_ms(tonumber(y), tonumber(mo), tonumber(d))
        return base and (base - assume_off_ms) or nil
    elseif fmt == "datetime" then
        if type(v) ~= "string" then return nil end
        local y, mo, d, hh, mi, ss = v:match("^(%d%d%d%d)%-(%d%d)%-(%d%d) (%d%d):(%d%d):(%d%d)$")
        if not y then return nil end
        local base = ymd_ms(tonumber(y), tonumber(mo), tonumber(d))
        hh, mi, ss = tonumber(hh), tonumber(mi), tonumber(ss)
        if not base or hh > 23 or mi > 59 or ss > 59 then return nil end
        return base + (hh * 3600 + mi * 60 + ss) * 1000 - assume_off_ms
    elseif fmt == "iso8601" then
        if type(v) ~= "string" then return nil end
        -- Require an explicit zone designator (strict): Z or ±HH:MM / ±HHMM.
        local y, mo, d, hh, mi, ss, tz =
            v:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)(.+)$")
        if not y then return nil end
        local off = parse_offset_ms(tz)
        if off == nil then return nil end
        local base = ymd_ms(tonumber(y), tonumber(mo), tonumber(d))
        hh, mi, ss = tonumber(hh), tonumber(mi), tonumber(ss)
        if not base or hh > 23 or mi > 59 or ss > 59 then return nil end
        return base + (hh * 3600 + mi * 60 + ss) * 1000 - off
    elseif fmt == "iso8601_ms" then
        if type(v) ~= "string" then return nil end
        -- Accept arbitrary-length fractional seconds (ms / micro / nano), then
        -- normalize to integer milliseconds below — covers Python (6-digit),
        -- Java (up to 9), and JS (3) ISO emitters without per-precision names.
        local y, mo, d, hh, mi, ss, frac, tz =
            v:match("^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d):(%d%d):(%d%d)%.(%d+)(.+)$")
        if not y then return nil end
        local off = parse_offset_ms(tz)
        if off == nil then return nil end
        local base = ymd_ms(tonumber(y), tonumber(mo), tonumber(d))
        hh, mi, ss = tonumber(hh), tonumber(mi), tonumber(ss)
        if not base or hh > 23 or mi > 59 or ss > 59 then return nil end
        -- Truncate sub-ms precision; left-justify-pad short fractions so
        -- ".5" -> 500ms, ".12" -> 120ms, ".250999" -> 250ms.
        local frac_ms = tonumber((frac .. "000"):sub(1, 3))
        return base + (hh * 3600 + mi * 60 + ss) * 1000 + frac_ms - off
    elseif fmt == "rfc1123" then
        if type(v) ~= "string" then return nil end
        -- e.g. "Wed, 14 Nov 2023 22:13:20 GMT" — always GMT/UTC by spec.
        local _, d, mon, y, hh, mi, ss =
            v:match("^(%a%a%a), (%d%d) (%a%a%a) (%d%d%d%d) (%d%d):(%d%d):(%d%d) GMT$")
        if not d then return nil end
        local moNum = MONTHS_BY_NAME[mon]
        if not moNum then return nil end
        local base = ymd_ms(tonumber(y), moNum, tonumber(d))
        hh, mi, ss = tonumber(hh), tonumber(mi), tonumber(ss)
        if not base or hh > 23 or mi > 59 or ss > 59 then return nil end
        return base + (hh * 3600 + mi * 60 + ss) * 1000
    end
    return nil
end

-- Format epoch milliseconds into named `fmt`. Numeric os.date("!...") specifiers
-- are locale-independent; month/weekday names come from the hardcoded tables.
local function epoch_ms_to_date(ms, fmt)
    local secs = math.floor(ms / 1000)
    if fmt == "epoch_s" then
        return secs
    elseif fmt == "epoch_ms" then
        return math.floor(ms)
    elseif fmt == "date" then
        return os.date("!%Y-%m-%d", secs)
    elseif fmt == "date_slash" then
        return os.date("!%Y/%m/%d", secs)
    elseif fmt == "datetime" then
        return os.date("!%Y-%m-%d %H:%M:%S", secs)
    elseif fmt == "iso8601" then
        return os.date("!%Y-%m-%dT%H:%M:%SZ", secs)
    elseif fmt == "iso8601_ms" then
        return os.date("!%Y-%m-%dT%H:%M:%S", secs)
            .. string.format(".%03dZ", ms % 1000)
    elseif fmt == "rfc1123" then
        local wday = tonumber(os.date("!%w", secs))
        local mon = tonumber(os.date("!%m", secs))
        return string.format("%s, %s %s %s %s GMT",
            WEEKDAYS[wday] or "Sun",
            os.date("!%d", secs),
            MONTHS_ABBR[mon] or "Jan",
            os.date("!%Y", secs),
            os.date("!%H:%M:%S", secs))
    end
    return nil
end

-- Bounded validity window [1970-01-01, 2100-01-01) — anything outside is treated
-- as a parse failure (fail-closed), preventing absurd dates from a misread value.
local DATE_EPOCH_MAX = 4102444800

-- ════════════════════════════════════════════════════════════════════════════
-- MendrScript closed-opcode interpreter (snapshot v2 `ops[]`)
-- ════════════════════════════════════════════════════════════════════════════
-- The AST is DATA the interpreter walks — never code, no load()/FFI. Semantics
-- mirror the Java MendrScriptExecutor exactly (the differential conformance suite
-- diffs the two). Value-op faults and post-condition violations raise a Lua error;
-- _M.apply_ops catches it and FAILS CLOSED (returns the payload unmodified) so a
-- silently-wrong value is never emitted.

-- Deep copy so a faulting program can be abandoned without partial mutation.
-- JSON_NULL identity must be preserved (it is a sentinel, not a plain table).
local function deep_copy(v)
    if v == JSON_NULL or type(v) ~= "table" then return v end
    local out = {}
    for k, val in pairs(v) do out[k] = deep_copy(val) end
    return out
end

local function as_str(v)
    if v == nil or v == JSON_NULL then return "" end
    if type(v) == "boolean" then return v and "true" or "false" end
    return tostring(v)
end

-- Strict numeric parse (string/number only); nil on failure (caller fails closed).
local function to_number_strict(v)
    if type(v) == "number" then return v end
    if type(v) == "string" then
        local trimmed = v:match("^%s*(.-)%s*$")
        return tonumber(trimmed)
    end
    return nil
end

-- Integral doubles -> integers so cjson encodes them like the Java Long path.
local function norm_num(n)
    if n == math.floor(n) and n ~= math.huge and n ~= -math.huge then
        return math.floor(n)
    end
    return n
end

local function assert_bounds(res, mn, mx)
    if res ~= res or res == math.huge or res == -math.huge then
        error("non-finite result")
    end
    mn, mx = tonumber(mn), tonumber(mx)
    if mn ~= nil and res < mn then error("post-condition: below expectedMin") end
    if mx ~= nil and res > mx then error("post-condition: above expectedMax") end
end

local function to_bool(v)
    if type(v) == "boolean" then return v end
    local s = as_str(v):lower()
    return s == "true" or s == "1" or s == "yes"
end

local function coerce_strict(v, t)
    if t == "string" then
        return as_str(v)
    elseif t == "integer" or t == "int" or t == "long" then
        local n = to_number_strict(v); if n == nil then error("coerce: not a number") end
        return math.floor(n + 0.5)
    elseif t == "number" or t == "double" or t == "float" then
        local n = to_number_strict(v); if n == nil then error("coerce: not a number") end
        return n
    elseif t == "boolean" then
        return to_bool(v)
    end
    error("coerce: unknown target type")
end

-- Literal (non-pattern) string replace, matching Java String.replace.
local function literal_replace(s, find, repl)
    find = find or ""
    if find == "" then return s end
    local parts, i = {}, 1
    while true do
        local st, en = s:find(find, i, true)
        if not st then parts[#parts + 1] = s:sub(i); break end
        parts[#parts + 1] = s:sub(i, st - 1)
        parts[#parts + 1] = repl or ""
        i = en + 1
    end
    return table.concat(parts)
end

-- ── named-format matchers (mirror NamedFormats.java) ─────────────────────────
local function fmt_email(s) return s:match("^[^@%s]+@[^@%s]+%.[^@%s]+$") ~= nil end
local function fmt_uuid(s)
    return s:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") ~= nil
end
local function fmt_iso_date(s) return s:match("^%d%d%d%d%-%d%d%-%d%d$") ~= nil end
local function fmt_iso_datetime(s)
    if not s:match("^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d") then return false end
    local rest = s:sub(20):gsub("^%.%d+", "")
    if rest == "" or rest == "Z" then return true end
    return rest:match("^[+-]%d%d:?%d%d$") ~= nil
end
local function fmt_e164(s)
    local d = s:match("^%+([1-9]%d*)$")
    return d ~= nil and #d >= 2 and #d <= 15
end
local function fmt_slug(s)
    if s == "" or s:match("[^a-z0-9%-]") then return false end
    if s:sub(1, 1) == "-" or s:sub(-1) == "-" or s:find("%-%-") then return false end
    return true
end
local function fmt_numeric(s)
    return (s:match("^%-?%d+$") or s:match("^%-?%d+%.%d+$")) ~= nil
end
local function fmt_alnum(s) return s:match("^[%a%d]+$") ~= nil end

local NAMED_FORMATS = {
    email = fmt_email, uuid = fmt_uuid, iso_date = fmt_iso_date,
    iso_datetime = fmt_iso_datetime, e164 = fmt_e164, slug = fmt_slug,
    numeric = fmt_numeric, alnum = fmt_alnum,
}

local function matches_format(fmt, value)
    local fn = NAMED_FORMATS[fmt]
    if not fn then return false end
    return fn(as_str(value))
end

-- ── structured predicate evaluation (Gap 3, Option C — no free-form regex) ────
local function eval_predicate(pred, payload)
    local raw = _M.get_path(payload, pred.path)
    local exists = raw ~= nil
    local op = pred.op
    if op == "exists" then return exists end
    if not exists then return false end
    local val = (raw == JSON_NULL) and nil or raw
    if op == "eq" then
        return as_str(val) == as_str(pred.value)
    elseif op == "in" then
        if type(pred.values) ~= "table" then return false end
        for _, x in ipairs(pred.values) do
            if as_str(val) == as_str(x) then return true end
        end
        return false
    elseif op == "matches_format" then
        return matches_format(pred.format, val)
    elseif op == "starts_with" then
        local v, s = pred.value or "", as_str(val)
        return s:sub(1, #v) == v
    elseif op == "ends_with" then
        local v, s = pred.value or "", as_str(val)
        return v == "" or s:sub(-#v) == v
    elseif op == "contains" then
        return as_str(val):find(pred.value or "", 1, true) ~= nil
    elseif op == "length_between" then
        local L = #as_str(val)
        return (pred.min == nil or L >= pred.min) and (pred.max == nil or L <= pred.max)
    end
    return false
end

-- ── per-opcode application (raises on value-op fault -> fail-closed) ──────────
local function log_transform_err(msg)
    if ngx and ngx.log then
        ngx.log(ngx.ERR, msg)
    end
end

local function apply_op(payload, op)
    local kind = op.op
    if kind == nil or kind == "" then
        local detail = "missing opcode on MendrScript op entry (edge cannot dispatch)"
        if ok_cjson and cjson then
            local encoded = cjson.encode(op)
            if encoded then detail = detail .. ": " .. encoded end
        end
        error(detail)
    end
    if kind == "rename" or kind == "move" then
        local v = _M.get_path(payload, op.from)
        if v ~= nil then
            _M.set_path(payload, op.to, v)
            if op.from ~= op.to then _M.delete_path(payload, op.from) end
        end
        return payload
    elseif kind == "copy" then
        local v = _M.get_path(payload, op.from)
        if v ~= nil then _M.set_path(payload, op.to, v) end
        return payload
    elseif kind == "remove" then
        _M.delete_path(payload, op.path)
        return payload
    elseif kind == "wrap" then
        return { [op.key] = payload }
    elseif kind == "unwrap" then
        if type(payload) == "table" and payload[op.key] ~= nil then return payload[op.key] end
        return payload
    elseif kind == "wrap_array" then
        local v = _M.get_path(payload, op.path)
        if v ~= nil then _M.set_path(payload, op.path, { v }) end
        return payload
    elseif kind == "unwrap_array" then
        local v = _M.get_path(payload, op.path)
        if type(v) == "table" and v[1] ~= nil and #v == 1 then
            _M.set_path(payload, op.path, v[1])
        end
        return payload
    elseif kind == "strip_unknown" then
        local p = op.path
        local node = (p == nil or p == "" or p == "/") and payload or _M.get_path(payload, p)
        if type(node) == "table" and type(op.allowed) == "table" then
            local allow = {}
            for _, k in ipairs(op.allowed) do allow[k] = true end
            for k in pairs(node) do
                if type(k) == "string" and not allow[k] then node[k] = nil end
            end
        end
        return payload
    elseif kind == "default" then
        local v = _M.get_path(payload, op.path)
        local exists = v ~= nil
        local is_null = exists and v == JSON_NULL
        local on = as_str(op.on):upper()
        if on == "" then on = "ABSENT" end
        local fire = (on == "ABSENT" and not exists)
            or (on == "NULL" and is_null)
            or (on == "BOTH" and (not exists or is_null))
        if fire then _M.set_path(payload, op.path, op.value) end
        return payload
    elseif kind == "coalesce" then
        if _M.get_path(payload, op.path) == JSON_NULL then
            _M.set_path(payload, op.path, op.value)
        end
        return payload
    elseif kind == "coerce" then
        local v = _M.get_path(payload, op.path)
        if v == nil then return payload end
        _M.set_path(payload, op.path, coerce_strict((v == JSON_NULL) and nil or v, op.targetType))
        return payload
    elseif kind == "scale" then
        local v = _M.get_path(payload, op.path)
        if v == nil then return payload end
        local n = to_number_strict((v == JSON_NULL) and nil or v)
        if n == nil then error("scale: not a number") end
        local den = tonumber(op.denominator)
        if den == nil or den == 0 then error("scale: denominator zero") end
        local res = n * (tonumber(op.numerator) or 0) / den
        assert_bounds(res, op.expectedMin, op.expectedMax)
        _M.set_path(payload, op.path, norm_num(res))
        return payload
    elseif kind == "arith" then
        local v = _M.get_path(payload, op.path)
        if v == nil then return payload end
        local n = to_number_strict((v == JSON_NULL) and nil or v)
        if n == nil then error("arith: not a number") end
        local operand = tonumber(op.operand) or 0
        local res
        local oper = op.operator
        if oper == "+" then res = n + operand
        elseif oper == "-" then res = n - operand
        elseif oper == "*" then res = n * operand
        elseif oper == "/" then
            if operand == 0 then error("arith: divide by zero") end
            res = n / operand
        else error("arith: bad operator") end
        assert_bounds(res, op.expectedMin, op.expectedMax)
        _M.set_path(payload, op.path, norm_num(res))
        return payload
    elseif kind == "map_value" then
        local v = _M.get_path(payload, op.path)
        if v == nil then return payload end
        local key = as_str((v == JSON_NULL) and nil or v)
        if type(op.mapping) == "table" and op.mapping[key] ~= nil then
            _M.set_path(payload, op.path, op.mapping[key])
            return payload
        end
        if (op.onUnmapped or "reject") == "passthrough" then return payload end
        error("map_value: unmapped value")
    elseif kind == "reformat_date" then
        local v = _M.get_path(payload, op.path)
        if v == nil then return payload end
        local assume_off = parse_offset_ms(op.tzPolicy) or 0
        local ms = date_to_epoch_ms((v == JSON_NULL) and nil or v, op.sourceFormat, assume_off)
        if ms == nil then error("reformat_date: parse failure") end
        -- Bounded validity window (fail-closed), same guard the legacy bucket applies;
        -- also keeps os.date away from negative epochs (platform-undefined).
        local secs = ms / 1000
        if secs < 0 or secs > DATE_EPOCH_MAX then error("reformat_date: out of validity window") end
        local out = epoch_ms_to_date(ms, op.targetFormat)
        if out == nil then error("reformat_date: format failure") end
        _M.set_path(payload, op.path, out)
        return payload
    elseif kind == "string" then
        local v = _M.get_path(payload, op.path)
        if v == nil then return payload end
        local s = as_str((v == JSON_NULL) and nil or v)
        local args = op.args or {}
        local oper, out = op.operation, nil
        if oper == "lower" then out = s:lower()
        elseif oper == "upper" then out = s:upper()
        elseif oper == "trim" then out = s:match("^%s*(.-)%s*$")
        elseif oper == "prepend" then out = as_str(args[1] or "") .. s
        elseif oper == "append" then out = s .. as_str(args[1] or "")
        elseif oper == "replace" then out = literal_replace(s, as_str(args[1] or ""), as_str(args[2] or ""))
        else error("string: bad operation") end
        _M.set_path(payload, op.path, out)
        return payload
    elseif kind == "conditional" then
        local branch = eval_predicate(op.predicate or {}, payload)
        local chosen = branch and op["then"] or op.otherwise
        if type(chosen) == "table" then
            local cur = payload
            for _, child in ipairs(chosen) do
                if type(child) == "table" then cur = apply_op(cur, child) end
            end
            return cur
        end
        return payload
    end
    error("unknown opcode: " .. tostring(kind))
end

-- Run a closed-opcode program over a fresh copy of `payload`. Any op fault makes
-- the WHOLE program fail closed: the original payload is returned unmodified.
function _M.apply_ops(payload, ops)
    if type(ops) ~= "table" or #ops == 0 then return payload end
    local work = deep_copy(payload)
    local ok, result = pcall(function()
        local cur = work
        for _, op in ipairs(ops) do
            if type(op) == "table" then cur = apply_op(cur, op) end
        end
        return cur
    end)
    if ok then return result end
    log_transform_err("transform: MendrScript program failed closed: " .. tostring(result))
    return payload
end

function _M.apply_program(payload, program)
    if not program or program.empty then
        return payload
    end

    -- Restructure FIRST so subsequent flat ops see the target shape.
    -- A move relocates a value across nesting levels (e.g. /credentials/token -> /token).
    -- This is just table get/set on the already-decoded payload: no extra parse,
    -- no buffering, so it adds no forwarding latency over a flat rename.
    if program.moves and type(program.moves) == "table" then
        for _, mv in ipairs(program.moves) do
            if mv and mv.from and mv.to then
                local v = _M.get_path(payload, mv.from)
                if v ~= nil then
                    _M.set_path(payload, mv.to, v)
                    if not mv.copy then
                        _M.delete_path(payload, mv.from)
                    end
                end
            end
        end
    end

    if program.renames then
        for old_key, new_key in pairs(program.renames) do
            if payload[old_key] ~= nil then
                payload[new_key] = payload[old_key]
                payload[old_key] = nil
            end
        end
    end

    -- COALESCE (§12, scenario 2): replace ONLY a present-but-null value at {path}.
    -- Distinct from ADD_DEFAULT (which fills an absent key). Path-based so it can
    -- target nested fields. Idempotent: once the null is replaced it is no longer
    -- JSON_NULL, so re-applying is a no-op.
    if program.coalesce and type(program.coalesce) == "table" then
        for _, co in ipairs(program.coalesce) do
            if co and co.path then
                if _M.get_path(payload, co.path) == JSON_NULL then
                    _M.set_path(payload, co.path, co.value)
                end
            end
        end
    end

    if program.defaults then
        for key, default_val in pairs(program.defaults) do
            if payload[key] == nil then
                payload[key] = default_val
            end
        end
    end

    if program.coercions then
        for key, target_type in pairs(program.coercions) do
            if payload[key] ~= nil then
                payload[key] = _M.coerce_value(payload[key], target_type)
            end
        end
    end

    -- SCALE (value-mutating, §12/§13): multiply by an exact rational factor and
    -- assert the mandatory [expectedMin, expectedMax] post-condition. On violation
    -- we FAIL CLOSED for that op — the original value is left untouched — so a
    -- wrong scale factor can never silently corrupt a value downstream.
    if program.scales and type(program.scales) == "table" then
        for _, sc in ipairs(program.scales) do
            if sc and sc.path and sc.denominator and sc.denominator ~= 0 then
                local v = _M.get_path(payload, sc.path)
                local n = tonumber(v)
                if n ~= nil then
                    local scaled = n * (tonumber(sc.numerator) or 0) / tonumber(sc.denominator)
                    local lo = tonumber(sc.expectedMin)
                    local hi = tonumber(sc.expectedMax)
                    local within = true
                    if lo ~= nil and scaled < lo then within = false end
                    if hi ~= nil and scaled > hi then within = false end
                    if within then
                        _M.set_path(payload, sc.path, scaled)
                    end
                    -- else: post-condition failed -> fail closed, original kept
                end
            end
        end
    end

    -- MAP_VALUE (§12, scenario 6): closed lookup-table substitution. The edge
    -- NEVER guesses — an unmapped value is left exactly as-is (the onUnmapped
    -- policy is enforced control-plane-side; the edge only ever applies known
    -- substitutions).
    if program.valueMaps and type(program.valueMaps) == "table" then
        for _, vm in ipairs(program.valueMaps) do
            if vm and vm.path and type(vm.mapping) == "table" then
                local v = _M.get_path(payload, vm.path)
                if v ~= nil and v ~= JSON_NULL then
                    local mapped = vm.mapping[tostring(v)]
                    if mapped ~= nil then
                        _M.set_path(payload, vm.path, mapped)
                    end
                end
            end
        end
    end

    -- REFORMAT_DATE (§12/§13, scenario 7): strict named-format conversion within a
    -- bounded validity window. Parse failure / out-of-window leaves the original
    -- (fail-closed) and makes the op naturally idempotent.
    if program.dateFormats and type(program.dateFormats) == "table" then
        for _, df in ipairs(program.dateFormats) do
            if df and df.path and df.sourceFormat and df.targetFormat then
                local v = _M.get_path(payload, df.path)
                if v ~= nil and v ~= JSON_NULL then
                    -- assumeTimezone is a fixed offset for TZ-less sources only;
                    -- a malformed offset is treated as a parse failure (fail-closed).
                    local assume_off = parse_offset_ms(df.assumeTimezone)
                    if assume_off ~= nil then
                        local ms = date_to_epoch_ms(v, df.sourceFormat, assume_off)
                        -- Window guard in seconds (matches DATE_EPOCH_MAX).
                        if ms ~= nil then
                            local secs = ms / 1000
                            if secs >= 0 and secs <= DATE_EPOCH_MAX then
                                local out = epoch_ms_to_date(ms, df.targetFormat)
                                if out ~= nil then
                                    _M.set_path(payload, df.path, out)
                                end
                            end
                        end
                    end
                end
            end
        end
    end

    -- STRIP_UNKNOWN (§12, scenario 5): drop object keys not on the allow-list.
    -- Operates on the object at {path} (root when path is omitted/"/"). Only string
    -- keys are considered, so array contents are untouched.
    if program.stripUnknown and type(program.stripUnknown) == "table" then
        for _, su in ipairs(program.stripUnknown) do
            if su and type(su.allowed) == "table" then
                local node
                local p = su.path
                if p == nil or p == "" or p == "/" then
                    node = payload
                else
                    node = _M.get_path(payload, p)
                end
                if type(node) == "table" then
                    local allow = {}
                    for _, k in ipairs(su.allowed) do allow[k] = true end
                    for k in pairs(node) do
                        if type(k) == "string" and not allow[k] then
                            node[k] = nil
                        end
                    end
                end
            end
        end
    end

    -- WRAP_ARRAY (§12, scenario 11): wrap a value into a single-element array.
    if program.wrapArrays and type(program.wrapArrays) == "table" then
        for _, wa in ipairs(program.wrapArrays) do
            if wa and wa.path then
                local v = _M.get_path(payload, wa.path)
                if v ~= nil and v ~= JSON_NULL then
                    _M.set_path(payload, wa.path, { v })
                end
            end
        end
    end

    -- UNWRAP_ARRAY (§12, scenario 11): replace a single-element array with its
    -- element. A non-array or empty array is left untouched (fail-closed).
    if program.unwrapArrays and type(program.unwrapArrays) == "table" then
        for _, ua in ipairs(program.unwrapArrays) do
            if ua and ua.path then
                local v = _M.get_path(payload, ua.path)
                if type(v) == "table" and v[1] ~= nil then
                    _M.set_path(payload, ua.path, v[1])
                end
            end
        end
    end

    if program.removals and type(program.removals) == "table" then
        for _, key in ipairs(program.removals) do
            payload[key] = nil
        end
    end

    if program.wrapKey then
        payload = { [program.wrapKey] = payload }
    end

    if program.unwrapKey and type(payload[program.unwrapKey]) == "table" then
        payload = payload[program.unwrapKey]
    end

    -- Snapshot v2: closed-opcode MendrScript program. DSL programs carry their
    -- logic here (legacy buckets empty); a fault fails closed for the whole program.
    if program.ops and type(program.ops) == "table" and #program.ops > 0 then
        payload = _M.apply_ops(payload, program.ops)
    end

    return payload
end

function _M.shallow_copy(tbl)
    local copy = {}
    if type(tbl) ~= "table" then
        return copy
    end
    for k, v in pairs(tbl) do
        copy[k] = v
    end
    return copy
end

return _M
