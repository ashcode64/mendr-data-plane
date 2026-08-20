-- splice.lua — path-trie JSON splice (P4).
--
-- Escape-aware scanner walks a pointer trie built from writePointers.
-- Unmatched values are copied from the wire as they are scanned (resumable
-- string/container/number state; no re-scan from member start).
-- Matched values are captured, rewritten via transform.apply_ops, then emitted.
-- Ops are compiled in program order onto wire paths (rename then coerce).
--
-- Wrap/unwrap are prefix/suffix (or deferred-object-frame), not a DOM wrap.
-- BOUNDED_WINDOW holds only the active inter-pointer span; overflow spills
-- to DOM if nothing has been flushed, else the flushed prefix is left alone.
-- Value-mutating ops stream: a fault re-emits the original matched-value bytes.
-- Structural programs drain completed members (TTFB). Value-mutating and
-- BOUNDED_WINDOW programs hold until EOF so fail-closed cannot torn-page.
-- After a flush, faults abort the incomplete response (body_filter). The
-- original is state.buf until the first drain (then compact); there is no
-- second raw copy.

local cjson = require("cjson.safe")
local transform = require("transform")

local _M = {}
local WINDOW_CAP = 256 * 1024

local HEX = {
    ["0"]=0,["1"]=1,["2"]=2,["3"]=3,["4"]=4,["5"]=5,["6"]=6,["7"]=7,["8"]=8,["9"]=9,
    a=10,b=11,c=12,d=13,e=14,f=15,A=10,B=11,C=12,D=13,E=14,F=15,
}

local VALUE_OPS = {
    coerce = true, scale = true, arith = true, map_value = true,
    reformat_date = true, string = true, coalesce = true,
    wrap_array = true, unwrap_array = true,
}

local function utf8_char(n)
    if n < 0x80 then return string.char(n) end
    if n < 0x800 then
        return string.char(0xC0 + math.floor(n / 0x40), 0x80 + (n % 0x40))
    end
    if n < 0x10000 then
        return string.char(
            0xE0 + math.floor(n / 0x1000),
            0x80 + math.floor(n / 0x40) % 0x40,
            0x80 + (n % 0x40))
    end
    return "?"
end

local function unescape_json_key(inner)
    local out, i, n = {}, 1, #inner
    while i <= n do
        local c = inner:sub(i, i)
        if c ~= "\\" then
            out[#out + 1] = c
            i = i + 1
        else
            local n1 = inner:sub(i + 1, i + 1)
            if n1 == "u" then
                local h1, h2, h3, h4 = inner:sub(i+2, i+2), inner:sub(i+3, i+3),
                    inner:sub(i+4, i+4), inner:sub(i+5, i+5)
                local v = (HEX[h1] or 0)*4096 + (HEX[h2] or 0)*256
                    + (HEX[h3] or 0)*16 + (HEX[h4] or 0)
                out[#out + 1] = utf8_char(v)
                i = i + 6
            elseif n1 == "n" then out[#out+1] = "\n"; i = i + 2
            elseif n1 == "r" then out[#out+1] = "\r"; i = i + 2
            elseif n1 == "t" then out[#out+1] = "\t"; i = i + 2
            elseif n1 == "b" then out[#out+1] = "\b"; i = i + 2
            elseif n1 == "f" then out[#out+1] = "\f"; i = i + 2
            elseif n1 == '"' or n1 == "\\" or n1 == "/" then
                out[#out+1] = n1; i = i + 2
            else
                out[#out+1] = n1; i = i + 2
            end
        end
    end
    return table.concat(out)
end

local function encode_key(k)
    return cjson.encode(tostring(k))
end

local function skip_ws(s, i, n)
    while i <= n do
        local c = s:byte(i)
        if c ~= 32 and c ~= 9 and c ~= 10 and c ~= 13 then break end
        i = i + 1
    end
    return i
end

local function scan_string(s, i, n)
    if s:byte(i) ~= 34 then return nil end
    local j = i + 1
    while j <= n do
        local c = s:byte(j)
        if c == 92 then
            j = j + 2
        elseif c == 34 then
            local raw = s:sub(i, j)
            return unescape_json_key(s:sub(i + 1, j - 1)), j + 1, raw
        else
            j = j + 1
        end
    end
    return nil
end

-- Numbers have no closing delimiter, so a token that runs to the buffer end
-- may continue in the next chunk. Return nil (need more) unless this is EOF.
local function skip_number(s, i, n, eof)
    local j = i
    if s:byte(j) == 45 then j = j + 1 end
    while j <= n do
        local c = s:byte(j)
        if (c >= 48 and c <= 57) or c == 46 or c == 101 or c == 69 or c == 43 or c == 45 then
            j = j + 1
        else
            break
        end
    end
    if j == i or (s:byte(i) == 45 and j == i + 1) then return nil end
    if j > n and not eof then return nil end
    return j
end

-- true/false/null. A partial token at the buffer end carries unless EOF.
local function skip_literal(s, i, n, eof)
    if s:sub(i, i + 3) == "true" then return i + 4 end
    if s:sub(i, i + 4) == "false" then return i + 5 end
    if s:sub(i, i + 3) == "null" then return i + 4 end
    if not eof then
        -- A prefix of a literal that reaches the buffer end must wait.
        local rest = s:sub(i, n)
        if rest ~= "" and (("true"):find(rest, 1, true) == 1
            or ("false"):find(rest, 1, true) == 1
            or ("null"):find(rest, 1, true) == 1) then
            return "carry"
        end
    end
    return nil
end

local function skip_value(s, i, n, eof)
    i = skip_ws(s, i, n)
    if i > n then return nil end
    local c = s:byte(i)
    if c == 34 then
        local _, after = scan_string(s, i, n)
        return after
    end
    if c == 123 or c == 91 then
        local depth, j, in_str, esc = 0, i, false, false
        while j <= n do
            local b = s:byte(j)
            if in_str then
                if esc then esc = false
                elseif b == 92 then esc = true
                elseif b == 34 then in_str = false end
            else
                if b == 34 then in_str = true
                elseif b == 123 or b == 91 then depth = depth + 1
                elseif b == 125 or b == 93 then
                    depth = depth - 1
                    if depth == 0 then return j + 1 end
                end
            end
            j = j + 1
        end
        return nil
    end
    local lit = skip_literal(s, i, n, eof)
    if lit == "carry" then return nil end
    if lit then return lit end
    return skip_number(s, i, n, eof)
end

local function is_num_char(c)
    return (c >= 48 and c <= 57) or c == 46 or c == 101 or c == 69 or c == 43 or c == 45
end

local emit
local begin_arr_elem

-- Resumable value scanner. Continues from state.pos with vs.{kind,depth,...}
-- so a large unmatched string/container is O(n), not re-scanned from its start.
-- dest: "stream" (emit verbatim), "capture" (vs.acc), "drop".
-- Returns "done", "need", or nil, err.
local function resume_value(state, eof, vs, dest)
    local s, n, i = state.buf, #state.buf, state.pos
    local function take(from, to)
        if to < from then return end
        local part = s:sub(from, to)
        if dest == "capture" then
            vs.acc = (vs.acc or "") .. part
        elseif dest == "stream" then
            emit(state, part)
        end
    end

    if not vs.kind then
        local j = skip_ws(s, i, n)
        if j > i then
            if dest == "stream" then take(i, j - 1)
            elseif dest == "capture" then vs.lead = (vs.lead or "") .. s:sub(i, j - 1)
            end
            i = j
            state.pos = i
        end
        if i > n then
            if eof then return nil, "incomplete" end
            return "need"
        end
        local c = s:byte(i)
        if c == 34 then
            vs.kind = "string"
        elseif c == 123 or c == 91 then
            vs.kind = "container"
            vs.depth = 1
            vs.in_str = false
            vs.esc = false
        elseif c == 116 or c == 102 or c == 110 then
            vs.kind = "literal"
        elseif c == 45 or (c >= 48 and c <= 57) then
            vs.kind = "number"
        else
            return nil, "bad_value"
        end
    end

    i = state.pos
    s, n = state.buf, #state.buf

    if vs.kind == "number" then
        local j = i
        if s:byte(j) == 45 then j = j + 1 end
        while j <= n and is_num_char(s:byte(j)) do
            j = j + 1
        end
        if j == i or (s:byte(i) == 45 and j == i + 1) then
            if j > n and not eof then return "need" end
            return nil, "bad_number"
        end
        if j > n and not eof then return "need" end
        take(i, j - 1)
        state.pos = j
        return "done"
    end

    if vs.kind == "literal" then
        local lit = skip_literal(s, i, n, eof)
        if lit == "carry" then return "need" end
        if not lit then return nil, "bad_literal" end
        take(i, lit - 1)
        state.pos = lit
        return "done"
    end

    if vs.kind == "string" then
        local j = i
        if not vs.opened then
            take(i, i)
            vs.opened = true
            vs.in_str = true
            vs.esc = false
            j = i + 1
            if j > n then
                state.pos = j
                if eof then return nil, "incomplete" end
                return "need"
            end
            i = j
        end
        while j <= n do
            local b = s:byte(j)
            if vs.esc then
                vs.esc = false
                j = j + 1
            elseif b == 92 then
                vs.esc = true
                j = j + 1
                if j > n then
                    take(i, n)
                    state.pos = n + 1
                    if eof then return nil, "incomplete" end
                    return "need"
                end
            elseif b == 34 then
                take(i, j)
                state.pos = j + 1
                return "done"
            else
                j = j + 1
            end
        end
        if eof then return nil, "incomplete" end
        take(i, n)
        state.pos = n + 1
        return "need"
    end

    if vs.kind == "container" then
        local j = i
        if not vs.opened then
            take(i, i)
            vs.opened = true
            j = i + 1
            if j > n then
                state.pos = j
                if eof then return nil, "incomplete" end
                return "need"
            end
            i = j
        end
        while j <= n do
            local b = s:byte(j)
            if vs.in_str then
                if vs.esc then vs.esc = false
                elseif b == 92 then vs.esc = true
                elseif b == 34 then vs.in_str = false end
            else
                if b == 34 then vs.in_str = true
                elseif b == 123 or b == 91 then vs.depth = vs.depth + 1
                elseif b == 125 or b == 93 then
                    vs.depth = vs.depth - 1
                    if vs.depth == 0 then
                        take(i, j)
                        state.pos = j + 1
                        return "done"
                    end
                end
            end
            j = j + 1
        end
        if eof then return nil, "incomplete" end
        take(i, n)
        state.pos = n + 1
        return "need"
    end

    return nil, "bad_value"
end

local function unescape_seg(seg)
    return (tostring(seg):gsub("~1", "/"):gsub("~0", "~"))
end

local function last_seg(pointer)
    if type(pointer) ~= "string" or pointer == "" or pointer == "/" then return nil end
    local seg = pointer:match("/([^/]*)$") or pointer
    return unescape_seg(seg)
end

local function is_index_token(s)
    return type(s) == "string" and s:match("^%d+$") ~= nil
end

-- First path segment as an array index (0-based), or nil. "/5" and "/5/x" → 5.
local function first_index(pathrel)
    if type(pathrel) ~= "string" then return nil end
    local d = pathrel:match("^/(%d+)")
    return d and tonumber(d) or nil
end

-- True when the relative pointer is exactly a direct numeric child ("/5").
local function is_direct_index_path(pathrel)
    return type(pathrel) == "string" and pathrel:match("^/%d+$") ~= nil
end

-- For the FIRST numeric segment in an absolute pointer, return its array parent
-- and index. "/items/2" and "/items/2/amt" → ("/items", 2). No numeric → nil.
local function array_ref(pointer)
    if type(pointer) ~= "string" then return nil end
    local par = ""
    for seg in pointer:gmatch("/([^/]*)") do
        if seg:match("^%d+$") then
            return (par == "" and "" or par), tonumber(seg)
        end
        par = par .. "/" .. seg
    end
    return nil
end

local function parent_of(pointer)
    if type(pointer) ~= "string" or pointer == "" or pointer == "/" then return "" end
    local parent = pointer:match("^(.*)/[^/]*$")
    return parent or ""
end

local function norm_path(p)
    if not p or p == "/" then return "" end
    return p
end

-- Pointer relative to parent, or nil if not under parent.
-- parent "" (root array) yields the pointer itself.
local function relative_under(parent, pointer)
    if type(pointer) ~= "string" then return nil end
    parent = norm_path(parent)
    pointer = norm_path(pointer)
    if parent == "" then return pointer end
    if pointer == parent then return "" end
    local pref = parent .. "/"
    if pointer:sub(1, #pref) == pref then
        return "/" .. pointer:sub(#pref + 1)
    end
    return nil
end

local function rewrite_op_path(op, new_path)
    local copy = {}
    for k, v in pairs(op) do copy[k] = v end
    copy.path = new_path
    return copy
end

-- Compile ops[] (and buckets) in apply_program order onto WIRE paths so
-- rename /amt→/amount then coerce /amount both fire at wire key amt.
local function compile(program)
    program = program or {}
    local loc = {}
    local wrap_key = program.wrapKey
    local unwrap_key = program.unwrapKey
    local wrap_prefix = wrap_key and ("/" .. tostring(wrap_key)) or nil
    local by_wire = {}
    local windows = {}
    local defaults_by_parent = {}
    local has_value = false
    local has_conditional = false
    local pointers = {}
    local ordered_ops = {}
    local function wire_of(p)
        p = norm_path(p)
        if loc[p] ~= nil then return loc[p] end
        if wrap_prefix then
            if p == wrap_prefix then return "" end
            local pref = wrap_prefix
            if p:sub(1, #pref) == pref then
                local rest = p:sub(#pref + 1)
                if rest == "" then return "" end
                return rest
            end
        end
        return p
    end

    local function slot(wp)
        wp = norm_path(wp)
        by_wire[wp] = by_wire[wp] or { value_ops = {} }
        pointers[wp] = true
        return by_wire[wp]
    end

    local function apply_op(op)
        if type(op) ~= "table" or not op.op then return end
        local k = op.op
        if k == "conditional" then
            has_conditional = true
            if type(op["then"]) == "table" then
                for _, c in ipairs(op["then"]) do apply_op(c) end
            end
            if type(op.otherwise) == "table" then
                for _, c in ipairs(op.otherwise) do apply_op(c) end
            end
            return
        end
        if k == "wrap" then
            wrap_key = op.key
            wrap_prefix = "/" .. tostring(op.key)
            return
        end
        if k == "unwrap" then
            unwrap_key = op.key
            return
        end
        ordered_ops[#ordered_ops + 1] = op
        if k == "rename" or k == "move" or k == "copy" then
            local from, to = op.from, op.to
            -- Cross-parent move/copy is UNBOUNDED and never streamed.
            if parent_of(from) ~= parent_of(to) then return end
            local w = wire_of(from)
            local s = slot(w)
            s.emit_key = last_seg(to)
            loc[norm_path(to)] = w
            if k ~= "copy" then loc[norm_path(from)] = false end
            local par = parent_of(from)
            local from_seg, to_seg = last_seg(from), last_seg(to)
            -- Object-field move/copy (and numeric-index rename/move/copy) hold
            -- a window on the parent. Array frames replay these in program order.
            if k == "move" or k == "copy"
                or (k == "rename" and is_index_token(from_seg) and is_index_token(to_seg)) then
                windows[norm_path(par)] = windows[norm_path(par)] or {
                    from_key = from_seg, to_key = to_seg, copy = (k == "copy"),
                }
            end
            slot(wire_of(to))
            return
        end
        if k == "remove" then
            slot(wire_of(op.path)).remove = true
            return
        end
        if k == "default" then
            local p = op.path
            local par = parent_of(p)
            defaults_by_parent[norm_path(par)] = defaults_by_parent[norm_path(par)] or {}
            local list = defaults_by_parent[norm_path(par)]
            list[#list + 1] = op
            slot(wire_of(p)).default = op
            return
        end
        if k == "strip_unknown" then
            slot(wire_of(op.path or "")).strip = op
            return
        end
        if VALUE_OPS[k] then
            has_value = true
            local s = slot(wire_of(op.path))
            s.value_ops[#s.value_ops + 1] = op
        end
    end

    if type(program.moves) == "table" then
        for _, mv in ipairs(program.moves) do
            if mv and mv.from and mv.to then
                apply_op({
                    op = mv.copy and "copy" or "move", from = mv.from, to = mv.to
                })
            end
        end
    end
    if type(program.renames) == "table" then
        for from, to in pairs(program.renames) do
            apply_op({
                op = "rename", from = "/" .. tostring(from), to = "/" .. tostring(to)
            })
        end
    end
    if type(program.coalesce) == "table" then
        for _, co in ipairs(program.coalesce) do
            if co then apply_op({ op = "coalesce", path = co.path, value = co.value }) end
        end
    end
    if type(program.defaults) == "table" then
        for k, v in pairs(program.defaults) do
            apply_op({ op = "default", path = "/" .. tostring(k), value = v, on = "ABSENT" })
        end
    end
    if type(program.coercions) == "table" then
        for k, t in pairs(program.coercions) do
            apply_op({ op = "coerce", path = "/" .. tostring(k), targetType = t })
        end
    end
    if type(program.scales) == "table" then
        for _, sc in ipairs(program.scales) do
            if sc then apply_op({
                op = "scale", path = sc.path, numerator = sc.numerator,
                denominator = sc.denominator, expectedMin = sc.expectedMin,
                expectedMax = sc.expectedMax,
            }) end
        end
    end
    if type(program.valueMaps) == "table" then
        for _, vm in ipairs(program.valueMaps) do
            if vm then apply_op({
                op = "map_value", path = vm.path, mapping = vm.mapping,
                onUnmapped = vm.onUnmapped or "passthrough",
            }) end
        end
    end
    if type(program.dateFormats) == "table" then
        for _, df in ipairs(program.dateFormats) do
            if df then apply_op({
                op = "reformat_date", path = df.path, sourceFormat = df.sourceFormat,
                targetFormat = df.targetFormat, tzPolicy = df.assumeTimezone or df.tzPolicy,
            }) end
        end
    end
    if type(program.stripUnknown) == "table" then
        for _, su in ipairs(program.stripUnknown) do apply_op({
            op = "strip_unknown", path = su.path or "/", allowed = su.allowed
        }) end
    end
    if type(program.wrapArrays) == "table" then
        for _, wa in ipairs(program.wrapArrays) do
            if wa then apply_op({ op = "wrap_array", path = wa.path }) end
        end
    end
    if type(program.unwrapArrays) == "table" then
        for _, ua in ipairs(program.unwrapArrays) do
            if ua then apply_op({ op = "unwrap_array", path = ua.path }) end
        end
    end
    if type(program.removals) == "table" then
        for _, key in ipairs(program.removals) do
            apply_op({ op = "remove", path = "/" .. tostring(key) })
        end
    end
    if wrap_key then wrap_prefix = "/" .. tostring(wrap_key) end
    if type(program.ops) == "table" then
        for _, op in ipairs(program.ops) do apply_op(op) end
    end

    local writePointers = {}
    if type(program.writePointers) == "table" then
        for _, p in ipairs(program.writePointers) do
            writePointers[#writePointers + 1] = p
            pointers[norm_path(p)] = true
        end
    end
    for p in pairs(pointers) do
        local found = false
        for _, e in ipairs(writePointers) do
            if norm_path(e) == p then found = true end
        end
        if not found and p ~= "" then
            writePointers[#writePointers + 1] = p
        end
    end

    -- Array parents that cannot drop-as-we-go, because a wire index no longer
    -- equals the live (post-shift) index. This happens for:
    --   * same-parent numeric move/copy/rename (reorders / replaces by index), or
    --   * a numeric-index remove co-occurring with any other numeric-index op
    --     (the remove shifts the live index a later op would target).
    -- Such parents are held and their child ops replayed in program order.
    local hold_array, array_ops, array_span = {}, {}, {}
    local idx_ops_by_parent = {}   -- count of ops touching an array by numeric index
    local remove_idx_by_parent = {}
    local function note_idx_op(par)
        if not par then return nil end
        par = norm_path(par)
        idx_ops_by_parent[par] = (idx_ops_by_parent[par] or 0) + 1
        return par
    end
    for _, op in ipairs(ordered_ops) do
        local k = op.op
        if k == "remove" then
            -- Only a direct numeric remove ("/items/2") shifts its array; a
            -- deeper remove ("/items/2/x") edits an element, not the array.
            if is_index_token(last_seg(op.path)) then
                local par = note_idx_op(parent_of(op.path))
                if par then remove_idx_by_parent[par] = (remove_idx_by_parent[par] or 0) + 1 end
            end
        elseif k == "move" or k == "copy" or k == "rename" then
            note_idx_op((array_ref(op.from)))
            note_idx_op((array_ref(op.to)))
        elseif VALUE_OPS[k] then
            -- Attribute deep edits ("/items/1/amt") to the array they index into,
            -- so a co-occurring remove forces a hold (live index != wire index).
            note_idx_op((array_ref(op.path)))
        end
    end
    for par, win in pairs(windows) do
        if is_index_token(win.from_key) and is_index_token(win.to_key) then
            hold_array[par] = true
        end
    end
    for par, c in pairs(idx_ops_by_parent) do
        local rc = remove_idx_by_parent[par] or 0
        if rc >= 2 or (rc >= 1 and c >= 2) then hold_array[par] = true end
    end
    -- Only move/copy/rename use from/to as pointers; value ops carry non-pointer
    -- fields there (coerce.to = "STRING", scale.by = 100, ...) which must not be
    -- relativized.
    local STRUCT = { move = true, copy = true, rename = true }
    local function relativize_op(op, parent)
        local c = {}
        for k, v in pairs(op) do c[k] = v end
        local any = false
        if c.path then
            local r = relative_under(parent, c.path)
            if not r then return nil end
            c.path = r
            any = true
        end
        if STRUCT[op.op] then
            if c.from then
                local r = relative_under(parent, c.from)
                if not r then return nil end
                c.from = r
                any = true
            end
            if c.to then
                local r = relative_under(parent, c.to)
                if not r then return nil end
                c.to = r
                any = true
            end
        end
        return any and c or nil
    end
    for par in pairs(hold_array) do
        local list = {}
        for _, op in ipairs(ordered_ops) do
            local rel = relativize_op(op, par)
            if rel then list[#list + 1] = rel end
        end
        array_ops[par] = list
        -- Inter-pointer span: lo is the smallest index any op touches; elements
        -- before lo are unchanged and stream verbatim. The tail is bounded only
        -- when no op shifts length (remove and move/rename delete a source, which
        -- shifts every later index); copy and value-ops do not shift, so a
        -- copy/value-only program can also stream the suffix after hi.
        local lo, hi, direct_only, has_shift = math.huge, -1, true, false
        for _, op in ipairs(list) do
            local k = op.op
            if k == "remove" or k == "move" or k == "rename" then has_shift = true end
            local prs = {}
            if op.path then prs[#prs + 1] = op.path end
            if STRUCT[k] then
                if op.from then prs[#prs + 1] = op.from end
                if op.to then prs[#prs + 1] = op.to end
            end
            for _, pr in ipairs(prs) do
                local fi = first_index(pr)
                if fi then
                    if fi < lo then lo = fi end
                    if fi > hi then hi = fi end
                end
                if not is_direct_index_path(pr) then direct_only = false end
            end
        end
        if lo == math.huge then lo = 0 end
        -- Nested-field edits inside a shifting array need the decoded oracle;
        -- hold the whole array (lo 0) and let flush_array use apply_ops.
        if not direct_only then lo = 0 end
        array_span[par] = {
            lo = lo,
            hi = (direct_only and not has_shift) and hi or math.huge,
            direct_only = direct_only,
        }
    end

    return {
        by_wire = by_wire,
        windows = windows,
        defaults_by_parent = defaults_by_parent,
        wrap_key = wrap_key,
        unwrap_key = unwrap_key,
        has_value = has_value,
        has_conditional = has_conditional,
        has_window = next(windows) ~= nil,
        writePointers = writePointers,
        hold_array = hold_array,
        array_ops = array_ops,
        array_span = array_span,
        -- Unwrap is a deferred-object-frame (extract at EOF). Value ops and
        -- BOUNDED_WINDOW hold until EOF so a fail-closed cannot torn-page after
        -- flush. Pure structural FORWARD_ONLY (rename/remove/wrap) may drain early.
        hold_output = unwrap_key ~= nil or has_value or (next(windows) ~= nil),
    }
end

local function build_trie(pointers)
    local trie = {}
    for _, p in ipairs(pointers or {}) do
        if type(p) == "string" then
            local node = trie
            if p == "" or p == "/" then
                node._end = true
            else
                for seg in p:gmatch("/([^/]*)") do
                    seg = unescape_seg(seg)
                    node[seg] = node[seg] or {}
                    node = node[seg]
                end
                node._end = true
            end
        end
    end
    return trie
end

local function trie_has_children(node)
    if type(node) ~= "table" then return false end
    for k in pairs(node) do
        if k ~= "_end" then return true end
    end
    return false
end

function _M.trie_for(program)
    local compiled = program and program._compiled or compile(program)
    local hash = (program and program.programHash)
        or (ngx and ngx.ctx and ngx.ctx.programHash)
    local dict = ngx and ngx.shared and ngx.shared.mendr_splice_trie
    if dict and hash then
        local cached = dict:get("t:" .. tostring(hash))
        if cached then
            local decoded = cjson.decode(cached)
            if decoded then return decoded, compiled end
        end
    end
    local trie = build_trie(compiled.writePointers)
    if dict and hash then
        pcall(function() dict:set("t:" .. tostring(hash), cjson.encode(trie), 3600) end)
    end
    return trie, compiled
end

local function apply_value_ops(raw, ops)
    if not ops or #ops == 0 then return raw end
    local decoded = cjson.decode(raw)
    local wrapper = { v = decoded }
    local mapped = {}
    for i, op in ipairs(ops) do
        mapped[i] = rewrite_op_path(op, "/v")
    end
    local out, ok = transform.apply_ops(wrapper, mapped)
    if ok == false then return nil, "fail_closed" end
    local encoded = cjson.encode(out.v)
    if not encoded then return raw end
    -- Keep original bytes when the decoded value is unchanged (int64).
    -- Nested tables never compare equal by identity; they always re-encode.
    if cjson.decode(encoded) == cjson.decode(raw) then return raw end
    return encoded
end

emit = function(state, s)
    if not s or s == "" then return end
    if state.wrap_key and not state.wrap_prefix_emitted then
        state.out[#state.out + 1] = "{" .. encode_key(state.wrap_key) .. ":"
        state.wrap_prefix_emitted = true
    end
    state.out[#state.out + 1] = s
end

-- Drop parsed prefix. Preserve an unconsumed comma so comma_at stays valid.
local function compact(state)
    local cut = state.pos or 1
    for _, fr in ipairs(state.stack or {}) do
        if fr.comma_at and fr.comma_at < cut then cut = fr.comma_at end
    end
    if cut <= 1 then return end
    local delta = cut - 1
    state.buf = state.buf:sub(cut)
    state.pos = (state.pos or 1) - delta
    for _, fr in ipairs(state.stack or {}) do
        if fr.comma_at then fr.comma_at = fr.comma_at - delta end
    end
end

-- The comma between members is a separator decided by had_member at emit time,
-- not the wire comma. lead_ws is the inter-member whitespace with its comma
-- stripped. This keeps output valid when members are dropped or reordered
-- (remove of the first key, or a window whose from/to are not the first key).
local function sep(frame)
    return frame.had_member and "," or ""
end

local function flush_pending(state, frame)
    local p = frame.pending
    if not p or p.drop then
        frame.pending = nil
        return
    end
    emit(state, sep(frame) .. p.body)
    frame.had_member = true
    frame.pending = nil
end

-- Member body WITHOUT the leading separator comma (lead_ws already comma-free).
local function member_bytes(lead_ws, key_raw, colon_ws, value_raw, emit_key)
    local parts = { lead_ws or "" }
    parts[#parts + 1] = emit_key and encode_key(emit_key) or key_raw
    parts[#parts + 1] = colon_ws or ":"
    parts[#parts + 1] = value_raw
    return table.concat(parts)
end

local function close_object(state, frame)
    flush_pending(state, frame)
    local defs = state.compiled.defaults_by_parent[frame.path or ""]
    if defs then
        for _, op in ipairs(defs) do
            local key = last_seg(op.path)
            local on = tostring(op.on or "ABSENT"):upper()
            if key and not frame.seen[key] then
                if on == "ABSENT" or on == "BOTH" then
                    local encoded = cjson.encode(op.value)
                    emit(state, sep(frame) .. encode_key(key) .. ":" .. (encoded or "null"))
                    frame.had_member = true
                    frame.seen[key] = true
                end
            end
        end
    end
    emit(state, "}")
end

-- Finish a BOUNDED_WINDOW parent: rewrite held members, then emit.
local function flush_window(state, frame)
    local win = frame.window
    if not win then return true end
    local from_key, to_key = win.from_key, win.to_key
    local from_val
    for _, m in ipairs(win.members) do
        if m.ks == from_key then from_val = m.value_raw end
    end
    local function emit_m(m, ks, value_raw)
        if m.drop then return end
        local relabel = (ks ~= m.ks) and ks or nil
        local body = member_bytes(m.lead_ws, m.kr, m.colon_ws, value_raw or m.value_raw, relabel)
        emit(state, sep(frame) .. body)
        frame.had_member = true
    end
    -- Rebuild: skip from_key (moved), replace to_key with from value, keep others.
    -- If to_key absent, append from as to_key.
    local saw_to = false
    for _, m in ipairs(win.members) do
        if m.ks == from_key and not win.copy then
            -- omit source
        elseif m.ks == to_key then
            saw_to = true
            if from_val then
                emit_m(m, to_key, from_val)
            else
                emit_m(m, m.ks, m.value_raw)
            end
        else
            emit_m(m, m.ks, m.value_raw)
        end
    end
    if from_val and not saw_to then
        emit(state, sep(frame) .. encode_key(to_key) .. ":" .. from_val)
        frame.had_member = true
    end
    frame.window = nil
    return true
end

-- Replay array-index ops in program order on the held span, mirroring
-- transform.lua array semantics (set = replace-if-present, delete = remove+shift)
-- so splice == apply_program == JsonPointers. Two engines:
--   * direct_only: operate on RAW element bytes (structural ops just move/drop
--     strings; value-ops decode a single element). Untouched int64 survives.
--   * otherwise (nested-field edits under a shifting array): decode the whole
--     held array through apply_ops.
-- `lo` offsets absolute-within-parent indices to the held member list.
local function replay_array_raw(entries, lo, ops)
    local function pos(absidx) return (absidx - lo) + 1 end
    for _, op in ipairs(ops) do
        local k = op.op
        if k == "remove" then
            local fi = first_index(op.path)
            if fi then
                local p = pos(fi)
                if entries[p] ~= nil then table.remove(entries, p) end
            end
        elseif k == "move" or k == "copy" or k == "rename" then
            local ff, ft = first_index(op.from), first_index(op.to)
            if ff and ft then
                local pf = pos(ff)
                local v = entries[pf]
                if v ~= nil then
                    local pt = pos(ft)
                    if entries[pt] ~= nil then entries[pt] = v end -- set = replace
                    if k ~= "copy" then table.remove(entries, pf) end -- delete + shift
                end
            end
        elseif VALUE_OPS[k] then
            local fi = first_index(op.path)
            if fi then
                local p = pos(fi)
                if entries[p] ~= nil then
                    local nv, err = apply_value_ops(entries[p], { op })
                    if err ~= "fail_closed" and nv then entries[p] = nv end
                end
            end
        end
    end
end

local function flush_array(state, frame)
    if not frame.hold_all or frame.win_flushed then return true end
    frame.win_flushed = true
    frame.hold_active = false
    local members = frame.members or {}
    local function emit_raw(list)
        for i = 1, #list do
            begin_arr_elem(state, frame)
            emit(state, list[i] or "null")
        end
    end
    if #members == 0 then return true end
    local entries = {}
    for i, m in ipairs(members) do entries[i] = m.value_raw or "null" end

    if frame.direct_only then
        replay_array_raw(entries, frame.lo or 0, frame.array_ops or {})
        emit_raw(entries)
        frame.members = nil
        return true
    end

    -- Decode fallback (nested-field edits). lo is 0 here (whole array held).
    local decoded = cjson.decode("[" .. table.concat(entries, ",") .. "]")
    if type(decoded) ~= "table" then
        emit_raw(entries)
        frame.members = nil
        return true
    end
    local function on_v(p)
        if not p or p == "" or p == "/" then return "/v" end
        if p:sub(1, 1) ~= "/" then p = "/" .. p end
        return "/v" .. p
    end
    local ops = {}
    for _, op in ipairs(frame.array_ops or {}) do
        local c = {}
        for k, v in pairs(op) do c[k] = v end
        if c.path then c.path = on_v(c.path) end
        if c.from then c.from = on_v(c.from) end
        if c.to then c.to = on_v(c.to) end
        ops[#ops + 1] = c
    end
    local out, ok = transform.apply_ops({ v = decoded }, ops)
    if ok == false then
        emit_raw(entries)
        frame.members = nil
        return true
    end
    local arr = out and out.v or decoded
    if type(arr) == "table" then
        local pieces = {}
        for i = 1, #arr do pieces[i] = cjson.encode(arr[i]) or "null" end
        emit_raw(pieces)
    end
    frame.members = nil
    return true
end

local function push_obj(state, path, trie)
    state.stack[#state.stack + 1] = {
        t = "obj", path = path, trie = trie, phase = "open",
        seen = {}, had_member = false,
        window = state.compiled.windows[path or ""],
        hold_bytes = 0,
    }
end

local function push_arr(state, path, trie)
    local p = path or ""
    local compiled = state.compiled or {}
    local hold_all = compiled.hold_array and compiled.hold_array[p] or false
    local span = (hold_all and compiled.array_span and compiled.array_span[p]) or nil
    state.stack[#state.stack + 1] = {
        t = "arr", path = path, trie = trie, phase = "open", had_elem = false, idx = 0,
        hold_all = hold_all,
        array_ops = compiled.array_ops and compiled.array_ops[p] or nil,
        members = hold_all and {} or nil,
        hold_bytes = 0,
        -- Inter-pointer span for the held array; elements outside stream verbatim.
        lo = span and span.lo or 0,
        hi = span and span.hi or math.huge,
        direct_only = span and span.direct_only or false,
        hold_active = false, -- true only while [lo..hi] is being captured
        win_flushed = false,
        window = compiled.windows and compiled.windows[p] or nil,
    }
end

-- Comma between array elements is decided by had_elem at emit time, not the
-- wire comma, so dropping index 0 does not leave "[,2]" and dropping the last
-- element does not leave a trailing comma.
begin_arr_elem = function(state, frame)
    if frame.had_elem then emit(state, ",") end
    frame.had_elem = true
end

-- True while a BOUNDED_WINDOW span is being held (not the whole document).
local function window_blocking(state)
    for _, fr in ipairs(state.stack or {}) do
        if fr.hold_active then return true end
        if fr.window and fr.window.active then return true end
    end
    return false
end

local function refresh_hold(state)
    if state.compiled and state.compiled.hold_output then
        state.must_hold = true
        return
    end
    if state.compiled and state.compiled.unwrap_key then
        state.must_hold = true
        return
    end
    state.must_hold = window_blocking(state)
end

-- True when captured value bytes are JSON null (optional surrounding whitespace).
local function is_json_null(raw)
    if type(raw) ~= "string" then return false end
    local n = #raw
    local i = skip_ws(raw, 1, n)
    if raw:sub(i, i + 3) ~= "null" then return false end
    i = skip_ws(raw, i + 4, n)
    return i > n
end

-- default on=NULL/BOTH replaces a present JSON null. ABSENT is handled at
-- close_object for keys that were never seen.
local function apply_default_null(info, value_raw)
    local d = info and info.default
    if not d then return value_raw end
    local on = tostring(d.on or "ABSENT"):upper()
    if on ~= "NULL" and on ~= "BOTH" then return value_raw end
    if not is_json_null(value_raw) then return value_raw end
    local encoded = cjson.encode(d.value)
    return encoded or value_raw
end

local function member_dest(top, info, drop, key)
    if drop then return "drop" end
    if top.window then
        local fk, tk = top.window.from_key, top.window.to_key
        if top.window.active or key == fk or key == tk then return "capture" end
    end
    if info and info.value_ops and #info.value_ops > 0 then return "capture" end
    -- Must capture to see a present null; streaming would already have emitted it.
    if info and info.default then
        local on = tostring(info.default.on or "ABSENT"):upper()
        if on == "NULL" or on == "BOTH" then return "capture" end
    end
    return "stream"
end

local function finish_obj_member(state, top, m)
    if m.stream then
        top.had_member = true
        top.seen[m.key] = true
        top.member = nil
        return true
    end
    local value_raw = m.vs.acc
    local info, key, drop = m.info, m.key, m.drop
    local colon_ws = (m.colon_ws or "") .. (m.vs.lead or "")
    if info and info.value_ops and #info.value_ops > 0 and not drop then
        local newv, err = apply_value_ops(value_raw, info.value_ops)
        if err ~= "fail_closed" and newv then value_raw = newv end
    end
    if not drop then value_raw = apply_default_null(info, value_raw) end
    local ek = info and info.emit_key
    local body = member_bytes(m.lead_ws, m.kr, colon_ws, value_raw, ek)
    if drop then body = nil end
    if top.window then
        local fk, tk = top.window.from_key, top.window.to_key
        local was_active = top.window.active
        if key == fk or key == tk then top.window.active = true end
        if top.window.active then
            -- A pre-window member may still be pending; emit it before the
            -- reordered window members so object order stays valid.
            if not was_active then flush_pending(state, top) end
            top.hold_bytes = (top.hold_bytes or 0) + #(value_raw or "") + #key
            if top.hold_bytes > WINDOW_CAP then
                return nil, "window_overflow"
            end
            top.window.members = top.window.members or {}
            top.window.members[#top.window.members + 1] = {
                ks = key, kr = m.kr, lead_ws = m.lead_ws, colon_ws = colon_ws,
                value_raw = value_raw, drop = drop, emit_key = ek,
            }
            top.seen[key] = true
            local saw_from, saw_to = false, false
            for _, wm in ipairs(top.window.members) do
                if wm.ks == fk then saw_from = true end
                if wm.ks == tk then saw_to = true end
            end
            if saw_from and saw_to then
                flush_window(state, top)
            end
        else
            if top.pending and top.pending.ks == key then
                top.pending = { ks = key, body = body, drop = drop }
            else
                flush_pending(state, top)
                top.pending = { ks = key, body = body, drop = drop }
            end
            top.seen[key] = true
        end
    else
        if top.pending and top.pending.ks == key then
            top.pending = { ks = key, body = body, drop = drop }
        else
            flush_pending(state, top)
            top.pending = { ks = key, body = body, drop = drop }
        end
        top.seen[key] = true
    end
    top.member = nil
    return true
end

local function run(state, eof)
    local compiled = state.compiled
    while true do
        local top = state.stack[#state.stack]
        local s, n, i = state.buf, #state.buf, state.pos
        if not top then
            if state.root_vs then
                local st, err = resume_value(state, eof, state.root_vs, "stream")
                if err then return nil, err end
                if st == "need" then return end
                state.root_vs = nil
                if compiled.wrap_key then emit(state, "}") end
                state.done = eof
                return
            end
            i = skip_ws(s, i, n)
            if i > n then
                state.pos = i
                if eof then
                    if compiled.wrap_key and state.wrap_prefix_emitted then
                        emit(state, "}")
                    end
                    state.done = true
                    return
                end
                return
            end
            local c = s:byte(i)
            if c == 123 then
                emit(state, "{")
                push_obj(state, "", state.trie)
                state.pos = i + 1
            elseif c == 91 then
                emit(state, "[")
                push_arr(state, "", state.trie)
                state.pos = i + 1
            else
                state.pos = i
                state.root_vs = {}
            end
        elseif top.member then
            local m = top.member
            if m.nested_maybe and not m.vs.kind then
                local js = skip_ws(state.buf, state.pos, #state.buf)
                if js > #state.buf then
                    state.pos = js
                    if eof then return nil, "incomplete" end
                    return
                end
                state.pos = js
                local vb = state.buf:byte(js)
                if vb == 123 or vb == 91 then
                    flush_pending(state, top)
                    local ek = m.info and m.info.emit_key
                    emit(state, sep(top) .. (m.lead_ws or "") .. (ek and encode_key(ek) or m.kr) .. (m.colon_ws or ":"))
                    if vb == 123 then
                        emit(state, "{")
                        push_obj(state, m.child_path, m.child_trie)
                    else
                        emit(state, "[")
                        push_arr(state, m.child_path, m.child_trie)
                    end
                    state.pos = js + 1
                    top.had_member = true
                    top.seen[m.key] = true
                    top.member = nil
                else
                    m.nested_maybe = false
                end
            end
            m = top.member
            if m then
                if m.stream == nil then
                    local dest = member_dest(top, m.info, m.drop, m.key)
                    m.stream = dest == "stream"
                    if m.stream then
                        flush_pending(state, top)
                        local ek = m.info and m.info.emit_key
                        emit(state, sep(top) .. (m.lead_ws or "") .. (ek and encode_key(ek) or m.kr) .. (m.colon_ws or ":"))
                        top.had_member = true
                    end
                end
                local dest = m.stream and "stream" or (m.drop and "drop" or "capture")
                local st, err = resume_value(state, eof, m.vs, dest)
                if err then return nil, err end
                if st == "need" then return end
                local ok, werr = finish_obj_member(state, top, m)
                if not ok then return nil, werr end
            end
        elseif top.elem then
            local e = top.elem
            local dest = e.drop and "drop" or (e.stream and "stream" or "capture")
            local st, err = resume_value(state, eof, e.vs, dest)
            if err then return nil, err end
            if st == "need" then return end
            if e.hold then
                local value_raw = e.vs.acc or "null"
                top.hold_bytes = (top.hold_bytes or 0) + #value_raw
                if top.hold_bytes > WINDOW_CAP then
                    return nil, "window_overflow"
                end
                top.members = top.members or {}
                top.members[#top.members + 1] = { value_raw = value_raw, idx = top.idx }
                top.idx = (top.idx or 0) + 1
                top.elem = nil
            else
                if not e.drop then
                    local value_raw = e.vs.acc
                    if e.info and e.info.value_ops and #e.info.value_ops > 0 then
                        local newv, verr = apply_value_ops(value_raw, e.info.value_ops)
                        if verr ~= "fail_closed" and newv then value_raw = newv end
                    end
                    if not e.stream then emit(state, value_raw) end
                end
                top.idx = (top.idx or 0) + 1
                top.elem = nil
            end
        else
            i = skip_ws(s, i, n)
            if i > n then
                state.pos = i
                if eof then return nil, "incomplete" end
                return
            end
            if top.t == "obj" then
                local b = s:byte(i)
                if b == 125 then
                    if top.window then flush_window(state, top) end
                    close_object(state, top)
                    state.stack[#state.stack] = nil
                    state.pos = i + 1
                    if #state.stack == 0 then
                        if compiled.wrap_key then emit(state, "}") end
                        state.done = eof or true
                        if eof then state.done = true; return end
                    end
                elseif b == 44 then
                    top.comma_at = i
                    state.pos = i + 1
                else
                    local carry_pos = top.comma_at or state.pos
                    local key, after_key, kr = scan_string(s, i, n)
                    if not key then
                        if eof then return nil, "incomplete" end
                        state.pos = carry_pos
                        return
                    end
                    local raw_lead
                    if top.comma_at then
                        raw_lead = s:sub(top.comma_at, i - 1)
                    else
                        raw_lead = s:sub(state.pos, i - 1)
                    end
                    -- The separator comma is decided by had_member at emit time,
                    -- not the wire. Keep only whitespace here (strip one comma) so
                    -- dropping the first key or reordering a window stays valid.
                    local lead_ws = raw_lead:gsub(",", "", 1)
                    top.comma_at = nil
                    i = skip_ws(s, after_key, n)
                    if i > n or s:byte(i) ~= 58 then
                        if i > n and not eof then
                            state.pos = carry_pos
                            return
                        end
                        if s:byte(i) ~= 58 then return nil, "bad_object" end
                    end
                    local colon_start = after_key
                    -- Leave post-colon whitespace for resume_value so a split
                    -- `":" + " 10"` keeps the spaces (stream emits them; capture
                    -- folds them into colon_ws).
                    state.pos = i + 1
                    local colon_ws = s:sub(colon_start, i)
                    i = state.pos
                    local child_path = (top.path == "" or not top.path) and ("/" .. key)
                        or (top.path .. "/" .. key)
                    local child_trie = top.trie and top.trie[key]
                    local info = compiled.by_wire[norm_path(child_path)]
                    local strip = compiled.by_wire[top.path or ""] and compiled.by_wire[top.path or ""].strip
                    local drop = (info and info.remove) or false
                    if strip and type(strip.allowed) == "table" then
                        local allow = {}
                        for _, a in ipairs(strip.allowed) do allow[a] = true end
                        if not allow[key] then drop = true end
                    end
                    local nested = child_trie and trie_has_children(child_trie) and not drop
                    if nested and i <= n then
                        local vb = s:byte(i)
                        if vb == 123 or vb == 91 then
                            flush_pending(state, top)
                            local ek = info and info.emit_key
                            emit(state, sep(top) .. (lead_ws or "") .. (ek and encode_key(ek) or kr) .. (colon_ws or ":"))
                            if vb == 123 then
                                emit(state, "{")
                                push_obj(state, child_path, child_trie)
                            else
                                emit(state, "[")
                                push_arr(state, child_path, child_trie)
                            end
                            state.pos = i + 1
                            top.had_member = true
                            top.seen[key] = true
                            nested = "pushed"
                        else
                            nested = false
                        end
                    end
                    if nested ~= "pushed" then
                        top.member = {
                            key = key, kr = kr, lead_ws = lead_ws, colon_ws = colon_ws,
                            info = info, drop = drop, vs = {},
                            nested_maybe = nested and true or false,
                            child_path = child_path, child_trie = child_trie,
                        }
                    end
                end
            elseif top.t == "arr" then
                local b = s:byte(i)
                if b == 93 then
                    if top.hold_all then
                        local ok, aerr = flush_array(state, top)
                        if not ok then return nil, aerr end
                    end
                    emit(state, "]")
                    state.stack[#state.stack] = nil
                    state.pos = i + 1
                    if #state.stack == 0 then
                        if compiled.wrap_key then emit(state, "}") end
                        state.done = true
                        if eof then return end
                    end
                elseif b == 44 then
                    -- Skip the wire comma; begin_arr_elem emits the separator
                    -- only for elements that are actually kept.
                    state.pos = i + 1
                else
                    local ci = top.idx or 0
                    local idx = tostring(ci)
                    local child_path = (top.path == "" or not top.path) and ("/" .. idx)
                        or (top.path .. "/" .. idx)
                    local child_trie = top.trie and top.trie[idx]
                    local info = compiled.by_wire[norm_path(child_path)]
                    -- Held arrays only capture the inter-pointer span [lo..hi].
                    -- Elements before lo (and, for shift-free programs, after hi)
                    -- stream verbatim so memory stays O(span), not O(array).
                    local in_window = top.hold_all
                        and ci >= (top.lo or 0) and ci <= (top.hi or math.huge)
                    if top.hold_all and not in_window and ci > (top.hi or math.huge)
                        and not top.win_flushed then
                        -- First element past the window: emit the held span first.
                        local ok, aerr = flush_array(state, top)
                        if not ok then return nil, aerr end
                    end
                    local drop = (not top.hold_all) and info and info.remove or false
                    -- Held span captures whole elements (replay at close); prefix
                    -- and suffix elements stream verbatim without a nested push.
                    local nested = (not top.hold_all) and child_trie
                        and trie_has_children(child_trie) and not drop
                    if nested then
                        if s:byte(i) == 123 then
                            begin_arr_elem(state, top)
                            emit(state, "{")
                            push_obj(state, child_path, child_trie)
                            state.pos = i + 1
                            top.idx = (top.idx or 0) + 1
                            nested = "pushed"
                        elseif s:byte(i) == 91 then
                            begin_arr_elem(state, top)
                            emit(state, "[")
                            push_arr(state, child_path, child_trie)
                            state.pos = i + 1
                            top.idx = (top.idx or 0) + 1
                            nested = "pushed"
                        else
                            nested = false
                        end
                    end
                    if nested ~= "pushed" then
                        local hold = in_window
                        if hold then top.hold_active = true end
                        local capture = hold
                            or ((not drop) and info and info.value_ops and #info.value_ops > 0)
                        state.pos = i
                        if not drop and not hold then begin_arr_elem(state, top) end
                        top.elem = {
                            info = info, drop = drop, hold = hold,
                            stream = not drop and not capture, vs = {},
                        }
                    end
                end
            else
                return nil, "bad_stack"
            end
        end
        if eof and #state.stack == 0 and not state.root_vs and state.pos > #state.buf then
            state.done = true
            return
        end
        if state._guard == state.pos and #state.stack == (state._gstack or -1)
            and not (top and (top.member or top.elem)) and not state.root_vs then
            if eof then return nil, "incomplete" end
            return
        end
        state._guard = state.pos
        state._gstack = #state.stack
    end
end

local function ensure(state)
    if state.compiled then return end
    local trie, compiled = _M.trie_for(state.program or {})
    state.compiled = compiled
    state.trie = trie
    state.wrap_key = compiled.wrap_key
    state.out = state.out or {}
    state.stack = state.stack or {}
    state.pos = state.pos or 1
    state.buf = state.buf or ""
    state.must_hold = compiled.hold_output
end

function _M.apply(body, program)
    if type(body) ~= "string" then return nil, "not string" end
    -- Unwrap uses inner copy; strip unwrap from a shadow program for inner apply
    local state = { program = program, buf = body, pos = 1 }
    ensure(state)
    -- splice cannot evaluate conditional predicates (it merges both branches at
    -- compile time). Spill to DOM so the branch selection stays correct.
    if state.compiled.has_conditional then return nil, "conditional" end
    -- Avoid recursive unwrap in inner apply: if unwrap, first extract then
    -- splice inner with unwrap_key cleared.
    if state.compiled.unwrap_key then
        local s, n = body, #body
        local i = skip_ws(s, 1, n)
        if s:byte(i) ~= 123 then return nil, "unwrap_not_object" end
        i = i + 1
        local key_found
        while true do
            i = skip_ws(s, i, n)
            if i > n then return nil, "incomplete" end
            if s:byte(i) == 125 then break end
            if s:byte(i) == 44 then i = i + 1; i = skip_ws(s, i, n) end
            local key, after, kr = scan_string(s, i, n)
            if not key then return nil, "incomplete" end
            i = skip_ws(s, after, n)
            if s:byte(i) ~= 58 then return nil, "bad_object" end
            i = skip_ws(s, i + 1, n)
            local after_val = skip_value(s, i, n, true)
            if not after_val then return nil, "incomplete" end
            if key == state.compiled.unwrap_key then
                key_found = s:sub(i, after_val - 1)
            end
            i = after_val
        end
        if not key_found then
            key_found = "null"
        end
        local inner_prog = {}
        for k, v in pairs(program or {}) do inner_prog[k] = v end
        inner_prog.unwrapKey = nil
        inner_prog.ops = {}
        if type(program.ops) == "table" then
            for _, op in ipairs(program.ops) do
                if type(op) == "table" and op.op ~= "unwrap" then
                    inner_prog.ops[#inner_prog.ops + 1] = op
                end
            end
        end
        local inner_out, err = _M.apply(key_found, inner_prog)
        if not inner_out then
            if err == "fail_closed" then return nil, err end
            inner_out = key_found
        end
        if state.compiled.wrap_key then
            return "{" .. encode_key(state.compiled.wrap_key) .. ":" .. inner_out .. "}"
        end
        return inner_out
    end
    local _, err = run(state, true)
    if err then
        if err == "fail_closed" then return nil, err end
        return nil, err
    end
    if state.fail_closed then return nil, "fail_closed" end
    return table.concat(state.out)
end

function _M.feed(state, chunk, eof)
    state = state or {}
    ensure(state)
    state.buf = (state.buf or "") .. (chunk or "")
    -- Conditional predicates cannot be streamed (splice merges both branches);
    -- spill to DOM before any bytes are emitted.
    if state.compiled.has_conditional then
        return state, "conditional"
    end
    -- Unwrap: extract at EOF so inner bytes stay verbatim (deferred frame).
    if state.compiled.unwrap_key then
        state.must_hold = true
        if not eof then
            return state, nil
        end
        local out, err = _M.apply(state.buf or "", state.program)
        if not out then
            state.fail_closed = (err == "fail_closed")
            return state, err or "fail_closed"
        end
        state.out = { out }
        state.done = true
        return state, nil
    end
    local _, err = run(state, eof)
    if err then
        refresh_hold(state)
        return state, err
    end
    if eof then state.done = true end
    refresh_hold(state)
    return state, nil
end

function _M.drain(state)
    if not state or state.fail_closed then return nil end
    if state.must_hold and not state.done then return nil end
    local from = state.drain_from or 1
    local n = #(state.out or {})
    if from > n then return nil end
    local parts = {}
    for i = from, n do parts[#parts + 1] = state.out[i] end
    state.drain_from = n + 1
    local s = table.concat(parts)
    if s ~= "" then
        state.flushed = true
        compact(state)
    end
    return s
end

function _M.output(state)
    if not state then return "" end
    if state.fail_closed then return state.buf or "" end
    return table.concat(state.out or {})
end

function _M.apply_chunked(body, program, chunks)
    if type(chunks) ~= "table" or #chunks == 0 then
        return _M.apply(body, program)
    end
    local state = { program = program }
    for i, ch in ipairs(chunks) do
        local _, err = _M.feed(state, ch, i == #chunks)
        if err then
            if err == "fail_closed" then return nil, err end
            return nil, err
        end
    end
    if state.fail_closed then return nil, "fail_closed" end
    return _M.output(state)
end

_M.WINDOW_CAP = WINDOW_CAP
_M.compile = compile

return _M
