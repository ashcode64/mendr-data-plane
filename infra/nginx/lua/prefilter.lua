-- prefilter.lua — Sound key-literal presence check (no false negatives).
-- Only object keys are scanned. A `\` inside a string value does not disable
-- skip. A `\` in a key is unescaped and compared; if the tokenizer cannot
-- finish, the verdict is "escape" (do not skip).

local _M = {}

local HEX = {
    ["0"]=0,["1"]=1,["2"]=2,["3"]=3,["4"]=4,["5"]=5,["6"]=6,["7"]=7,["8"]=8,["9"]=9,
    a=10,b=11,c=12,d=13,e=14,f=15,A=10,B=11,C=12,D=13,E=14,F=15,
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
                local h1 = inner:sub(i+2, i+2)
                local h2 = inner:sub(i+3, i+3)
                local h3 = inner:sub(i+4, i+4)
                local h4 = inner:sub(i+5, i+5)
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
    local escaped = false
    while j <= n do
        local c = s:byte(j)
        if c == 92 then
            escaped = true
            j = j + 2
        elseif c == 34 then
            local inner = s:sub(i + 1, j - 1)
            return unescape_json_key(inner), j + 1, escaped
        else
            j = j + 1
        end
    end
    return nil
end

local function skip_value(s, i, n)
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
    if s:sub(i, i + 3) == "true" then return i + 4 end
    if s:sub(i, i + 4) == "false" then return i + 5 end
    if s:sub(i, i + 3) == "null" then return i + 4 end
    local j = i
    if s:byte(j) == 45 then j = j + 1 end
    while j <= n do
        local b = s:byte(j)
        if (b >= 48 and b <= 57) or b == 46 or b == 101 or b == 69 or b == 43 or b == 45 then
            j = j + 1
        else
            break
        end
    end
    if j == i then return nil end
    return j
end

local function walk(s, i, n, on_key)
    i = skip_ws(s, i, n)
    if i > n then return nil end
    local c = s:byte(i)
    if c == 123 then
        i = skip_ws(s, i + 1, n)
        if i > n then return nil end
        if s:byte(i) == 125 then return i + 1 end
        while true do
            i = skip_ws(s, i, n)
            if i > n then return nil end
            local key, after, escaped = scan_string(s, i, n)
            if not key then return nil end
            on_key(key, escaped)
            i = skip_ws(s, after, n)
            if i > n or s:byte(i) ~= 58 then return nil end
            i = skip_ws(s, i + 1, n)
            local after_val = walk(s, i, n, on_key)
            if not after_val then return nil end
            i = skip_ws(s, after_val, n)
            if i > n then return nil end
            local b = s:byte(i)
            if b == 44 then
                i = i + 1
            elseif b == 125 then
                return i + 1
            else
                return nil
            end
        end
    elseif c == 91 then
        i = skip_ws(s, i + 1, n)
        if i > n then return nil end
        if s:byte(i) == 93 then return i + 1 end
        while true do
            local after_val = walk(s, i, n, on_key)
            if not after_val then return nil end
            i = skip_ws(s, after_val, n)
            if i > n then return nil end
            local b = s:byte(i)
            if b == 44 then
                i = i + 1
            elseif b == 93 then
                return i + 1
            else
                return nil
            end
        end
    else
        return skip_value(s, i, n)
    end
end

--- Returns:
--   "miss"  — no target key found; skip transform
--   "hit"   — at least one literal is an object key (possibly after unescape)
--   "escape"— tokenizer failed; not sound to skip
function _M.scan(body, literals)
    if type(body) ~= "string" or body == "" then
        return "miss"
    end
    local want = {}
    if type(literals) == "table" then
        for _, lit in ipairs(literals) do
            if type(lit) == "string" and lit ~= "" then want[lit] = true end
        end
    end
    local hit = false
    local saw_escape_key = false
    local after = walk(body, 1, #body, function(key, escaped)
        if escaped then saw_escape_key = true end
        if want[key] then hit = true end
    end)
    if hit then return "hit" end
    if not after then return "escape" end
    if saw_escape_key and next(want) then
        -- Unescape already compared; leftover escape with no match is a miss.
        return "miss"
    end
    return "miss"
end

function _M.should_skip(body, program)
    if type(program) ~= "table" then return false end
    local prefilterable = program.prefilterable == true
        or program.planClass == "PREFILTERABLE"
    if not prefilterable then return false end
    return _M.scan(body, program.prefilterLiterals) == "miss"
end

return _M
