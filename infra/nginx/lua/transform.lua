-- Shared flat JSON transform primitives (mirrors Java TransformProgram / access.lua).

local _M = {}

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
