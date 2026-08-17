-- streaming_transform.lua — Flat top-level JSON transform for streamable programs.
-- Mirrors Java StreamingJsonTransformer: renames / removals / coercions / defaults
-- on top-level object fields. Nested structures are re-encoded as-is.
-- Called from body_filter when program.streamable == true.

local cjson = require("cjson.safe")

local _M = {}

local function coerce_scalar(val, to_type)
    if to_type == nil or val == nil then return val end
    to_type = string.lower(tostring(to_type))
    if to_type == "string" then return tostring(val) end
    if to_type == "number" or to_type == "integer" then
        return tonumber(val) or val
    end
    if to_type == "boolean" then
        if val == true or val == false then return val end
        local s = string.lower(tostring(val))
        if s == "true" or s == "1" then return true end
        if s == "false" or s == "0" then return false end
    end
    return val
end

local function removal_set(removals)
    local set = {}
    if type(removals) == "table" then
        for _, r in ipairs(removals) do
            set[tostring(r)] = true
        end
        -- also support map form
        for k, v in pairs(removals) do
            if type(k) == "string" and v == true then set[k] = true end
        end
    end
    return set
end

--- Apply flat streamable program to a decoded top-level object table.
--- Returns transformed table, or nil if input is not a top-level object.
function _M.apply_flat(obj, program)
    if type(obj) ~= "table" or type(program) ~= "table" then
        return nil
    end
    -- Arrays are not streamable flat path
    if #obj > 0 and next(obj, #obj) == nil then
        return nil
    end

    local renames = program.renames or {}
    local defaults = program.defaults or {}
    local coercions = program.coercions or {}
    local removals = removal_set(program.removals)

    local out = {}
    local seen = {}

    for k, v in pairs(obj) do
        local key = tostring(k)
        if not removals[key] then
            local out_name = renames[key] or key
            seen[key] = true
            seen[out_name] = true
            local coerce_to = coercions[out_name] or coercions[key]
            if coerce_to and (type(v) ~= "table") then
                out[out_name] = coerce_scalar(v, coerce_to)
            else
                out[out_name] = v
            end
        end
    end

    for k, v in pairs(defaults) do
        if not seen[tostring(k)] then
            out[k] = v
        end
    end

    return out
end

--- True when program is eligible for the flat streaming path (no nested ops).
function _M.is_flat_eligible(program)
    if type(program) ~= "table" or not program.streamable then
        return false
    end
    if program.wrapKey or program.unwrapKey then return false end
    if program.moves and type(program.moves) == "table" and #program.moves > 0 then return false end
    if program.scales and type(program.scales) == "table" and #program.scales > 0 then return false end
    if program.coalesce and type(program.coalesce) == "table" and #program.coalesce > 0 then return false end
    if program.valueMaps and type(program.valueMaps) == "table" and next(program.valueMaps) then return false end
    if program.dateFormats and type(program.dateFormats) == "table" and next(program.dateFormats) then return false end
    if program.stripUnknown and type(program.stripUnknown) == "table" and next(program.stripUnknown) then return false end
    if program.ops and type(program.ops) == "table" and #program.ops > 0 then return false end
    return true
end

--- Encode helper
function _M.encode(obj)
    return cjson.encode(obj)
end

return _M
