-- Shared flat JSON transform primitives (mirrors Java TransformProgram / access.lua).

local _M = {}

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
