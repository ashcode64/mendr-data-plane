-- plan_class.lua — Edge re-derivation of compile-time planClass (defense in depth).
-- Rank: PASSTHROUGH < PREFILTERABLE < FORWARD_ONLY < BOUNDED_WINDOW < UNBOUNDED

local _M = {}

local RANK = {
    PASSTHROUGH = 0,
    PREFILTERABLE = 1,
    FORWARD_ONLY = 2,
    BOUNDED_WINDOW = 3,
    UNBOUNDED = 4,
}

local function last_segment(pointer)
    if type(pointer) ~= "string" or pointer == "" or pointer == "/" then
        return nil
    end
    local seg = pointer:match("/([^/]*)$") or pointer
    seg = seg:gsub("~1", "/"):gsub("~0", "~")
    if seg == "" then return nil end
    return seg
end

local function parent_of(pointer)
    if type(pointer) ~= "string" or pointer == "" or pointer == "/" then
        return ""
    end
    local parent = pointer:match("^(.*)/[^/]*$")
    return parent or ""
end

local function depth_of(pointer)
    if type(pointer) ~= "string" or pointer == "" or pointer == "/" then
        return 0
    end
    local n = 0
    for _ in pointer:gmatch("/") do n = n + 1 end
    return n
end

local function bump(state, class)
    local r = RANK[class] or RANK.UNBOUNDED
    if r > state.rank then
        state.rank = r
        state.class = class
    end
end

local function add_ptr(state, pointer)
    if type(pointer) ~= "string" or pointer == "" then return end
    if not state.seen_ptr[pointer] then
        state.seen_ptr[pointer] = true
        state.writePointers[#state.writePointers + 1] = pointer
    end
    local d = depth_of(pointer)
    if d > state.maxDepth then state.maxDepth = d end
    local lit = last_segment(pointer)
    if lit and not state.seen_lit[lit] then
        state.seen_lit[lit] = true
        state.prefilterLiterals[#state.prefilterLiterals + 1] = lit
    end
end

local function consider_op(state, op)
    if type(op) ~= "table" then return end
    local kind = op.op
    if kind == "conditional" then
        -- Union of branch classes (worst case). The predicate path is a read.
        if type(op.predicate) == "table" then
            add_ptr(state, op.predicate.path)
        end
        if type(op["then"]) == "table" then
            for _, c in ipairs(op["then"]) do consider_op(state, c) end
        end
        if type(op.otherwise) == "table" then
            for _, c in ipairs(op.otherwise) do consider_op(state, c) end
        end
        return
    end
    if kind == "move" or kind == "copy" then
        add_ptr(state, op.from)
        add_ptr(state, op.to)
        -- Same-parent move/copy is BOUNDED_WINDOW; the edge spills to DOM if
        -- the parent object's byte span exceeds splice.WINDOW_CAP.
        if parent_of(op.from) == parent_of(op.to) then
            bump(state, "BOUNDED_WINDOW")
        else
            bump(state, "UNBOUNDED")
        end
        state.prefilterable = false
        return
    end
    if kind == "wrap" or kind == "unwrap" then
        bump(state, "FORWARD_ONLY")
        state.prefilterable = false
        return
    end
    if kind == "strip_unknown" then
        bump(state, "FORWARD_ONLY")
        state.prefilterable = false
        add_ptr(state, op.path or "/")
        return
    end
    if kind == "default" then
        add_ptr(state, op.path)
        bump(state, "FORWARD_ONLY")
        local on = tostring(op.on or "ABSENT"):upper()
        if on ~= "NULL" then
            state.prefilterable = false
        end
        return
    end
    -- leaf / same-object structural
    if kind == "rename" then
        add_ptr(state, op.from)
        add_ptr(state, op.to)
        bump(state, "FORWARD_ONLY")
        return
    end
    if kind == "remove" or kind == "coerce" or kind == "scale" or kind == "arith"
        or kind == "map_value" or kind == "reformat_date" or kind == "string"
        or kind == "coalesce" or kind == "wrap_array" or kind == "unwrap_array" then
        add_ptr(state, op.path or op.from)
        bump(state, "FORWARD_ONLY")
        return
    end
    if kind then
        bump(state, "UNBOUNDED")
        state.prefilterable = false
    end
end

local function consider_program_buckets(state, program)
    if type(program.wrapKey) == "string" or type(program.unwrapKey) == "string" then
        bump(state, "FORWARD_ONLY")
        state.prefilterable = false
    end
    if type(program.moves) == "table" and #program.moves > 0 then
        state.prefilterable = false
        for _, mv in ipairs(program.moves) do
            if mv then
                add_ptr(state, mv.from)
                add_ptr(state, mv.to)
                if parent_of(mv.from) == parent_of(mv.to) then
                    bump(state, "BOUNDED_WINDOW")
                else
                    bump(state, "UNBOUNDED")
                end
            end
        end
    end
    local function path_list(lst, prefilterable)
        if type(lst) ~= "table" then return end
        for _, e in ipairs(lst) do
            if e and e.path then
                add_ptr(state, e.path)
                bump(state, "FORWARD_ONLY")
                if prefilterable == false then state.prefilterable = false end
            end
        end
    end
    path_list(program.scales, true)
    path_list(program.coalesce, true)
    path_list(program.valueMaps, true)
    path_list(program.dateFormats, true)
    path_list(program.stripUnknown, false)
    path_list(program.wrapArrays, true)
    path_list(program.unwrapArrays, true)
    if type(program.renames) == "table" then
        for from, to in pairs(program.renames) do
            add_ptr(state, "/" .. tostring(from))
            add_ptr(state, "/" .. tostring(to))
            bump(state, "FORWARD_ONLY")
        end
    end
    if type(program.coercions) == "table" then
        for k in pairs(program.coercions) do
            add_ptr(state, "/" .. tostring(k))
            bump(state, "FORWARD_ONLY")
        end
    end
    if type(program.removals) == "table" then
        for _, k in ipairs(program.removals) do
            add_ptr(state, "/" .. tostring(k))
            bump(state, "FORWARD_ONLY")
        end
    end
    if type(program.defaults) == "table" and next(program.defaults) then
        for k in pairs(program.defaults) do
            add_ptr(state, "/" .. tostring(k))
        end
        bump(state, "FORWARD_ONLY")
        state.prefilterable = false
    end
end

function _M.classify(program)
    if type(program) ~= "table" or program.empty then
        return {
            planClass = "PASSTHROUGH",
            prefilterLiterals = {},
            writePointers = {},
            maxWindowDepth = "0",
            prefilterable = false,
        }
    end
    local state = {
        rank = 0,
        class = "PASSTHROUGH",
        prefilterable = true,
        prefilterLiterals = {},
        writePointers = {},
        seen_lit = {},
        seen_ptr = {},
        maxDepth = 0,
    }
    if type(program.ops) == "table" then
        for _, op in ipairs(program.ops) do
            consider_op(state, op)
        end
    end
    consider_program_buckets(state, program)

    local planClass = state.class
    if state.rank == RANK.FORWARD_ONLY and state.prefilterable
        and #state.prefilterLiterals > 0 then
        planClass = "PREFILTERABLE"
    end
    if state.rank == 0 then
        planClass = "PASSTHROUGH"
        state.prefilterable = false
    end
    return {
        planClass = planClass,
        prefilterLiterals = state.prefilterLiterals,
        writePointers = state.writePointers,
        maxWindowDepth = (planClass == "UNBOUNDED") and "UNBOUNDED" or tostring(state.maxDepth),
        prefilterable = planClass == "PREFILTERABLE",
    }
end

-- Always re-derive. The control-plane planClass is a hint, not authority.
function _M.resolve(program)
    return _M.classify(program)
end

return _M
