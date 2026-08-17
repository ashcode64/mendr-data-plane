-- metrics.lua — Lightweight Prometheus text exposition from shared dict counters.

local _M = {}

local dict = ngx.shared.mendr_metrics

function _M.inc(name, labels, n)
    if not dict then return end
    n = n or 1
    local key = name
    if type(labels) == "table" then
        local parts = {}
        for k, v in pairs(labels) do
            -- Prometheus requires quoted label values
            local sv = tostring(v):gsub("\\", "\\\\"):gsub('"', '\\"'):gsub("\n", "\\n")
            parts[#parts + 1] = k .. '="' .. sv .. '"'
        end
        table.sort(parts)
        key = name .. "{" .. table.concat(parts, ",") .. "}"
    end
    dict:incr(key, n, 0)
end

function _M.observe_latency(ms, labels)
    -- coarse histogram buckets
    local bucket = "le_inf"
    if ms <= 5 then bucket = "le_5"
    elseif ms <= 25 then bucket = "le_25"
    elseif ms <= 100 then bucket = "le_100"
    elseif ms <= 500 then bucket = "le_500"
    elseif ms <= 2000 then bucket = "le_2000"
    end
    local lbl = labels or {}
    lbl.le = bucket
    _M.inc("mendr_request_latency_bucket", lbl, 1)
    _M.inc("mendr_request_latency_count", labels, 1)
    _M.inc("mendr_request_latency_sum", labels, math.floor(ms))
end

function _M.render_prometheus()
    if not dict then
        return "# no metrics dict\n"
    end
    local keys = dict:get_keys(0)
    local lines = {
        "# HELP mendr_edge_requests_total Total edge requests",
        "# TYPE mendr_edge_requests_total counter",
    }
    for _, k in ipairs(keys or {}) do
        local v = dict:get(k)
        if v then
            -- keys already encode label sets as name{a=b,c=d}
            if k:find("{", 1, true) then
                local name, rest = k:match("^([^{]+)(.+)$")
                lines[#lines + 1] = string.format("%s%s %s", name, rest, tostring(v))
            else
                lines[#lines + 1] = string.format("%s %s", k, tostring(v))
            end
        end
    end
    return table.concat(lines, "\n") .. "\n"
end

return _M
