-- pii_redact.lua — Scrub PII from failure/telemetry payloads (not only AI prompts).

local _M = {}

local PATTERNS = {
    { re = [[\b\d{3}-\d{2}-\d{4}\b]], repl = "[REDACTED-SSN]" },
    { re = [[\b(?:\d[ -]*?){13,19}\b]], repl = "[REDACTED-CARD]" },
    { re = [[[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}]], repl = "[REDACTED-EMAIL]" },
    { re = [[(?i)(password|passwd|secret|api[_-]?key|token|authorization)\s*[:=]\s*["']?[^\s,"']+]],
      repl = "%1=[REDACTED]" },
    { re = [[Bearer\s+[A-Za-z0-9\-._~+/]+=*]], repl = "Bearer [REDACTED]" },
}

local function redact_string(s)
    if type(s) ~= "string" or s == "" then return s end
    local out = s
    for _, p in ipairs(PATTERNS) do
        out = ngx.re.gsub(out, p.re, p.repl, "jo") or out
    end
    return out
end

local function redact_any(v, depth)
    depth = depth or 0
    if depth > 8 then return v end
    if type(v) == "string" then
        return redact_string(v)
    elseif type(v) == "table" then
        local out = {}
        for k, val in pairs(v) do
            local key = type(k) == "string" and k:lower() or k
            if type(key) == "string" and (key:find("password", 1, true) or key:find("secret", 1, true)
                or key:find("token", 1, true) or key:find("authorization", 1, true)
                or key:find("apikey", 1, true) or key:find("api_key", 1, true)) then
                out[k] = "[REDACTED]"
            else
                out[k] = redact_any(val, depth + 1)
            end
        end
        return out
    end
    return v
end

function _M.scrub(payload)
    if os.getenv("MENDR_PII_REDACT") == "false" then
        return payload
    end
    return redact_any(payload, 0)
end

return _M
