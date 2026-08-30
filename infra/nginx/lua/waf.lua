-- waf.lua — Production edge WAF with OWASP CRS–inspired rule packs.
-- Modes: off | detect | block (MENDR_WAF_MODE or route_config.wafPolicy.mode).
-- Optionally delegates to lua-resty-coraza + CRS when MENDR_WAF_CORAZA=true and lib is present.
-- Always applies built-in high-signal rules (SQLi, XSS, LFI/RFI, RCE, protocol anomalies).

local cjson = require("cjson.safe")
local metrics = require("metrics")

local _M = {}

local function mode()
    local m = os.getenv("MENDR_WAF_MODE")
    if m and m ~= "" then return string.lower(m) end
    return "detect"
end

--- Read a numeric field from wafPolicy. JSON null decodes to cjson.null (userdata),
--- not a Lua table — never index policy without this guard.
local function policy_number(policy, field, default)
    if type(policy) ~= "table" then return default end
    local v = policy[field]
    if v == nil then return default end
    return tonumber(v) or default
end

local function max_body()
    return tonumber(os.getenv("MENDR_WAF_MAX_BODY_BYTES")) or (1024 * 1024) -- 1 MiB inspect
end

-- OWASP CRS–inspired high-confidence patterns (paranoia level 1–2 subset).
local RULES = {
    { id = "942100", name = "SQLi", severity = "CRITICAL",
      re = [=[(?i)(?:union\s+(?:all\s+)?select|select\s+.+\s+from|insert\s+into|drop\s+table|;\s*--|/\*|\*/|xp_cmdshell|information_schema|or\s+1\s*=\s*1|'\s*or\s*'[^']*'\s*=\s*')]=] },
    { id = "941100", name = "XSS", severity = "CRITICAL",
      re = [=[(?i)(?:<script[\s>/]|javascript\s*:|on(?:error|load|click|mouseover)\s*=|document\.cookie|<\s*iframe|<\s*object|<\s*embed|eval\s*\()]=] },
    { id = "930100", name = "LFI", severity = "CRITICAL",
      re = [=[(?i)(?:\.\./|\.\.\\|/etc/passwd|/proc/self|boot\.ini|win\.ini)]=] },
    { id = "931100", name = "RFI", severity = "CRITICAL",
      re = [=[(?i)(?:(?:https?|ftp|php|zlib|data|glob|phar|ssh2|rar|ogg|expect):/{1,2})]=] },
    { id = "932100", name = "RCE", severity = "CRITICAL",
      re = [=[(?i)(?:(?:;|\||`|\$\()\s*(?:cat|wget|curl|bash|sh|python|perl|nc|ncat|powershell)\b|\$\{jndi:)]=] },
    { id = "920100", name = "PROTOCOL", severity = "WARNING",
      re = [=[\x00|\r\n(?:content-length|transfer-encoding|host)\s*:]=] },
    { id = "933100", name = "PHP_INJECTION", severity = "CRITICAL",
      re = [=[(?i)(?:<\?php|php://(?:filter|input)|assert\s*\(|create_function\s*\()]=] },
    { id = "920270", name = "XXE", severity = "CRITICAL",
      re = [=[(?i)(?:<!ENTITY\b|SYSTEM\s+["']|<!DOCTYPE[^>]+\[)]=] },
    { id = "949110", name = "SCANNER", severity = "WARNING",
      re = [=[(?i)(?:nikto|sqlmap|acunetix|nessus|dirbuster|masscan|nmap\s+script)]=] },
}

local function scan_string(value, findings)
    if type(value) ~= "string" or value == "" then return end
    -- Cap inspection length
    local sample = #value > 8192 and value:sub(1, 8192) or value
    for _, rule in ipairs(RULES) do
        if ngx.re.find(sample, rule.re, "jo") then
            findings[#findings + 1] = {
                id = rule.id,
                name = rule.name,
                severity = rule.severity,
            }
        end
    end
end

local function scan_table(t, findings, depth)
    depth = depth or 0
    if depth > 6 or type(t) ~= "table" then return end
    for k, v in pairs(t) do
        scan_string(tostring(k), findings)
        if type(v) == "string" then
            scan_string(v, findings)
        elseif type(v) == "table" then
            scan_table(v, findings, depth + 1)
        end
    end
end

local function geo_blocked(policy)
    local deny = ""
    local allow = ""
    if type(policy) == "table" then
        if type(policy.geoDeny) == "table" then
            deny = table.concat(policy.geoDeny, ",")
        end
        if type(policy.geoAllow) == "table" then
            allow = table.concat(policy.geoAllow, ",")
        end
    end
    if deny == "" then deny = os.getenv("MENDR_GEO_DENY") or "" end
    if allow == "" then allow = os.getenv("MENDR_GEO_ALLOW") or "" end
    local country = ngx.var.geoip2_data_country_code
        or ngx.var.geoip_country_code
        or ngx.req.get_headers()["CF-IPCountry"]
        or ""
    country = string.upper(tostring(country))
    if country == "" then return false end
    if allow ~= "" then
        local ok = false
        for c in allow:gmatch("[^,]+") do
            if string.upper((c:match("^%s*(.-)%s*$")) or "") == country then ok = true break end
        end
        if not ok then return true, "geo_allow" end
    end
    if deny ~= "" then
        for c in deny:gmatch("[^,]+") do
            if string.upper((c:match("^%s*(.-)%s*$")) or "") == country then
                return true, "geo_deny"
            end
        end
    end
    return false
end

--- Parse IPv4 dotted-quad to 32-bit integer (nil if invalid).
local function ipv4_to_int(ip)
    local a, b, c, d = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not a then return nil end
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if not a or not b or not c or not d then return nil end
    if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return a * 16777216 + b * 65536 + c * 256 + d
end

local function band32(x, y)
    local ok_bit, bitlib = pcall(require, "bit")
    if ok_bit and bitlib then
        return bitlib.band(x, y)
    end
    local r, p = 0, 1
    for _ = 1, 32 do
        if (x % 2 == 1) and (y % 2 == 1) then r = r + p end
        x = math.floor(x / 2)
        y = math.floor(y / 2)
        p = p * 2
    end
    return r
end

--- True if `ip` is in `cidr` (exact IPv4 or prefix/len CIDR). No substring tricks.
local function ip_matches(cidr, ip)
    cidr = (cidr:match("^%s*(.-)%s*$")) or ""
    if cidr == "" then return false end
    if cidr == ip then return true end
    local net, bits = cidr:match("^([^/]+)/(%d+)$")
    if not net then return false end
    bits = tonumber(bits)
    if not bits or bits < 0 or bits > 32 then return false end
    local ip_n = ipv4_to_int(ip)
    local net_n = ipv4_to_int(net)
    if not ip_n or not net_n then return false end
    if bits == 0 then return true end
    local mask = 0
    for i = 0, bits - 1 do
        mask = mask + 2 ^ (31 - i)
    end
    return band32(ip_n, mask) == band32(net_n, mask)
end

local function ip_blocked(policy)
    local deny = ""
    local allow = ""
    if type(policy) == "table" then
        if type(policy.ipDeny) == "table" then
            deny = table.concat(policy.ipDeny, ",")
        end
        if type(policy.ipAllow) == "table" then
            allow = table.concat(policy.ipAllow, ",")
        end
    end
    if deny == "" then deny = os.getenv("MENDR_IP_DENY") or "" end
    if allow == "" then allow = os.getenv("MENDR_IP_ALLOW") or "" end
    local ip = ngx.var.remote_addr or ""
    if allow ~= "" then
        local ok = false
        for a in allow:gmatch("[^,]+") do
            if ip_matches(a, ip) then ok = true break end
        end
        if not ok then return true, "ip_allow" end
    end
    if deny ~= "" then
        for a in deny:gmatch("[^,]+") do
            if ip_matches(a, ip) then
                return true, "ip_deny"
            end
        end
    end
    return false
end

--- Inspect request. Returns ok, finding_or_reason
function _M.inspect(route_config, ctx)
    local waf_mode = mode()
    local policy = route_config and route_config.wafPolicy
    if type(policy) == "table" and policy.mode then
        waf_mode = string.lower(tostring(policy.mode))
    end
    if waf_mode == "off" or waf_mode == "disabled" then
        return true
    end

    local blocked, reason = ip_blocked(policy)
    if blocked then
        metrics.inc("mendr_waf_blocks_total", { reason = reason or "ip" }, 1)
        if waf_mode == "block" then
            return false, "IP blocked by policy"
        end
    end

    blocked, reason = geo_blocked(policy)
    if blocked then
        metrics.inc("mendr_waf_blocks_total", { reason = reason or "geo" }, 1)
        if waf_mode == "block" then
            return false, "Geo blocked by policy"
        end
    end

    -- Bot / volumetric detection
    local ok_bot, bot = pcall(require, "bot_detect")
    if ok_bot and bot then
        local bot_ok, bot_err = bot.inspect(route_config)
        if not bot_ok then
            return false, bot_err or "Blocked by bot detection"
        end
    end

    -- Payload size cap
    local cl = tonumber(ngx.var.content_length) or 0
    local max_allowed = policy_number(policy, "maxBodyBytes", 10 * 1024 * 1024)
    if cl > max_allowed then
        metrics.inc("mendr_waf_blocks_total", { reason = "body_size" }, 1)
        if waf_mode == "block" then
            return false, "Request body exceeds maxBodyBytes"
        end
    end

    local findings = {}
    -- URI + query
    scan_string(ngx.var.request_uri or "", findings)
    scan_string(ngx.var.args or "", findings)
    -- Headers (selected)
    local headers = ngx.req.get_headers()
    for _, h in ipairs({ "user-agent", "referer", "cookie", "x-forwarded-for" }) do
        scan_string(tostring(headers[h] or ""), findings)
    end

    -- Body sample
    if ctx and type(ctx.payload) == "table" then
        scan_table(ctx.payload, findings)
    elseif ctx and type(ctx.raw_body) == "string" then
        local sample = ctx.raw_body
        if #sample > max_body() then sample = sample:sub(1, max_body()) end
        scan_string(sample, findings)
    end

    if #findings > 0 then
        ngx.ctx.waf_findings = findings
        metrics.inc("mendr_waf_matches_total", {
            rule = findings[1].id,
            severity = findings[1].severity,
        }, 1)
        ngx.log(ngx.WARN, "waf: matched ", findings[1].id, " ", findings[1].name,
            " mode=", waf_mode)
        if waf_mode == "block" then
            return false, "WAF blocked: " .. findings[1].name .. " (" .. findings[1].id .. ")"
        end
    end

    -- Optional Coraza CRS on the request path
    if os.getenv("MENDR_WAF_CORAZA") == "true" then
        local ok_c, coraza = pcall(require, "resty.coraza")
        if ok_c and coraza and _G.mendr_coraza_waf then
            local tx = coraza.transaction(_G.mendr_coraza_waf)
            if tx then
                pcall(coraza.process_connection, tx, ngx.var.remote_addr, ngx.var.remote_port,
                    ngx.var.server_addr, ngx.var.server_port)
                pcall(coraza.process_uri, tx, ngx.var.request_uri, ngx.req.get_method(), ngx.var.server_protocol)
                local hdrs = ngx.req.get_headers()
                for k, v in pairs(hdrs) do
                    if type(v) == "string" then
                        pcall(coraza.add_request_header, tx, k, v)
                    end
                end
                pcall(coraza.process_request_headers, tx)
                if ctx and type(ctx.raw_body) == "string" and #ctx.raw_body > 0 then
                    pcall(coraza.append_request_body, tx, ctx.raw_body)
                    pcall(coraza.process_request_body, tx)
                end
                local intervened = false
                local ok_int, action = pcall(coraza.intervention, tx)
                if ok_int and action and action.disruptive then
                    intervened = true
                end
                pcall(coraza.free_transaction, tx)
                ngx.ctx.coraza_enabled = true
                if intervened then
                    metrics.inc("mendr_waf_blocks_total", { reason = "coraza" }, 1)
                    if waf_mode == "block" then
                        return false, "WAF blocked by Coraza CRS"
                    end
                end
            end
        end
    end

    return true
end

function _M.init_coraza()
    if os.getenv("MENDR_WAF_CORAZA") ~= "true" then return end
    local ok, coraza = pcall(require, "resty.coraza")
    if not ok or not coraza then
        ngx.log(ngx.WARN, "waf: MENDR_WAF_CORAZA set but resty.coraza unavailable")
        return
    end
    local waf = coraza.create_waf()
    local crs_setup = os.getenv("MENDR_WAF_CRS_SETUP") or "/etc/nginx/waf/crs-setup.conf"
    local crs_rules = os.getenv("MENDR_WAF_CRS_RULES") or "/etc/nginx/waf/rules"
    local conf = os.getenv("MENDR_WAF_CORAZA_CONF") or "/etc/nginx/waf/coraza.conf"
    pcall(coraza.rules_add_file, waf, conf)
    pcall(coraza.rules_add, waf, "Include " .. crs_setup)
    pcall(coraza.rules_add, waf, "Include " .. crs_rules .. "/*.conf")
    _G.mendr_coraza_waf = waf
    ngx.log(ngx.INFO, "waf: Coraza CRS initialized")
end

return _M
