-- bot_detect.lua — Volumetric / bot scoring (shared-dict EWMA).
-- Complements signature WAF: flags abusive RPS and 4xx error bursts per IP.

local metrics = require("metrics")

local _M = {}

local dict = ngx.shared.mendr_rate_limit

local function slot_key(prefix, ip)
    local slot = math.floor(ngx.time())
    return prefix .. ":" .. ip .. ":" .. slot
end

--- Inspect request. Returns ok, reason
function _M.inspect(route_config)
    local policy = route_config and route_config.wafPolicy
    local bot_mode = "off"
    if type(policy) == "table" and policy.botMode then
        bot_mode = string.lower(tostring(policy.botMode))
    elseif os.getenv("MENDR_BOT_MODE") then
        bot_mode = string.lower(os.getenv("MENDR_BOT_MODE"))
    end
    if bot_mode == "off" or bot_mode == "disabled" or bot_mode == "" then
        return true
    end

    local ip = ngx.var.remote_addr or "unknown"
    local rps_threshold = tonumber(policy and policy.botRpsThreshold)
        or tonumber(os.getenv("MENDR_BOT_RPS")) or 80
    local err_burst = tonumber(policy and policy.botErrorBurst)
        or tonumber(os.getenv("MENDR_BOT_ERROR_BURST")) or 40

    if not dict then return true end

    local rps_key = slot_key("bot:rps", ip)
    local n = dict:incr(rps_key, 1, 0, 2) or 1
    if n > rps_threshold then
        metrics.inc("mendr_bot_blocks_total", { reason = "rps" }, 1)
        ngx.ctx.bot_score = n
        if bot_mode == "block" then
            return false, "Bot / volumetric rate exceeded"
        end
        ngx.log(ngx.WARN, "bot_detect: RPS ", n, " from ", ip, " (detect)")
    end

    -- Scanner UA heuristic (cheap)
    local ua = string.lower(tostring(ngx.var.http_user_agent or ""))
    if ua:find("sqlmap", 1, true) or ua:find("nikto", 1, true)
            or ua:find("masscan", 1, true) or ua:find("zgrab", 1, true) then
        metrics.inc("mendr_bot_blocks_total", { reason = "scanner_ua" }, 1)
        if bot_mode == "block" then
            return false, "Known scanner user-agent blocked"
        end
    end

    -- Empty UA + high RPS already counted; soft flag
    if ua == "" and n > (rps_threshold / 2) then
        metrics.inc("mendr_bot_blocks_total", { reason = "empty_ua" }, 1)
        if bot_mode == "block" then
            return false, "Suspicious empty User-Agent"
        end
    end

    ngx.ctx.bot_error_burst_threshold = err_burst
    return true
end

--- Record 4xx in log phase for error-burst detection on subsequent requests.
function _M.record_error(status)
    if not dict or not status or status < 400 or status >= 500 then return end
    local ip = ngx.var.remote_addr or "unknown"
    local key = slot_key("bot:err", ip)
    dict:incr(key, 1, 0, 60)
end

return _M
