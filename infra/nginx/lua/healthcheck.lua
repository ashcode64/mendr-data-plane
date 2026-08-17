-- healthcheck.lua — Active upstream health checks (timer-based).
-- Periodically probes instance healthPath and updates shared dict so peer_resolver
-- can skip DOWN peers even before control-plane ejection syncs.

local http = require("resty.http")
local cjson = require("cjson.safe")
local redis = require("resty.redis")
local config = require("config")

local _M = {}

local dict = ngx.shared.mendr_circuit_breaker
local INTERVAL = tonumber(os.getenv("MENDR_ACTIVE_HC_INTERVAL_SEC")) or 15
local TIMEOUT_MS = tonumber(os.getenv("MENDR_ACTIVE_HC_TIMEOUT_MS")) or 3000

local function redis_connect()
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000)
    local ok, err = red:connect(config.redis_host(), config.redis_port())
    if not ok then return nil, err end
    return red
end

local function set_peer_health(base_url, status)
    if not dict or not base_url then return end
    dict:set("hc:status:" .. base_url, status, INTERVAL * 3)
    dict:set("hc:checked:" .. base_url, ngx.time(), INTERVAL * 3)
end

function _M.get_status(base_url)
    if not dict or not base_url then return "UNKNOWN" end
    return dict:get("hc:status:" .. base_url) or "UNKNOWN"
end

function _M.is_healthy(base_url)
    local s = _M.get_status(base_url)
    -- UNKNOWN means not yet probed — allow traffic
    return s ~= "DOWN" and s ~= "UNHEALTHY"
end

local function probe(base_url, health_path)
    health_path = health_path or "/actuator/health"
    if health_path:sub(1, 1) ~= "/" then health_path = "/" .. health_path end
    local url = base_url:gsub("/$", "") .. health_path
    local httpc = http.new()
    httpc:set_timeout(TIMEOUT_MS)
    local res, err = httpc:request_uri(url, { method = "GET", ssl_verify = false })
    if not res then
        set_peer_health(base_url, "DOWN")
        return false, err
    end
    if res.status >= 200 and res.status < 400 then
        set_peer_health(base_url, "UP")
        return true
    end
    set_peer_health(base_url, "UNHEALTHY")
    return false, "status " .. tostring(res.status)
end

--- Collect unique baseUrls from recent route snapshots in Redis (best-effort sample).
local function collect_targets()
    local targets = {}
    local red = redis_connect()
    if not red then return targets end

    local list = red:get("mendr:health:targets")
    if list and list ~= ngx.null then
        local decoded = cjson.decode(list)
        red:set_keepalive(10000, 50)
        if type(decoded) == "table" then
            return decoded
        end
        return targets
    end

    local cursor = "0"
    local seen = {}
    for _ = 1, 5 do
        local res = red:scan(cursor, "MATCH", "*mendr:routeconfig:*", "COUNT", 50)
        if type(res) ~= "table" then break end
        cursor = tostring(res[1] or "0")
        for _, key in ipairs(res[2] or {}) do
            local val = red:get(key)
            if val and val ~= ngx.null then
                local snap = cjson.decode(val)
                if type(snap) == "table" then
                    local hp = snap.healthEndpoint or "/actuator/health"
                    if type(snap.targetInstances) == "table" then
                        for _, inst in ipairs(snap.targetInstances) do
                            local bu = inst.baseUrl or inst.base_url
                            if bu and not seen[bu] then
                                seen[bu] = true
                                local hp = inst.healthPath or inst.health_path
                                    or snap.healthEndpoint or "/actuator/health"
                                targets[#targets + 1] = { baseUrl = bu, healthPath = hp }
                            end
                        end
                    elseif snap.targetBaseUrl and not seen[snap.targetBaseUrl] then
                        seen[snap.targetBaseUrl] = true
                        targets[#targets + 1] = {
                            baseUrl = snap.targetBaseUrl,
                            healthPath = hp,
                        }
                    end
                end
            end
        end
        if cursor == "0" then break end
    end
    red:set_keepalive(10000, 50)
    return targets
end

local function tick(premature)
    if premature then return end
    if os.getenv("MENDR_ACTIVE_HC") == "false" then
        ngx.timer.at(INTERVAL, tick)
        return
    end
    local targets = collect_targets()
    for _, t in ipairs(targets) do
        local ok, err = probe(t.baseUrl, t.healthPath)
        if not ok then
            ngx.log(ngx.WARN, "healthcheck: ", t.baseUrl, " → DOWN: ", tostring(err))
        end
    end
    local ok, err = ngx.timer.at(INTERVAL, tick)
    if not ok then
        ngx.log(ngx.ERR, "healthcheck: reschedule failed: ", err)
    end
end

function _M.start()
    if ngx.worker.id() ~= 0 then return end
    local ok, err = ngx.timer.at(5, tick)
    if not ok then
        ngx.log(ngx.ERR, "healthcheck: start failed: ", err)
    else
        ngx.log(ngx.INFO, "healthcheck: active probes every ", INTERVAL, "s")
    end
end

return _M
