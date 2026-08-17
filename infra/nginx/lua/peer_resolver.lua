-- peer_resolver.lua — Multi-instance LB for named upstream mendr_dynamic.
-- Access phase: prepare() builds ngx.ctx.balancer_peer_list (canary + primary).
-- Balancer phase: balance() picks peer, applies timeouts, enables retries.
-- Mirror: fire-and-forget duplicate to mirrorInstances (response discarded).

local circuit = require("circuit_breaker")

local _M = {}

local rr_dict = ngx.shared.mendr_lb_rr

local function parse_url(base_url)
    if type(base_url) ~= "string" or base_url == "" then return nil end
    local scheme, host, port = base_url:match("^(https?)://([^:/]+):?(%d*)")
    if not host then return nil end
    port = tonumber(port)
    if not port or port == 0 then
        port = (scheme == "https") and 443 or 80
    end
    local normalized = scheme .. "://" .. host
    if not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)) then
        normalized = normalized .. ":" .. port
    end
    return {
        scheme = scheme,
        host = host,
        port = port,
        base_url = normalized,
    }
end

local function parse_peer(inst)
    if type(inst) ~= "table" or not inst.baseUrl or inst.baseUrl == "" then
        return nil
    end
    local weight = tonumber(inst.weight) or 100
    if weight <= 0 then return nil end
    local status = tostring(inst.healthStatus or "UNKNOWN"):upper()
    if status == "EJECTED" or status == "DOWN" or status == "UNHEALTHY" then
        return nil
    end
    local ok_hc, healthcheck = pcall(require, "healthcheck")
    if ok_hc and healthcheck and not healthcheck.is_healthy(inst.baseUrl) then
        return nil
    end
    local u = parse_url(inst.baseUrl)
    if not u then return nil end
    u.weight = weight
    u.zone = inst.zone
    u.base_url = inst.baseUrl:gsub("/$", "")
    u.health_path = inst.healthPath or inst.health_path
    return u
end

local function healthy_peers(instances, cb_cfg)
    local peers = {}
    local half_open_candidates = {}
    if type(instances) ~= "table" then return peers end
    for _, inst in ipairs(instances) do
        local p = parse_peer(inst)
        if p then
            local open, half_eligible = circuit.is_open(p.base_url, cb_cfg)
            if not open and not half_eligible then
                peers[#peers + 1] = p
            elseif half_eligible then
                half_open_candidates[#half_open_candidates + 1] = p
            end
        end
    end
    if #peers == 0 and #half_open_candidates > 0 then
        for _, p in ipairs(half_open_candidates) do
            if circuit.try_half_open_probe(p.base_url, cb_cfg) then
                peers[#peers + 1] = p
                break
            end
        end
    end
    return peers
end

local function round_robin(peers, key)
    if #peers == 1 then return peers[1] end
    local idx = 0
    if rr_dict then
        idx = rr_dict:incr(key, 1, 0) or 0
    else
        return peers[math.random(1, #peers)]
    end
    return peers[((idx - 1) % #peers) + 1]
end

local function weighted(peers)
    local total = 0
    for _, p in ipairs(peers) do total = total + (p.weight or 100) end
    if total <= 0 then return peers[1] end
    local r = math.random(1, total)
    local acc = 0
    for _, p in ipairs(peers) do
        acc = acc + (p.weight or 100)
        if r <= acc then return p end
    end
    return peers[#peers]
end

local function consistent_hash(peers, hash_key)
    if not hash_key or hash_key == "" then
        return round_robin(peers, "ch_fallback")
    end
    local h = ngx.crc32_short(hash_key)
    return peers[(h % #peers) + 1]
end

local function pick(peers, algo, hash_key, svc)
    if #peers == 0 then return nil end
    algo = tostring(algo or "ROUND_ROBIN"):upper()
    if algo == "WEIGHTED" then return weighted(peers) end
    if algo == "CONSISTENT_HASH" then return consistent_hash(peers, hash_key) end
    return round_robin(peers, "rr:" .. tostring(svc or "svc"))
end

--- Fire-and-forget mirror request (response discarded).
local function schedule_mirror(mirror_peers, method, uri, body, headers)
    if type(mirror_peers) ~= "table" or #mirror_peers == 0 then return end
    local peer = mirror_peers[math.random(1, #mirror_peers)]
    if not peer or not peer.base_url then return end
    local url = peer.base_url .. (uri or "/")
    local ok, err = ngx.timer.at(0, function(premature)
        if premature then return end
        local http = require("resty.http")
        local httpc = http.new()
        httpc:set_timeout(5000)
        local req_headers = {}
        if type(headers) == "table" then
            for k, v in pairs(headers) do
                if type(v) == "string" then req_headers[k] = v end
            end
        end
        req_headers["X-Mendr-Mirror"] = "1"
        local _, merr = httpc:request_uri(url, {
            method = method or "GET",
            body = body,
            headers = req_headers,
            ssl_verify = false,
        })
        if merr then
            ngx.log(ngx.DEBUG, "peer_resolver: mirror failed: ", merr)
        end
    end)
    if not ok then
        ngx.log(ngx.WARN, "peer_resolver: mirror schedule failed: ", err)
    end
end

--- Access-phase: build peer list + decide named-upstream vs absolute URL.
function _M.prepare(route_config, opts)
    opts = opts or {}
    if type(route_config) ~= "table" then return route_config and route_config.targetBaseUrl end

    local traffic = route_config.trafficPolicy or {}
    local cb_cfg = traffic.circuitBreaker
    local instances = route_config.targetInstances
    local peers = healthy_peers(instances, cb_cfg)

    -- Canary split: canaryPercent% of traffic → canaryInstances
    local canary_pct = tonumber(traffic.canaryPercent) or 0
    if canary_pct > 0 and type(traffic.canaryInstances) == "table" then
        local canary = healthy_peers(traffic.canaryInstances, cb_cfg)
        if #canary > 0 and math.random(1, 100) <= math.min(100, canary_pct) then
            peers = canary
            ngx.ctx.canary_routed = true
        end
    end

    -- Shadow mirror (async, response discarded)
    local mirror_pct = tonumber(traffic.mirrorPercent) or 0
    if mirror_pct > 0 and type(traffic.mirrorInstances) == "table"
            and math.random(1, 100) <= math.min(100, mirror_pct) then
        local mirrors = healthy_peers(traffic.mirrorInstances, nil)
        if #mirrors > 0 then
            local method = opts.method or ngx.req.get_method()
            local uri = opts.uri or ngx.var.uri
            local body = opts.body
            if body == nil and method ~= "GET" and method ~= "HEAD" then
                ngx.req.read_body()
                body = ngx.req.get_body_data()
            end
            schedule_mirror(mirrors, method, uri, body, opts.headers or ngx.req.get_headers())
            ngx.ctx.mirror_scheduled = true
        end
    end

    ngx.ctx.trafficPolicy = traffic
    ngx.ctx.cb_cfg = cb_cfg

    local connect_ms = tonumber(traffic.connectTimeoutMs) or 10000
    local read_ms = tonumber(traffic.timeoutMs) or 60000
    local retries = tonumber(traffic.retryCount) or 2
    ngx.ctx.balancer_timeouts = {
        connect = connect_ms / 1000,
        send = read_ms / 1000,
        read = read_ms / 1000,
    }
    ngx.ctx.balancer_retries = math.max(0, retries)

    local pool_configured = type(instances) == "table" and #instances > 0
    local use_named = #peers >= 2
        or (#peers == 1 and pool_configured and #instances > 1)
        or (#peers >= 1 and retries > 0)
        or ngx.ctx.canary_routed == true

    if use_named then
        local ordered = {}
        local first = pick(peers, traffic.loadBalanceAlgorithm, opts.hash_key, route_config.targetService)
        if first then
            ordered[#ordered + 1] = first
            for _, p in ipairs(peers) do
                if p.base_url ~= first.base_url then
                    ordered[#ordered + 1] = p
                end
            end
        else
            ordered = peers
        end
        ngx.ctx.balancer_peer_list = ordered
        ngx.ctx.balancer_peer_index = 0
        ngx.ctx.use_dynamic_balancer = true
        ngx.ctx.selected_peer = ordered[1] and ordered[1].base_url
        return nil
    end

    local base = (#peers == 1 and peers[1].base_url) or route_config.targetBaseUrl
    ngx.ctx.use_dynamic_balancer = false
    ngx.ctx.balancer_peer_list = nil
    ngx.ctx.selected_peer = base
    return base
end

function _M.balance()
    local ok_b, balancer = pcall(require, "ngx.balancer")
    if not ok_b or not balancer then return end

    local peers = ngx.ctx.balancer_peer_list
    if type(peers) ~= "table" or #peers == 0 then
        return
    end

    local timeouts = ngx.ctx.balancer_timeouts
    if timeouts and balancer.set_timeouts then
        pcall(balancer.set_timeouts, timeouts.connect, timeouts.send, timeouts.read)
    end

    local state = ngx.ctx.balancer_state
    if not state then
        state = { tried = {}, idx = 0 }
        ngx.ctx.balancer_state = state
        local retries = ngx.ctx.balancer_retries or 2
        if balancer.set_more_tries and retries > 0 then
            pcall(balancer.set_more_tries, math.min(retries, math.max(0, #peers - 1)))
        end
    else
        local prev = state.current
        if prev and prev.base_url then
            state.tried[prev.base_url] = true
        end
    end

    local chosen
    for i = 1, #peers do
        local idx = ((state.idx + i - 1) % #peers) + 1
        local p = peers[idx]
        if p and not state.tried[p.base_url] then
            chosen = p
            state.idx = idx
            break
        end
    end
    if not chosen then
        chosen = peers[1]
    end
    state.current = chosen
    ngx.ctx.selected_peer = chosen.base_url

    local ok, err = balancer.set_current_peer(chosen.host, chosen.port)
    if not ok then
        ngx.log(ngx.ERR, "peer_resolver: set_current_peer failed: ", err)
    elseif chosen.scheme == "https" and balancer.enable_ssl then
        local ok_ssl, ssl_err = balancer.enable_ssl()
        if not ok_ssl then
            ngx.log(ngx.ERR, "peer_resolver: enable_ssl failed: ", ssl_err)
        end
    end
end

function _M.select(route_config, opts)
    local base = _M.prepare(route_config, opts)
    if base then return base end
    local peers = ngx.ctx.balancer_peer_list
    return peers and peers[1] and peers[1].base_url or (route_config and route_config.targetBaseUrl)
end

_M.parse_url = parse_url

return _M
