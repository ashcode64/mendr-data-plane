-- ai_gateway.lua — AI edge enforcement: TPM/RPM limits, prompt firewall, semantic cache.
-- Routes matched when protocol=AI or path under /v1/chat|/v1/completions|/mendr/ai/.
-- Policies synced into Redis key mendr:ai:route:{virtual_path} or route_config.aiPolicy.

local cjson = require("cjson.safe")
local redis = require("resty.redis")
local config = require("config")
local metrics = require("metrics")

local _M = {}

local rl_dict = ngx.shared.mendr_rate_limit
local cache_dict = ngx.shared.mendr_response_cache

local function redis_connect()
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000)
    local ok, err = red:connect(config.redis_host(), config.redis_port())
    if not ok then return nil, err end
    return red
end

local function load_ai_policy(virtual_path)
    local red, err = redis_connect()
    if not red then return nil end
    local key = "mendr:ai:route:" .. virtual_path
    local val = red:get(key)
    red:set_keepalive(10000, 100)
    if not val or val == ngx.null then return nil end
    return cjson.decode(val)
end

--- Increment a sliding fixed-window counter by `amount` (default 1). Returns ok, current.
local function window_incr(bucket, limit, window, amount)
    if not rl_dict or not limit or limit <= 0 then return true, 0 end
    amount = tonumber(amount) or 1
    if amount < 1 then amount = 1 end
    local slot = math.floor(ngx.time() / window)
    local k = "ai:" .. bucket .. ":" .. slot
    local n = rl_dict:incr(k, amount, 0, window + 1) or amount
    return n <= limit, n
end

--- Estimate tokens from a chat/completions JSON body (chars/4 heuristic + usage if present).
local function estimate_tokens(payload)
    if type(payload) ~= "table" then return 0 end
    if type(payload.usage) == "table" and tonumber(payload.usage.total_tokens) then
        return tonumber(payload.usage.total_tokens)
    end
    local text = ""
    if type(payload.messages) == "table" then
        for _, m in ipairs(payload.messages) do
            if type(m) == "table" and m.content then
                text = text .. tostring(m.content)
            end
        end
    elseif payload.prompt then
        text = tostring(payload.prompt)
    elseif payload.input then
        text = tostring(payload.input)
    end
    return math.max(1, math.ceil(#text / 4))
end

local JAILBREAK = {
    [=[(?i)(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions)]=],
    [=[(?i)(?:you\s+are\s+now\s+(?:dan|jailbroken|unrestricted))]=],
    [=[(?i)(?:do\s+not\s+follow\s+(?:your|the)\s+(?:system|safety)\s+(?:prompt|rules))]=],
    [=[(?i)(?:bypass\s+(?:safety|content)\s+(?:filter|policy))]=],
}

local PII = {
    [=[(\b\d{3}-\d{2}-\d{4}\b)]=],                         -- SSN
    [=[(\b(?:\d[ -]*?){13,19}\b)]=],                       -- card-ish
    [=[([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})]=], -- email
}

local function collect_text(payload)
    local parts = {}
    if type(payload) ~= "table" then return "" end
    if type(payload.messages) == "table" then
        for _, m in ipairs(payload.messages) do
            if type(m) == "table" and m.content then parts[#parts + 1] = tostring(m.content) end
        end
    end
    if payload.prompt then parts[#parts + 1] = tostring(payload.prompt) end
    return table.concat(parts, "\n")
end

local function prompt_firewall(policy, payload)
    local text = collect_text(payload)
    if text == "" then return true end

    if policy.blockJailbreak ~= false then
        for _, re in ipairs(JAILBREAK) do
            if ngx.re.find(text, re, "jo") then
                return false, "Prompt firewall: jailbreak pattern blocked"
            end
        end
    end

    if policy.redactPii then
        local redacted = text
        for _, re in ipairs(PII) do
            redacted = ngx.re.gsub(redacted, re, "[REDACTED]", "jo")
        end
        if redacted ~= text and type(payload.messages) == "table" then
            -- Best-effort: redact last user message content
            for i = #payload.messages, 1, -1 do
                local m = payload.messages[i]
                if type(m) == "table" and tostring(m.role) == "user" and m.content then
                    local c = tostring(m.content)
                    for _, pre in ipairs(PII) do
                        c = ngx.re.gsub(c, pre, "[REDACTED]", "jo")
                    end
                    m.content = c
                    break
                end
            end
            ngx.ctx.ai_pii_redacted = true
        end
    end

    if policy.blockOffTopic and policy.topicAllowlist and type(policy.topicAllowlist) == "table" then
        -- Soft: if allowlist present and none of the terms appear, block
        local ok = false
        local lower = text:lower()
        for _, term in ipairs(policy.topicAllowlist) do
            if lower:find(tostring(term):lower(), 1, true) then ok = true break end
        end
        if not ok and #policy.topicAllowlist > 0 then
            return false, "Prompt firewall: off-topic request blocked"
        end
    end

    return true
end

local function semantic_cache_key(payload)
    local text = collect_text(payload)
    -- Normalize whitespace / case for near-duplicate hits
    text = text:lower():gsub("%s+", " "):gsub("^%s+", ""):gsub("%s+$", "")
    return "ai:sem:" .. ngx.md5(text)
end

function _M.is_ai_request(route_config, ctx)
    if route_config and tostring(route_config.protocol or ""):upper() == "AI" then
        return true
    end
    if route_config and type(route_config.aiPolicy) == "table" then
        return true
    end
    local path = (ctx and ctx.endpoint) or ngx.var.uri or ""
    return path:find("^/v1/chat") or path:find("^/v1/completions")
        or path:find("^/mendr/ai/") or path:find("/chat/completions")
end

--- Returns ok, err_or_cached_response_table
function _M.enforce(route_config, ctx)
    if not _M.is_ai_request(route_config, ctx) then
        return true
    end

    local policy = (route_config and route_config.aiPolicy)
        or load_ai_policy((ctx and ctx.endpoint) or ngx.var.uri or "")
    if type(policy) ~= "table" then
        -- Default safe TPM if AI traffic without explicit policy
        policy = {
            tokensPerMinute = tonumber(os.getenv("MENDR_AI_DEFAULT_TPM")) or 100000,
            requestsPerMinute = tonumber(os.getenv("MENDR_AI_DEFAULT_RPM")) or 60,
            blockJailbreak = true,
            redactPii = true,
            semanticCacheEnabled = os.getenv("MENDR_AI_SEMANTIC_CACHE") == "true",
            semanticCacheTtlSeconds = 300,
        }
    end

    local consumer = ngx.var.remote_addr or "anon"
    local claims = ngx.ctx.jwt_claims
    if claims and claims.sub then consumer = tostring(claims.sub) end

    -- RPM
    local rpm = tonumber(policy.requestsPerMinute) or tonumber(policy.requests_per_minute)
    if rpm and rpm > 0 then
        local ok = window_incr("rpm:" .. consumer, rpm, 60)
        if not ok then
            metrics.inc("mendr_ai_rate_limited_total", { kind = "rpm" }, 1)
            return false, "AI rate limit: requests per minute exceeded"
        end
    end

    local payload = ctx and ctx.payload
    local tokens = estimate_tokens(payload or {})
    ngx.ctx.ai_estimated_tokens = tokens

    -- TPM: increment by estimated token count (not by 1 request)
    local tpm = tonumber(policy.tokensPerMinute) or tonumber(policy.tokens_per_minute)
    if tpm and tpm > 0 then
        local ok = window_incr("tpm:" .. consumer, tpm, 60, tokens)
        if not ok then
            metrics.inc("mendr_ai_rate_limited_total", { kind = "tpm" }, 1)
            return false, "AI rate limit: tokens per minute exceeded"
        end
    end

    local ok_fw, fw_err = prompt_firewall(policy, payload or {})
    if not ok_fw then
        metrics.inc("mendr_ai_firewall_blocks_total", { reason = "prompt" }, 1)
        return false, fw_err
    end

    local sem_on = policy.semanticCacheEnabled or policy.semantic_cache_enabled
    if sem_on and cache_dict and payload then
        local key = semantic_cache_key(payload)
        local hit = cache_dict:get(key)
        if hit then
            local decoded = cjson.decode(hit)
            if decoded then
                metrics.inc("mendr_ai_semantic_cache_hits_total", {}, 1)
                return true, decoded
            end
        end
        ngx.ctx.ai_semantic_cache_key = key
        ngx.ctx.ai_semantic_cache_ttl = tonumber(policy.semanticCacheTtlSeconds
            or policy.semantic_cache_ttl_seconds) or 300
    end

    -- Multi-provider: stash ordered providers for peer_resolver / upstream pick
    local providers = policy.providers or policy.providers_json
    if type(providers) == "string" then providers = cjson.decode(providers) end
    if type(providers) == "table" and #providers > 0 then
        ngx.ctx.ai_providers = providers
        -- Build multi-peer pool so balancer_by_lua + proxy_next_upstream can fail over on 5xx
        local instances = {}
        for _, p in ipairs(providers) do
            if p.baseUrl then
                instances[#instances + 1] = {
                    baseUrl = p.baseUrl,
                    weight = tonumber(p.weight) or 100,
                    healthStatus = "UP",
                    provider = p.provider or p.name,
                }
            end
        end
        if #instances >= 1 and route_config then
            route_config.targetInstances = instances
            -- Prefer weighted algorithm for AI providers
            route_config.trafficPolicy = route_config.trafficPolicy or {}
            if not route_config.trafficPolicy.loadBalanceAlgorithm then
                route_config.trafficPolicy.loadBalanceAlgorithm = "WEIGHTED"
            end
            if not route_config.trafficPolicy.retryCount then
                route_config.trafficPolicy.retryCount = math.min(2, #instances - 1)
            end
        end
        -- Weighted pick for header / logging (balancer may override)
        local total = 0
        for _, p in ipairs(providers) do total = total + (tonumber(p.weight) or 100) end
        local r = math.random(1, math.max(total, 1))
        local acc = 0
        for _, p in ipairs(providers) do
            acc = acc + (tonumber(p.weight) or 100)
            if r <= acc then
                ngx.ctx.ai_selected_provider = p
                if p.baseUrl then
                    ngx.ctx.ai_upstream_base = p.baseUrl
                end
                break
            end
        end
    end

    metrics.inc("mendr_ai_requests_total", {}, 1)
    return true
end

function _M.store_semantic_cache(body, content_type)
    local key = ngx.ctx.ai_semantic_cache_key
    local ttl = ngx.ctx.ai_semantic_cache_ttl or 300
    if not key or not cache_dict or not body then return end
    -- body must be an encoded JSON string (never a Lua table)
    local body_str = body
    if type(body) == "table" then
        body_str = cjson.encode(body)
        if not body_str then return end
    elseif type(body) ~= "string" then
        body_str = tostring(body)
    end
    local entry = cjson.encode({
        status = 200,
        body = body_str,
        content_type = content_type or "application/json",
        semantic = true,
    })
    if entry then
        cache_dict:set(key, entry, ttl)
    end
end

return _M
