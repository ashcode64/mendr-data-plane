-- Shared configuration for Mendr OpenResty data plane (overridable via env).

local _M = {}

function _M.control_plane_base()
    return os.getenv("MENDR_CONTROL_PLANE_URL") or "http://api-gateway:8090"
end

function _M.redis_host()
    return os.getenv("MENDR_REDIS_HOST") or "redis"
end

function _M.redis_port()
    return tonumber(os.getenv("MENDR_REDIS_PORT")) or 6379
end

function _M.java_fallback_enabled()
    local flag = os.getenv("MENDR_JAVA_FALLBACK")
    return flag == nil or flag == "" or flag == "true" or flag == "1"
end

function _M.internal_api_key()
    local key = os.getenv("GATEWAY_INTERNAL_API_KEY")
    if key == nil or key == "" then
        return nil
    end
    return key
end

--- Per-tenant edge API key ("<prefix>.<secret>"), issued by the control plane and
--- mapped to exactly one tenant. Presenting it makes the control plane resolve the
--- tenant server-side and return ONLY that tenant's route snapshots. This is the
--- SaaS multi-tenant edge credential; prefer it over the shared internal key.
function _M.edge_api_key()
    local key = os.getenv("GATEWAY_EDGE_API_KEY")
    if key == nil or key == "" then
        return nil
    end
    return key
end

--- Optional tenant id sent as a defense-in-depth cross-check header. The control
--- plane authoritatively derives the tenant from the API key; this must match.
function _M.tenant_id()
    local id = os.getenv("MENDR_TENANT_ID")
    if id == nil or id == "" then
        return nil
    end
    return id
end

function _M.docker_host_rewrite()
    local rewrite = os.getenv("MENDR_DOCKER_HOST_REWRITE")
    if rewrite == nil or rewrite == "" then
        return nil
    end
    return rewrite
end

--- Interval between forced full resyncs (seconds). 0 disables the backstop.
function _M.full_resync_interval_sec()
    local raw = os.getenv("MENDR_FULL_RESYNC_INTERVAL_SEC")
    if raw == nil or raw == "" then
        return 300
    end
    local n = tonumber(raw)
    if n == nil or n < 0 then
        return 300
    end
    return n
end

--- Sampled edge-observation reporting (TRAFFIC_OBSERVED topology tier). Off by default —
--- when enabled, a sampled/deduped fraction of proxied calls report the observed
--- source->target:endpoint edge (with propagated trace context) to the control plane.
function _M.edge_observation_enabled()
    local flag = os.getenv("MENDR_EDGE_OBSERVATION_ENABLED")
    return flag == "true" or flag == "1"
end

--- Fraction [0,1] of proxied calls that emit an edge observation (after the per-edge
--- dedup window already caps volume). Defaults to 1.0 when unset/invalid.
function _M.edge_observation_sample_rate()
    local raw = os.getenv("MENDR_EDGE_OBSERVATION_SAMPLE_RATE")
    local n = tonumber(raw)
    if n == nil or n < 0 then
        return 1.0
    end
    if n > 1 then
        return 1.0
    end
    return n
end

--- Transparent HTTP ingress (OpenAPI base-URL swap). Off by default.
function _M.ingress_enabled()
    local flag = os.getenv("MENDR_INGRESS_ENABLED")
    return flag == "true" or flag == "1"
end

--- When true and X-Mendr-Key is absent, resolve identity from Host via
--- mendr:hostident:{host} (Phase 6). Default on when ingress is enabled.
function _M.host_identity_fallback_enabled()
    local flag = os.getenv("MENDR_HOST_IDENTITY_FALLBACK")
    if flag == "false" or flag == "0" then
        return false
    end
    if flag == "true" or flag == "1" then
        return true
    end
    return _M.ingress_enabled()
end

--- Reject non-HTTPS ingress traffic (except ACME HTTP-01). Off by default so
--- local docker/dev on :8080 still works; enable on public edges with ACME.
function _M.tls_required()
    local flag = os.getenv("MENDR_TLS_REQUIRED")
    return flag == "true" or flag == "1"
end

--- In-edge ACME (Let's Encrypt) via lua-resty-acme. Requires public DNS CNAME
--- to this edge and ports 80/443.
function _M.acme_enabled()
    local flag = os.getenv("MENDR_ACME_ENABLED")
    return flag == "true" or flag == "1"
end

function _M.acme_email()
    return os.getenv("MENDR_ACME_EMAIL") or ""
end

--- Comma-separated domains this edge may issue certs for (hostname isolation).
--- Returns list + set: domains.list = { "a.com", ... }, domains.set["a.com"] = true
function _M.acme_domains()
    local raw = os.getenv("MENDR_ACME_DOMAINS") or ""
    local list, set = {}, {}
    for part in string.gmatch(raw, "[^,]+") do
        local d = string.lower((part:match("^%s*(.-)%s*$")) or "")
        if d ~= "" and not set[d] then
            set[d] = true
            table.insert(list, d)
        end
    end
    return { list = list, set = set }
end

function _M.acme_domain_allowed(host)
    if not host or host == "" then return false end
    host = string.lower(host)
    local domains = _M.acme_domains()
    return domains.set[host] == true
end

--- Undeclared-route edge mode when the radixtree is built but path/method miss.
--- observe|shadow|learning → log SHADOW_ROUTE_ACCESSED then 404;
--- strict|enforcing → hard 404 without shadow metric.
function _M.ingress_undeclared_enforce()
    local mode = os.getenv("MENDR_INGRESS_UNDECLARED_ENFORCE")
    if mode == nil or mode == "" then
        return "observe"
    end
    return string.lower(mode)
end

--- Rewrite localhost / 127.0.0.1 so OpenResty inside Docker can reach host-run services.
function _M.rewrite_localhost(url)
    if url == nil or url == "" then
        return url
    end
    local rewrite = _M.docker_host_rewrite()
    if rewrite == nil then
        return url
    end
    url = url:gsub("://localhost:", "://" .. rewrite .. ":")
    url = url:gsub("://127%.0%.0%.1:", "://" .. rewrite .. ":")
    return url
end

function _M.waf_mode()
    return string.lower(os.getenv("MENDR_WAF_MODE") or "detect")
end

function _M.otel_enabled()
    local flag = os.getenv("MENDR_OTEL_ENABLED")
    return flag == "true" or flag == "1"
end

function _M.mtls_enabled()
    local flag = os.getenv("MENDR_MTLS_ENABLED")
    return flag == "true" or flag == "1"
end

return _M
