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

return _M
