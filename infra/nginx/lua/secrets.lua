-- secrets.lua — Secrets manager adapter (Vault / AWS SM / GCP SM / env fallback).
-- Used by auth_jwt / AI providers for client secrets without baking into snapshots.

local http = require("resty.http")
local cjson = require("cjson.safe")

local _M = {}
local cache = ngx.shared.mendr_jwks  -- reuse small dict for secret TTL cache

local function env_get(name)
    local v = os.getenv(name)
    if v and v ~= "" then return v end
    return nil
end

local function cache_get(key)
    if not cache then return nil end
    return cache:get("sec:" .. key)
end

local function cache_set(key, val, ttl)
    if cache and val then cache:set("sec:" .. key, val, ttl or 300) end
end

local function from_vault(path)
    local addr = env_get("VAULT_ADDR") or env_get("MENDR_VAULT_ADDR")
    local token = env_get("VAULT_TOKEN") or env_get("MENDR_VAULT_TOKEN")
    if not addr or not token or not path then return nil, "vault not configured" end
    local cached = cache_get("vault:" .. path)
    if cached then return cached end
    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(addr:gsub("/$", "") .. "/v1/" .. path:gsub("^/", ""), {
        method = "GET",
        headers = { ["X-Vault-Token"] = token },
        ssl_verify = true,
    })
    if not res then return nil, err end
    if res.status ~= 200 then return nil, "vault status " .. res.status end
    local body = cjson.decode(res.body or "")
    local data = body and body.data
    if type(data) == "table" and data.data then data = data.data end  -- KV v2
    local secret = data and (data.value or data.secret or data.password)
    if type(secret) == "string" then
        cache_set("vault:" .. path, secret, 300)
        return secret
    end
    return nil, "vault secret shape unsupported"
end

local function from_aws(secret_id)
    -- Prefer AWS Secrets Manager via sidecar HTTP (MENDR_AWS_SM_PROXY) — no AWS SDK in Lua
    local proxy = env_get("MENDR_AWS_SM_PROXY")
    if not proxy or not secret_id then return nil, "aws sm proxy not configured" end
    local cached = cache_get("aws:" .. secret_id)
    if cached then return cached end
    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(proxy:gsub("/$", "") .. "/secrets/" .. ngx.escape_uri(secret_id), {
        method = "GET",
        headers = { ["Accept"] = "application/json" },
    })
    if not res then return nil, err end
    local body = cjson.decode(res.body or "")
    local secret = body and (body.SecretString or body.value or body.secret)
    if type(secret) == "string" then
        cache_set("aws:" .. secret_id, secret, 300)
        return secret
    end
    return nil, "aws secret missing"
end

local function from_gcp(secret_id)
    local proxy = env_get("MENDR_GCP_SM_PROXY")
    if not proxy or not secret_id then return nil, "gcp sm proxy not configured" end
    local cached = cache_get("gcp:" .. secret_id)
    if cached then return cached end
    local httpc = http.new()
    httpc:set_timeout(2000)
    local res, err = httpc:request_uri(proxy:gsub("/$", "") .. "/secrets/" .. ngx.escape_uri(secret_id), {
        method = "GET",
    })
    if not res then return nil, err end
    local body = cjson.decode(res.body or "")
    local secret = body and (body.payload and body.payload.data or body.value or body.secret)
    if type(secret) == "string" then
        cache_set("gcp:" .. secret_id, secret, 300)
        return secret
    end
    return nil, "gcp secret missing"
end

--- Resolve a secret reference: "env:NAME" | "vault:path" | "aws:id" | "gcp:id" | literal
function _M.resolve(ref)
    if not ref or ref == "" then return nil, "empty ref" end
    local scheme, rest = ref:match("^(%w+):(.+)$")
    if not scheme then
        return ref  -- literal
    end
    scheme = scheme:lower()
    if scheme == "env" then
        return env_get(rest)
    elseif scheme == "vault" then
        return from_vault(rest)
    elseif scheme == "aws" then
        return from_aws(rest)
    elseif scheme == "gcp" then
        return from_gcp(rest)
    end
    return nil, "unknown secret scheme: " .. scheme
end

return _M
