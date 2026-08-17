-- auth_jwt.lua — Production edge consumer auth with cryptographic JWKS verify.
-- Priority: lua-resty-openidc bearer_jwt_verify → lua-resty-jwt + JWKS PEM → reject
-- when jwksUri is configured (fail-closed for JWT/OIDC). Claim checks always run.

local cjson = require("cjson.safe")
local http  = require("resty.http")

local _M = {}

local jwks_dict = ngx.shared.mendr_jwks
local JWKS_TTL = 3600  -- 1 hour cache

local function b64url_decode(s)
    if not s then return nil end
    s = s:gsub("-", "+"):gsub("_", "/")
    local pad = #s % 4
    if pad > 0 then s = s .. string.rep("=", 4 - pad) end
    local ok, bin = pcall(ngx.decode_base64, s)
    if ok then return bin end
    return nil
end

local function decode_part(token, idx)
    if type(token) ~= "string" then return nil end
    token = token:gsub("^Bearer%s+", "")
    local parts = {}
    for p in token:gmatch("[^%.]+") do parts[#parts + 1] = p end
    if #parts < idx then return nil end
    local raw = b64url_decode(parts[idx])
    if not raw then return nil end
    return cjson.decode(raw), parts
end

local function has_scope(claims, required)
    if not required or #required == 0 then return true end
    local scope = claims.scope or claims.scp or ""
    local set = {}
    if type(scope) == "table" then
        for _, s in ipairs(scope) do set[tostring(s)] = true end
    else
        for s in tostring(scope):gmatch("%S+") do set[s] = true end
    end
    for _, need in ipairs(required) do
        if not set[tostring(need)] then return false end
    end
    return true
end

local function check_claims(claims, policy)
    if not claims then return false, "Invalid JWT" end
    local now = ngx.time()
    local skew = tonumber(policy.clockSkewSeconds) or 60
    if claims.exp and tonumber(claims.exp) and tonumber(claims.exp) + skew < now then
        return false, "Token expired"
    end
    if claims.nbf and tonumber(claims.nbf) and tonumber(claims.nbf) - skew > now then
        return false, "Token not yet valid"
    end
    if policy.issuer and claims.iss and tostring(claims.iss) ~= tostring(policy.issuer) then
        return false, "Invalid issuer"
    end
    if policy.audience then
        local aud = claims.aud
        local ok_aud = false
        if type(aud) == "table" then
            for _, a in ipairs(aud) do
                if tostring(a) == tostring(policy.audience) then ok_aud = true break end
            end
        else
            ok_aud = tostring(aud or "") == tostring(policy.audience)
        end
        if not ok_aud then
            return false, "Invalid audience"
        end
    end
    if not has_scope(claims, policy.requiredScopes) then
        return false, "Insufficient scope"
    end
    return true
end

--- Fetch JWKS JSON (cached in shared dict).
local function fetch_jwks(uri)
    if not uri or uri == "" then return nil, "missing jwksUri" end
    if jwks_dict then
        local cached = jwks_dict:get("jwks:" .. uri)
        if cached then
            local decoded = cjson.decode(cached)
            if decoded then return decoded end
        end
    end
    local httpc = http.new()
    httpc:set_timeout(5000)
    local res, err = httpc:request_uri(uri, {
        method = "GET",
        ssl_verify = true,
        headers = { ["Accept"] = "application/json" },
    })
    if not res then
        return nil, "JWKS fetch failed: " .. (err or "unknown")
    end
    if res.status ~= 200 then
        return nil, "JWKS HTTP " .. tostring(res.status)
    end
    local body = cjson.decode(res.body)
    if not body or type(body.keys) ~= "table" then
        return nil, "Invalid JWKS body"
    end
    if jwks_dict then
        jwks_dict:set("jwks:" .. uri, res.body, JWKS_TTL)
    end
    return body
end

--- Convert a JWK (RSA) to PEM using lua-resty-openssl when available.
local function jwk_to_pem(jwk)
    if not jwk or jwk.kty ~= "RSA" then return nil end
    local ok_openssl, openssl = pcall(require, "resty.openssl")
    if not ok_openssl then
        -- Fallback: use resty.jwt helpers if present
        local ok_jwt, jwt = pcall(require, "resty.jwt")
        if ok_jwt and jwt and jwt.jwt_load_jwks then
            return nil  -- handled elsewhere
        end
        return nil
    end
    local ok_pkey, pkey = pcall(require, "resty.openssl.pkey")
    if not ok_pkey then return nil end
    local ok, key_or_err = pcall(pkey.new, {
        type = "RSA",
        params = {
            n = jwk.n,
            e = jwk.e,
        },
        is_priv = false,
    })
    if not ok or not key_or_err then return nil end
    local pem = key_or_err:to_PEM("public")
    return pem
end

local function find_jwk(jwks, kid)
    if not jwks or type(jwks.keys) ~= "table" then return nil end
    for _, k in ipairs(jwks.keys) do
        if kid == nil or kid == "" or tostring(k.kid) == tostring(kid) then
            if k.kty == "RSA" and k.n and k.e then
                return k
            end
        end
    end
    -- Fallback: first RSA key
    for _, k in ipairs(jwks.keys) do
        if k.kty == "RSA" and k.n and k.e then return k end
    end
    return nil
end

--- Cryptographic verify using lua-resty-openidc when available (preferred).
local function verify_openidc(token, policy)
    local ok_oidc, openidc = pcall(require, "resty.openidc")
    if not ok_oidc or not openidc then return nil, "openidc unavailable" end
    local opts = {
        discovery = policy.discoveryUrl,
        jwks_uri = policy.jwksUri,
        token_signing_alg_values_expected = policy.algorithms
            or { "RS256", "RS384", "RS512", "ES256", "ES384", "ES512" },
        accept_none_alg = false,
        accept_unsupported_alg = false,
        ssl_verify = "yes",
        iat_slack = tonumber(policy.clockSkewSeconds) or 60,
    }
    if policy.issuer then opts.issuer = policy.issuer end
    -- bearer_jwt_verify reads Authorization by default; set ngx.var if needed
    local res, err = openidc.bearer_jwt_verify(opts, token:gsub("^Bearer%s+", ""))
    if err or not res then
        return nil, err or "JWT signature verification failed"
    end
    return res
end

--- Cryptographic verify via lua-resty-jwt + JWKS PEM.
local function verify_jwt_lib(token, policy)
    local ok_jwt, jwt = pcall(require, "resty.jwt")
    if not ok_jwt or not jwt then
        return nil, "resty.jwt unavailable"
    end
    local header = decode_part(token, 1)
    if not header then return nil, "Invalid JWT header" end
    local alg = tostring(header.alg or "")
    if alg == "" or alg:upper() == "NONE" then
        return nil, "Unsigned tokens rejected"
    end
    if not policy.jwksUri then
        return nil, "jwksUri required for signature verification"
    end
    local jwks, jerr = fetch_jwks(policy.jwksUri)
    if not jwks then return nil, jerr end
    local jwk = find_jwk(jwks, header.kid)
    if not jwk then return nil, "No matching JWK for kid" end

    local pem = jwk_to_pem(jwk)
    if not pem then
        -- Try jwt:verify with jwk table (some forks accept it)
        local ok_v, jwt_obj = pcall(function()
            return jwt:verify(jwk, token:gsub("^Bearer%s+", ""))
        end)
        if ok_v and jwt_obj and jwt_obj.valid then
            return jwt_obj.payload
        end
        return nil, "Unable to materialize PEM from JWK (install lua-resty-openssl)"
    end

    local jwt_obj = jwt:verify(pem, token:gsub("^Bearer%s+", ""))
    if not jwt_obj or not jwt_obj.valid then
        local reason = jwt_obj and jwt_obj.reason or "signature invalid"
        return nil, "JWT verify failed: " .. tostring(reason)
    end
    return jwt_obj.payload
end

--- Returns ok, err_message
function _M.enforce(route_config)
    local policy = route_config and route_config.authPolicy
    if type(policy) ~= "table" then return true end
    local typ = tostring(policy.type or "NONE"):upper()
    if typ == "NONE" or typ == "" then return true end

    if policy.requireHttps then
        local scheme = ngx.var.scheme or "http"
        if scheme ~= "https" then
            return false, "HTTPS required by authPolicy"
        end
    end

    local header_name = policy.headerName or "Authorization"
    local headers = ngx.req.get_headers()
    local raw = headers[header_name] or headers[string.lower(header_name)]

    if typ == "API_KEY" then
        if not raw or raw == "" then
            return false, "Missing API key"
        end
        -- Cryptographic verify against synced ingress key projections (hash compare)
        local ok_id, identity = pcall(require, "identity_resolver")
        if ok_id and identity and identity.resolve_by_api_key then
            local source, tenant, err = identity.resolve_by_api_key(raw)
            if not source then
                return false, err or "Invalid API key"
            end
            ngx.ctx.api_key_source = source
            ngx.ctx.tenant_id = tenant
            -- Optional scope check against authPolicy.requiredScopes vs key scopes
            if type(policy.requiredScopes) == "table" and #policy.requiredScopes > 0 then
                local scopes = ngx.ctx.api_key_scopes
                if type(scopes) ~= "table" then
                    -- resolve_by_api_key may stash scopes on ctx
                    scopes = {}
                end
                for _, need in ipairs(policy.requiredScopes) do
                    local found = false
                    for _, have in ipairs(scopes) do
                        if tostring(have) == tostring(need) then found = true break end
                    end
                    if not found then
                        return false, "API key missing required scope: " .. tostring(need)
                    end
                end
            end
            return true
        end
        -- Fail closed when identity resolver unavailable in production
        if os.getenv("MENDR_API_KEY_FAIL_OPEN") == "true" then
            ngx.log(ngx.WARN, "auth_jwt: API_KEY accepted without hash verify (fail-open)")
            return true
        end
        return false, "API key verification unavailable"
    end

    if typ == "OAUTH_INTROSPECTION" or typ == "INTROSPECTION" then
        if not raw or raw == "" then
            return false, "Missing Bearer token"
        end
        local token = raw:gsub("^Bearer%s+", "")
        local intro_url = policy.introspectionUrl or policy.introspection_url
        if not intro_url or intro_url == "" then
            return false, "authPolicy.introspectionUrl required for OAUTH_INTROSPECTION"
        end
        local http = require("resty.http")
        local httpc = http.new()
        httpc:set_timeout(3000)
        local auth_header = nil
        local client_secret = policy.introspectionClientSecret or policy.introspection_client_secret
        if (not client_secret or client_secret == "") and policy.introspectionClientSecretRef then
            local ok_s, secrets = pcall(require, "secrets")
            if ok_s and secrets then
                client_secret = secrets.resolve(policy.introspectionClientSecretRef)
            end
        end
        if policy.introspectionClientId and client_secret and client_secret ~= "" then
            local cred = ngx.encode_base64(
                policy.introspectionClientId .. ":" .. client_secret)
            auth_header = "Basic " .. cred
        end
        local res, err = httpc:request_uri(intro_url, {
            method = "POST",
            body = "token=" .. ngx.escape_uri(token),
            headers = {
                ["Content-Type"] = "application/x-www-form-urlencoded",
                ["Authorization"] = auth_header,
            },
            ssl_verify = true,
        })
        if not res then
            return false, "Token introspection failed: " .. tostring(err)
        end
        local body = cjson.decode(res.body or "")
        if not body or body.active ~= true then
            return false, "Token inactive or introspection rejected"
        end
        local ok_c, cerr = check_claims(body, policy)
        if not ok_c then return false, cerr end
        ngx.ctx.jwt_claims = body
        return true
    end

    if typ == "MTLS" then
        -- Client cert verified at TLS layer; expose DN for upstream
        local dn = ngx.var.ssl_client_s_dn
        if not dn or dn == "" then
            return false, "Client certificate required (mTLS)"
        end
        if policy.requireClientCertVerify ~= false then
            local verify = ngx.var.ssl_client_verify
            if verify ~= "SUCCESS" then
                return false, "Client certificate verification failed: " .. tostring(verify)
            end
        end
        ngx.ctx.mtls_client_dn = dn
        ngx.req.set_header("X-Client-Cert-DN", dn)
        return true
    end

    if typ == "JWT" or typ == "OIDC" then
        if not raw or raw == "" then
            return false, "Missing Bearer token"
        end

        -- Fail-closed when jwksUri/discovery configured: must cryptographically verify
        local require_crypto = (policy.jwksUri and policy.jwksUri ~= "")
            or (policy.discoveryUrl and policy.discoveryUrl ~= "")
            or policy.requireSignatureVerify == true

        local claims, verr
        if require_crypto then
            claims, verr = verify_openidc(raw, policy)
            if not claims then
                claims, verr = verify_jwt_lib(raw, policy)
            end
            if not claims then
                return false, verr or "JWT signature verification failed"
            end
        else
            claims = decode_part(raw, 2)
            if not claims then
                return false, "Invalid JWT"
            end
            ngx.log(ngx.WARN, "auth_jwt: JWT accepted without cryptographic verify "
                .. "(set authPolicy.jwksUri for production)")
        end

        local ok_c, cerr = check_claims(claims, policy)
        if not ok_c then return false, cerr end

        ngx.ctx.jwt_claims = claims
        if claims.sub then
            ngx.req.set_header("X-Mendr-Subject", tostring(claims.sub))
        end
        return true
    end

    return true
end

--- Invalidate JWKS cache (e.g. after key rotation webhook).
function _M.invalidate_jwks(uri)
    if jwks_dict and uri then
        jwks_dict:delete("jwks:" .. uri)
    end
end

return _M
