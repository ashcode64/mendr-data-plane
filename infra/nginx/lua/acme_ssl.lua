-- acme_ssl.lua — In-edge Let's Encrypt (HTTP-01) via lua-resty-acme autossl.
-- Hostname isolation: only MENDR_ACME_DOMAINS are allowlisted for issuance.
-- Init failures are retryable (Redis may not be ready at init_by_lua).

local config = require("config")

local _M = {}
local initialized = false
local last_err = nil

function _M.init()
    if initialized then
        return true
    end
    if not config.acme_enabled() then
        last_err = "acme disabled"
        return false
    end

    local email = config.acme_email()
    if email == "" then
        last_err = "MENDR_ACME_EMAIL required when MENDR_ACME_ENABLED=true"
        ngx.log(ngx.ERR, "acme_ssl: ", last_err)
        return false
    end

    local ok_acme, autossl = pcall(require, "resty.acme.autossl")
    if not ok_acme or not autossl then
        last_err = "lua-resty-acme missing — install with: opm get fffonion/lua-resty-acme"
        ngx.log(ngx.ERR, "acme_ssl: ", last_err)
        return false
    end

    local domains = config.acme_domains().list
    if #domains == 0 then
        last_err = "MENDR_ACME_DOMAINS required (comma-separated allowlist)"
        ngx.log(ngx.ERR, "acme_ssl: ", last_err)
        return false
    end

    local staging = os.getenv("MENDR_ACME_STAGING")
    staging = staging == "true" or staging == "1"

    local ok, err = pcall(function()
        autossl.init({
            tos_accepted = true,
            staging = staging,
            account_key_path = os.getenv("MENDR_ACME_ACCOUNT_KEY")
                or "/etc/nginx/acme/account.key",
            account_email = email,
            domain_whitelist = domains,
            storage_adapter = "redis",
            storage_config = {
                host = config.redis_host(),
                port = config.redis_port(),
                database = 0,
                namespace = "mendr:acme:",
            },
        })
    end)
    if not ok then
        -- Retryable: do not permanently latch; init_worker / next call may succeed
        -- once Redis (or the ACME API network path) is available.
        last_err = tostring(err)
        ngx.log(ngx.ERR, "acme_ssl: autossl.init failed (will retry): ", last_err)
        return false
    end

    initialized = true
    last_err = nil
    ngx.log(ngx.INFO, "acme_ssl: autossl.init ok domains=", table.concat(domains, ","),
        staging and " (staging)" or "")
    return true
end

function _M.init_worker()
    if not config.acme_enabled() then
        return
    end
    if not _M.init() then
        -- Schedule retries while Redis/network comes up after container start.
        local delay = 5
        local max_attempts = 24  -- ~2 minutes
        local attempts = 0
        local function retry(premature)
            if premature or initialized then
                return
            end
            attempts = attempts + 1
            if _M.init() then
                local ok, autossl = pcall(require, "resty.acme.autossl")
                if ok and autossl and autossl.init_worker then
                    pcall(autossl.init_worker)
                end
                return
            end
            if attempts < max_attempts then
                ngx.timer.at(delay, retry)
            else
                ngx.log(ngx.ERR, "acme_ssl: gave up after ", attempts, " init attempts: ",
                    tostring(last_err))
            end
        end
        ngx.timer.at(delay, retry)
        return
    end
    local ok, autossl = pcall(require, "resty.acme.autossl")
    if ok and autossl and autossl.init_worker then
        pcall(autossl.init_worker)
    end
end

function _M.ssl_certificate()
    if not initialized then
        -- Best-effort late init on first TLS handshake if earlier retries pending.
        _M.init()
    end
    if not initialized then
        return
    end
    local host = ngx.ssl and ngx.ssl.server_name and ngx.ssl.server_name() or nil
    if host and not config.acme_domain_allowed(host) then
        ngx.log(ngx.WARN, "acme_ssl: SNI host not allowlisted: ", host)
        return
    end
    local ok, autossl = pcall(require, "resty.acme.autossl")
    if ok and autossl then
        autossl.ssl_certificate()
    end
end

function _M.serve_http_challenge()
    if not initialized then
        _M.init()
    end
    if not initialized then
        ngx.status = 503
        ngx.say("acme not ready")
        return ngx.exit(503)
    end
    local ok, autossl = pcall(require, "resty.acme.autossl")
    if ok and autossl then
        autossl.serve_http_challenge()
    else
        ngx.status = 503
        ngx.say("acme library unavailable")
        return ngx.exit(503)
    end
end

function _M.status()
    return {
        enabled = config.acme_enabled(),
        ready = initialized,
        error = last_err,
        domains = config.acme_domains().list,
    }
end

return _M
