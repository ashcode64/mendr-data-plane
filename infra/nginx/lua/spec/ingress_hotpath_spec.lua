-- Functional specs for body / fallthrough / identity (Phase 6 + PATCH_3 body rules).
--   cd infra/nginx/lua && lua spec/ingress_hotpath_spec.lua

package.path = package.path .. ";../?.lua;./?.lua"

local failures = 0
local function check(name, cond)
    if cond then
        print("ok   - " .. name)
    else
        failures = failures + 1
        print("FAIL - " .. name)
    end
end

package.preload["cjson.safe"] = function()
    return {
        encode = function(t) return tostring(t) end,
        decode = function(s) return {}, nil end,
    }
end
package.preload["resty.redis"] = function()
    return {
        new = function()
            return {
                set_timeouts = function() end,
                connect = function() return false, "stub" end,
                set_keepalive = function() return true end,
            }
        end,
    }
end
package.preload["resty.sha256"] = function()
    return {
        new = function()
            return {
                update = function() end,
                final = function() return "\0\0\0\0" end,
            }
        end,
    }
end
package.preload["resty.string"] = function()
    return { to_hex = function() return "00000000" end }
end
package.preload["resty.lrucache"] = function()
    return {
        new = function(size)
            local store, n = {}, 0
            return {
                get = function(_, k) return store[k] end,
                set = function(_, k, v)
                    if not store[k] and n >= size then return end
                    if not store[k] then n = n + 1 end
                    store[k] = v
                end,
            }
        end,
    }
end
package.preload["resty.radixtree"] = function()
    error("radixtree unavailable in unit stub")
end

-- Stub config with controllable tenant for check_tenant tests
local stub_tenant = nil
package.preload["config"] = function()
    return {
        redis_host = function() return "127.0.0.1" end,
        redis_port = function() return 6379 end,
        tenant_id = function() return stub_tenant end,
        host_identity_fallback_enabled = function() return true end,
        ingress_enabled = function() return true end,
        tls_required = function() return false end,
        acme_enabled = function() return false end,
        acme_email = function() return "" end,
        acme_domains = function() return { list = {}, set = {} } end,
        acme_domain_allowed = function() return false end,
        control_plane_base = function() return "http://cp" end,
        java_fallback_enabled = function() return true end,
        rewrite_localhost = function(u) return u end,
        docker_host_rewrite = function() return nil end,
        full_resync_interval_sec = function() return 300 end,
        edge_api_key = function() return nil end,
        internal_api_key = function() return nil end,
        ingress_undeclared_enforce = function() return "observe" end,
    }
end

-- Minimal shared-dict stub. proxy_core pulls peer_resolver → circuit_breaker
-- (and rate_limit / metrics / response_cache / ai_gateway / auth_jwt), all of
-- which index ngx.shared.* at module load time.
local function new_dict()
    local data = {}
    return {
        get = function(_, k) return data[k] end,
        set = function(_, k, v) data[k] = v; return true end,
        add = function(_, k, v)
            if data[k] ~= nil then return nil, "exists" end
            data[k] = v
            return true
        end,
        incr = function(_, k, n, init)
            local cur = tonumber(data[k]) or tonumber(init) or 0
            cur = cur + (tonumber(n) or 1)
            data[k] = cur
            return cur
        end,
        delete = function(_, k) data[k] = nil end,
        ttl = function() return 0 end,
        expire = function() return true end,
    }
end

ngx = {
    null = {},
    shared = {
        mendr_circuit_breaker = new_dict(),
        mendr_lb_rr = new_dict(),
        mendr_rate_limit = new_dict(),
        mendr_metrics = new_dict(),
        mendr_response_cache = new_dict(),
        mendr_jwks = new_dict(),
        mendr_sync_state = new_dict(),
        dedup_cache = new_dict(),
    },
    log = function() end,
    INFO = 6, WARN = 4, ERR = 3, DEBUG = 7, CRIT = 2,
    time = function() return 0 end,
    now = function() return 0 end,
    req = {},
    ctx = {},
    header = {},
    var = {},
    HTTP_GET = 1, HTTP_POST = 2,
}

local proxy_core = require("proxy_core")

check("GET → none",
    proxy_core.body_output_mode({ has_body = false }, "GET", false, {}) == "none")

check("empty POST → none",
    proxy_core.body_output_mode({ has_body = false, mode = "ingress", is_json = true }, "POST", false, {}) == "none")

check("envelope always json-encodes payload",
    proxy_core.body_output_mode({ has_body = true, mode = "envelope", is_json = true }, "POST", false, {}) == "json")

check("ingress JSON without transform → raw (no re-encode)",
    proxy_core.body_output_mode({
        has_body = true, mode = "ingress", is_json = true, raw_body = '{"a":1}'
    }, "POST", false, { ["Content-Type"] = "application/json" }) == "raw")

check("ingress JSON + transform → json",
    proxy_core.body_output_mode({
        has_body = true, mode = "ingress", is_json = true, raw_body = '{"a":1}'
    }, "POST", true, { ["Content-Type"] = "application/json" }) == "json")

check("spilled + JSON → error413",
    proxy_core.body_output_mode({
        has_body = true, body_spilled = true, mode = "ingress", is_json = true
    }, "POST", false, {}) == "error413")

check("spilled + transform → error413",
    proxy_core.body_output_mode({
        has_body = true, body_spilled = true, mode = "ingress", is_json = false
    }, "POST", true, {}) == "error413")

check("spilled + non-JSON → spilled",
    proxy_core.body_output_mode({
        has_body = true, body_spilled = true, mode = "ingress", is_json = false
    }, "POST", false, { ["Content-Type"] = "application/octet-stream" }) == "spilled")

local ingress_rt = require("ingress_routing")
check("NO_TREE distinct",
    ingress_rt.classify_fallthrough("NO_TREE", "observe") == "NO_TREE")
check("observe → SHADOW",
    ingress_rt.classify_fallthrough("NO_MATCH", "observe") == "SHADOW_ROUTE_ACCESSED")
check("strict → NO_MATCH",
    ingress_rt.classify_fallthrough("NO_MATCH", "strict") == "NO_MATCH")

local identity = require("identity_resolver")
check("opaque key rejected",
    identity.shape_ok("abcdefghijklmnopqrstuvwxyz012345") == false)
check("prefix.secret accepted",
    identity.shape_ok("mendr_AbC123xy.abcdefghijklmnopqrstuvwx") == true)

stub_tenant = "tenant-a"
check("tenant match ok", identity.check_tenant("tenant-a") == true)
check("tenant mismatch rejected", identity.check_tenant("tenant-b") == false)
stub_tenant = nil
check("no edge tenant configured → skip check", identity.check_tenant("anything") == true)

print("")
if failures == 0 then
    print("ALL PASSED")
    os.exit(0)
else
    print(failures .. " FAILED")
    os.exit(1)
end
