-- ingress_sync_spec.lua ? worker version catch-up / NO_TREE retry helpers
--   cd infra/nginx/lua && lua spec/ingress_sync_spec.lua

package.path = package.path .. ';../?.lua;./?.lua'

local failures = 0
local function check(name, cond)
    if cond then
        print('ok   - ' .. name)
    else
        failures = failures + 1
        print('FAIL - ' .. name)
    end
end

-- ingress_routing requires a real JSON decoder to parse the sync tables.
local ok_cjson = pcall(require, 'cjson.safe')
if not ok_cjson then
    print('SKIP - cjson.safe not available')
    os.exit(0)
end

local function reset_modules()
    -- Clear both loaded caches and preloads. The NO_TREE block installs a stub
    -- via package.preload['ingress_routing']; leaving that in place makes later
    -- requires return the stub (no match_pair / no real reload_from_redis).
    local names = {
        'ingress_routing', 'ingress', 'proxy_core', 'identity_resolver',
        'resty.redis', 'resty.radixtree', 'config', 'cjson.safe',
    }
    for _, name in ipairs(names) do
        package.loaded[name] = nil
        package.preload[name] = nil
    end
end

local function new_shared(init)
    local data = init or {}
    return {
        get = function(_, k) return data[k] end,
        set = function(_, k, v) data[k] = v; return true end,
        add = function(_, k, v, ttl)
            if data[k] ~= nil then return nil, 'exists' end
            data[k] = v
            return true
        end,
        delete = function(_, k) data[k] = nil end,
        _data = data,
    }
end

local function stub_common(shared)
    ngx = {
        shared = { mendr_sync_state = shared },
        null = {},
        sleep = function() end,
        log = function() end,
        WARN = 4, INFO = 6, ERR = 3, DEBUG = 7,
        time = function() return 0 end,
    }
    package.preload['config'] = function()
        return { redis_host = function() return '127.0.0.1' end, redis_port = function() return 6379 end }
    end
    package.preload['resty.radixtree'] = function() error('no radix in unit test') end
    -- ingress_routing require("resty.redis") at load; connection is provided via
    -- the proxy_core.redis_connect stub, so this only needs to load.
    package.preload['resty.redis'] = function()
        return {
            new = function()
                return {
                    set_timeouts = function() end,
                    connect = function() return false, 'stub' end,
                    set_keepalive = function() return true end,
                }
            end,
        }
    end
end

do
    reset_modules()
    local shared = new_shared({ last_version = '7' })
    stub_common(shared)

    local fake_redis = {
        get = function(_, k)
            if k == 'mendr:ingress:tables' then
                return '{"api.example.com":[{"path":"/orders/{id}","method":"GET","targetService":"orders","endpointTemplate":"/orders/{id}"}]}'
            elseif k == 'mendr:ingress:pair_keys' then
                return '["mendr:routeconfig:shop:orders:/orders/{id}"]'
            end
            return ngx.null
        end,
        keys = function() return {} end,
        set_keepalive = function() return true end,
    }
    package.preload['proxy_core'] = function()
        return {
            redis_connect = function() return fake_redis end,
            redis_close = function() return true end,
        }
    end
    local rt = require('ingress_routing')
    local ok = rt.ensure_fresh()
    local target, tmpl = rt.match('api.example.com', 'GET', '/orders/42')
    check('ensure_fresh reloads host tree on version mismatch', ok == true and target == 'orders')
    check('ensure_fresh reloads pair tree on version mismatch', rt.match_pair('shop', 'orders', '/orders/42') == '/orders/{id}')
    check('local version advanced after reload', tostring(rt.get_last_sync_version()) == '7')
end

do
    reset_modules()
    local shared = new_shared({ last_version = '8', ['ingress:rebuild_lock'] = 1 })
    stub_common(shared)
    local fake_redis = {
        get = function(_, k)
            if k == 'mendr:ingress:tables' then
                return '{"api.example.com":[{"path":"/v1","method":"GET","targetService":"svc","endpointTemplate":"/v1"}]}'
            end
            return ngx.null
        end,
        keys = function() return {} end,
        set_keepalive = function() return true end,
    }
    package.preload['proxy_core'] = function()
        return {
            redis_connect = function() return fake_redis end,
            redis_close = function() return true end,
        }
    end
    local rt = require('ingress_routing')
    local reloads = 0
    local orig = rt.reload_from_redis
    rt.reload_from_redis = function(...)
        reloads = reloads + 1
        return orig(...)
    end
    rt.ensure_fresh()
    check('loser path does not rebuild while lock held', reloads == 0)
end

do
    -- Explicit NO_TREE retry in ingress.lua should call ensure_fresh once more before re-match.
    package.loaded['ingress'] = nil
    package.loaded['proxy_core'] = nil
    package.loaded['identity_resolver'] = nil
    package.loaded['ingress_routing'] = nil
    package.loaded['config'] = nil
    package.loaded['cjson.safe'] = nil

    local calls = { match = 0, ensure = 0 }
    ngx = {
        ctx = {},
        var = { host = 'api.example.com', uri = '/orders/42' },
        req = { get_headers = function() return {} end, get_method = function() return 'GET' end },
        header = {},
        log = function() end,
        HTTP_POST = 2,
    }
    package.preload['cjson.safe'] = function() return { encode = function() return '{}' end, decode = function() return {} end } end
    package.preload['config'] = function()
        return {
            tls_required = function() return false end,
            ingress_undeclared_enforce = function() return 'observe' end,
            java_fallback_enabled = function() return false end,
            control_plane_base = function() return 'http://cp' end,
        }
    end
    package.preload['identity_resolver'] = function()
        return { resolve = function() return 'shop', 'tenant-a' end }
    end
    package.preload['proxy_core'] = function()
        return {
            json_error = function(status) ngx.ctx._status = status end,
            run = function() ngx.ctx._ran = true end,
        }
    end
    package.preload['ingress_routing'] = function()
        return {
            match = function()
                calls.match = calls.match + 1
                if calls.match == 1 then return nil, nil, nil, 'NO_TREE' end
                return 'orders', '/orders/{id}', 'observe', nil
            end,
            ensure_fresh = function() calls.ensure = calls.ensure + 1; return true end,
            handle_fallthrough = function() return 'NO_TREE' end,
            is_stale = function() return false end,
        }
    end

    require('ingress')
    check('ingress NO_TREE retry explicitly calls ensure_fresh', calls.ensure == 1)
    check('ingress NO_TREE retry performs second match', calls.match == 2 and ngx.ctx._ran == true)

    -- Drop stub preloads so later blocks load the real ingress_routing module.
    reset_modules()
end

do
    -- pair_keys index absent (edge upgraded before first post-upgrade sync):
    -- reload_from_redis must SCAN mendr:routeconfig:* and still build pair trees.
    reset_modules()
    local shared = new_shared({ last_version = '9' })
    stub_common(shared)
    local scanned = false
    local fake_redis = {
        get = function(_, k)
            if k == 'mendr:ingress:tables' then
                return '{"api.example.com":[{"path":"/orders/{id}","method":"GET","targetService":"orders","endpointTemplate":"/orders/{id}"}]}'
            end
            -- pair_keys deliberately absent ? forces the SCAN fallback path.
            return ngx.null
        end,
        keys = function(_, pattern)
            if pattern == 'mendr:routeconfig:*' then
                scanned = true
                return { 'mendr:routeconfig:shop:orders:/orders/{id}' }
            end
            return {}
        end,
        set_keepalive = function() return true end,
    }
    package.preload['proxy_core'] = function()
        return {
            redis_connect = function() return fake_redis end,
            redis_close = function() return true end,
        }
    end
    local rt = require('ingress_routing')
    rt.ensure_fresh()
    check('missing pair_keys triggers routeconfig SCAN', scanned == true)
    check('SCAN fallback rebuilds pair tree from routeconfig keys',
        rt.match_pair('shop', 'orders', '/orders/42') == '/orders/{id}')
end

do
    -- Pair rebuild failure must NOT advance last_sync_version (P0): otherwise
    -- envelope catch-up stops for the whole sync version.
    reset_modules()
    local shared = new_shared({ last_version = '11' })
    stub_common(shared)
    local fake_redis = {
        get = function(_, k)
            if k == 'mendr:ingress:tables' then
                return '{"api.example.com":[{"path":"/orders/{id}","method":"GET","targetService":"orders","endpointTemplate":"/orders/{id}"}]}'
            elseif k == 'mendr:ingress:pair_keys' then
                return '["mendr:routeconfig:shop:orders:/orders/{id}"]'
            end
            return ngx.null
        end,
        keys = function() return {} end,
        set_keepalive = function() return true end,
    }
    package.preload['proxy_core'] = function()
        return {
            redis_connect = function() return fake_redis end,
            redis_close = function() return true end,
        }
    end
    local rt = require('ingress_routing')
    local orig_pairs = rt.rebuild_pairs_from_route_keys
    rt.rebuild_pairs_from_route_keys = function()
        return false, 'forced pair failure'
    end
    local ok = rt.reload_from_redis('11')
    check('pair rebuild failure returns false from reload_from_redis', ok == false)
    check('pair rebuild failure does not advance last_sync_version',
        tostring(rt.get_last_sync_version() or '') ~= '11')
    -- Restore for safety if the module is reused in-process.
    rt.rebuild_pairs_from_route_keys = orig_pairs
end

do
    -- sync_client contract: after host rebuild + pair failure, set_last_sync_version
    -- rolls worker-0 local version back while shared last_version can still advance.
    reset_modules()
    local shared = new_shared({ last_version = '5' })
    stub_common(shared)
    package.preload['proxy_core'] = function()
        return {
            redis_connect = function() return {
                get = function() return ngx.null end,
                keys = function() return {} end,
                set_keepalive = function() return true end,
            } end,
            redis_close = function() return true end,
        }
    end
    local rt = require('ingress_routing')
    -- Simulate worker-0 host rebuild advancing local version, then pair fail rollback.
    local ok_host = rt.rebuild({
        ['api.example.com'] = {
            { path = '/v1', method = 'GET', targetService = 'svc', endpointTemplate = '/v1' },
        },
    }, '12')
    check('host rebuild advances local version', ok_host == true and tostring(rt.get_last_sync_version()) == '12')
    rt.set_last_sync_version('5') -- rollback as sync_client does on pair failure
    shared:set('last_version', '12') -- shared still bumped for other workers
    check('pair-fail rollback leaves local behind shared',
        tostring(rt.get_last_sync_version()) == '5'
        and tostring(shared:get('last_version')) == '12')
    -- ensure_fresh should therefore attempt another reload for this worker.
    local reloads = 0
    local orig = rt.reload_from_redis
    rt.reload_from_redis = function(...)
        reloads = reloads + 1
        return orig(...)
    end
    rt.ensure_fresh()
    check('rolled-back worker retries reload via ensure_fresh', reloads >= 1)
end

print(string.rep('-', 40))
if failures == 0 then
    print('ALL PASSED')
    os.exit(0)
else
    print(failures .. ' FAILED')
    os.exit(1)
end