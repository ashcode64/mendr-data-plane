-- body_filter_abort_spec.lua — hold-output + after-flush abort behavior
--   cd infra/nginx/lua && lua spec/body_filter_abort_spec.lua

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

local splice = require('splice')

do
    local _, compiled = splice.trie_for({ empty = false, ops = { { op = 'coerce', path = '/n', targetType = 'integer' } } })
    check('value-op programs hold until EOF', compiled.hold_output == true)
end

do
    local _, compiled = splice.trie_for({ empty = false, ops = { { op = 'rename', from = '/a', to = '/b' } } })
    check('pure structural rename stays streamable', compiled.hold_output == false)
end

local function reset_body_filter_modules()
    package.loaded['body_filter'] = nil
    package.loaded['plan_class'] = nil
    package.loaded['transform'] = nil
    package.loaded['splice'] = nil
    package.loaded['cjson.safe'] = nil
    package.loaded['metrics'] = nil
    package.loaded['prefilter'] = nil
end

local function stub_body_filter(http_ver)
    reset_body_filter_modules()
    local metric_calls = 0
    package.preload['cjson.safe'] = function()
        return { encode = function() return '{}' end, decode = function() return {} end }
    end
    package.preload['transform'] = function()
        return { protected_violation = function() return nil end }
    end
    package.preload['plan_class'] = function()
        return { classify = function() return { planClass = 'FORWARD_ONLY' } end }
    end
    package.preload['metrics'] = function()
        return { inc = function() metric_calls = metric_calls + 1 end }
    end
    package.preload['problem_detail'] = function()
        return {
            merge_a3 = function(_, opts)
                return {
                    type = 'https://mendr.dev/problems/splice',
                    title = 'SPLICE',
                    status = opts and opts.status or 502,
                    detail = opts and opts.detail_fallback,
                    extensions = { failureCategory = 'SPLICE' },
                }
            end,
        }
    end
    package.preload['splice'] = function()
        return {
            feed = function(state)
                state.flushed = true
                state.buf = '{"n":"1"}'
                return state, 'boom'
            end,
            drain = function() return nil end,
            output = function() return '{}' end,
        }
    end
    ngx = {
        ctx = { need_response_body = true, responseProgram = { empty = false, ops = { { op = 'rename', from = '/a', to = '/b' } } } },
        status = 200,
        arg = { 'chunk', false },
        req = { http_version = function() return http_ver end },
        log = function() end,
        now = function() return 0 end,
        header = {},
        var = { uri = '/x', request_uri = '/x' },
        ERR = 3,
        ERROR = -1,
    }
    local ok, res = pcall(require, 'body_filter')
    return ok, res, metric_calls, ngx.ctx.splice_abort_after_flush, ngx.ctx.spliceAbortReason, ngx.ctx.mendrProblemDetail
end

do
    local ok, res, metrics, aborted, reason, pd = stub_body_filter(1.1)
    check('http/1 abort returns ngx.ERROR', ok and res == ngx.ERROR)
    check('http/1 abort marks ctx + metric', metrics == 1 and aborted == true and reason == 'boom')
    check('http/1 abort sets problem detail status 502', pd and pd.status == 502)
end

do
    local ok, res, metrics, aborted, reason, pd = stub_body_filter(2.0)
    check('http/2 abort raises controlled lua error', ok == false and tostring(res):find('mendr_splice_abort_after_flush:boom', 1, true) ~= nil)
    check('http/2 abort still marks ctx + metric', metrics == 1 and aborted == true and reason == 'boom')
    check('http/2 abort sets problem detail status 502', pd and pd.status == 502)
end

print(string.rep('-', 40))
if failures == 0 then
    print('ALL PASSED')
    os.exit(0)
else
    print(failures .. ' FAILED')
    os.exit(1)
end