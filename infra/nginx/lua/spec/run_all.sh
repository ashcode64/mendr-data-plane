#!/usr/bin/env bash
# Run all OpenResty Lua unit specs with a plain Lua interpreter.
# Specs stub ngx / resty.* where needed; those requiring cjson SKIP if it is
# unavailable. Override the interpreter with LUA_BIN (e.g. lua5.1, luajit, resty).
set -uo pipefail

# cd to infra/nginx/lua so the specs' package.path (";../?.lua;./?.lua") resolves.
cd "$(dirname "$0")/.." || exit 2

LUA_BIN="${LUA_BIN:-lua}"
if ! command -v "$LUA_BIN" >/dev/null 2>&1; then
    echo "error: '$LUA_BIN' not found on PATH (set LUA_BIN)" >&2
    exit 2
fi

specs=(
    spec/transform_ops_spec.lua
    spec/splice_spec.lua
    spec/body_policy_spec.lua
    spec/prefilter_spec.lua
    spec/problem_detail_spec.lua
    spec/ingress_hotpath_spec.lua
    spec/ingress_sync_spec.lua
    spec/body_filter_abort_spec.lua
    spec/waf_null_policy_spec.lua
)

fail=0
for s in "${specs[@]}"; do
    if [[ ! -f "$s" ]]; then
        echo "== SKIP (missing) $s =="
        continue
    fi
    echo "== running $s =="
    if ! "$LUA_BIN" "$s"; then
        echo "!! FAILED: $s" >&2
        fail=1
    fi
done

if [[ "$fail" -ne 0 ]]; then
    echo "Lua specs FAILED" >&2
    exit 1
fi
echo "All Lua specs passed"
