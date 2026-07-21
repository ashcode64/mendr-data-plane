-- Functional spec for RFC 9457 problem_detail helpers (plain Lua, no OpenResty).
--   cd infra/nginx/lua && lua spec/problem_detail_spec.lua

package.path = package.path .. ";../?.lua;./?.lua"
local PD = require("problem_detail")

local failures = 0
local function check(name, cond)
    if cond then
        print("ok   - " .. name)
    else
        failures = failures + 1
        print("FAIL - " .. name)
    end
end

do
    local p = PD.native_problem({
        status = 401,
        error_type = "IDENTITY_UNRESOLVED",
        message = "unauthorized",
        healing = false,
        instance = "/api/x",
        correlation_id = "c1",
        request_id = "r1",
    })
    check("native type lowercases code", p.type == "https://mendr.dev/problems/identity_unresolved")
    check("native title preserves code", p.title == "IDENTITY_UNRESOLVED")
    check("native detail set", p.detail == "unauthorized")
    check("native status", p.status == 401)
    check("native selfHealing false", p.selfHealingTriggered == false)
    check("native corr", p.correlationId == "c1")
    check("native retains error extension", p.error == "IDENTITY_UNRESOLVED")
end

do
    check("ct match problem+json", PD.is_problem_content_type("application/problem+json; charset=utf-8"))
    check("ct rejects plain json", not PD.is_problem_content_type("application/json"))
    check("ct rejects nil", not PD.is_problem_content_type(nil))
end

do
    check("prefer detail over message",
        PD.prefer_detail_message({ detail = "d", message = "m", error = "e" }) == "d")
    check("prefer message when no detail",
        PD.prefer_detail_message({ message = "m", error = "e" }) == "m")
end

do
    local body = {
        type = "https://example.com/problems/x",
        title = "X",
        status = 422,
        detail = "bad amount",
        instance = "/charge",
        template_id = "t1",
        json_path = "/amount",
    }
    local pd = PD.from_body(body, 422)
    check("from_body detail", pd.detail == "bad amount")
    check("from_body extensions flatten", pd.extensions.template_id == "t1" and pd.extensions.json_path == "/amount")
end

do
    local upstream = {
        type = "https://up.example/problems/y",
        title = "Y",
        status = 400,
        detail = "upstream detail",
        extensions = { owner_action_required = true },
    }
    local merged = PD.merge_a3(upstream, {
        category = "SCHEMA_MISMATCH",
        status = 400,
        source = "orders",
        target = "payments",
        endpoint = "/charge",
        correlation_id = "c",
        request_id = "r",
        detail_fallback = "fallback",
        template_id = "tpl",
        json_path = "/x",
    })
    check("merge keeps upstream detail", merged.detail == "upstream detail")
    check("merge adds sourceService", merged.extensions.sourceService == "orders")
    check("merge adds targetService", merged.extensions.targetService == "payments")
    check("merge keeps owner flag", merged.extensions.owner_action_required == true)
    check("merge adds template_id when known", merged.extensions.template_id == "tpl")
    check("merge adds json_path when known", merged.extensions.json_path == "/x")
end

-- Wire contract: native json_error → A3 merge → /failures payload shape (no OpenResty needed)
do
    local report = PD.failure_report_shape({
        status = 401,
        error_type = "IDENTITY_UNRESOLVED",
        message = "unauthorized",
        healing = false,
        instance = "/api/pay",
        correlation_id = "c-wire",
        request_id = "r-wire",
    }, {
        source = "orders",
        target = "unknown",
        endpoint = "/api/pay",
        json_path = "/amount",
        template_id = "drain-tpl-1",
    })
    check("wire CT problem+json", report.ContentType == "application/problem+json")
    check("wire errorMessage from detail", report.errorMessage == "unauthorized")
    check("wire correlationId", report.correlationId == "c-wire")
    check("wire pd title", report.problemDetail.title == "IDENTITY_UNRESOLVED")
    check("wire A3 sourceService", report.problemDetail.extensions.sourceService == "orders")
    check("wire localization template_id", report.problemDetail.extensions.template_id == "drain-tpl-1")
    check("wire localization json_path", report.problemDetail.extensions.json_path == "/amount")
end

do
    local pd = PD.from_body({
        type = "https://example.com/problems/x",
        detail = "bad",
        status = 400,
        template_id = "t-up",
        json_path = "/tax",
    }, 400)
    local ctx = {}
    PD.promote_localization(pd, ctx)
    check("promote template_id to ctx", ctx.template_id == "t-up")
    check("promote json_path to ctx", ctx.json_path == "/tax")
end

if failures > 0 then
    print(failures .. " failure(s)")
    os.exit(1)
end
print("all passed")
