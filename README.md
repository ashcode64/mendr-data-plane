# Mendr Data Plane

This repository contains the lightweight edge data plane for Mendr:

- `mendr-gateway` (OpenResty/Lua)
- `mendr-edge-redis` (local snapshot cache with AOF)

## Purpose

Client services call the local data plane for:

- `POST /api/gateway/proxy`
- `POST /api/services`
- `POST /api/services/{name}/contracts`
- `POST /api/gateway/cors-rules/bootstrap` (CORS policy bootstrap — forwarded to control plane)
- `GET /api/gateway/cors-rules` (list active CORS rules — forwarded to control plane)

The proxy hot path stays local. Registration and contract calls are forwarded upstream to the Mendr control plane.

## Run

```powershell
docker compose up -d --build
```

## Required environment

- `MENDR_CONTROL_PLANE_URL` - cloud or on-prem control plane base URL
- `GATEWAY_EDGE_API_KEY` - **per-tenant** edge API key (`<prefix>.<secret>`), issued by
  the control plane. Presenting it makes the control plane resolve the tenant and
  return ONLY that tenant's route snapshots. This is the multi-tenant SaaS credential.
- `MENDR_TENANT_ID` - (optional) the tenant UUID, sent as a defense-in-depth
  cross-check header (`X-Tenant-Id`). Also enforced on ingress API-key / host
  identity resolution (tenant mismatch → 401).
- `GATEWAY_INTERNAL_API_KEY` - shared internal API key. Kept for backward
  compatibility for legacy/single-tenant edges that do not yet have a per-tenant key.

### Transparent ingress (Phase 6)

- `MENDR_INGRESS_ENABLED=true` — enable the catch-all ingress location.
- `MENDR_HOST_IDENTITY_FALLBACK` — when unset, follows ingress enabled. Host
  fallback uses synced `mendr:hostident:{host}` if `X-Mendr-Key` is absent.
- `MENDR_TLS_REQUIRED=true` — reject non-HTTPS ingress (except ACME HTTP-01).
- `MENDR_ACME_ENABLED=true` — in-edge Let's Encrypt via `lua-resty-acme`.
  When false/unset, **:443 does not listen** (entrypoint skips installing the
  HTTPS server). When true, exposes `:443` with ACME + fallback cert until
  issuance succeeds.
- `MENDR_ACME_EMAIL` — ACME account email (required when ACME on).
- `MENDR_ACME_DOMAINS` — comma-separated hostname allowlist for this edge
  (CNAME your customer hosts here; isolation is per-edge allowlist).
- `MENDR_ACME_STAGING=true` — use Let's Encrypt staging (recommended first).

**CNAME onboarding:** point `api.customer.com` → this edge's public hostname
(A/AAAA or CNAME). Register host identity:

```http
POST /api/services/ingress-host-identity
{ "host": "api.customer.com", "sourceService": "order-service" }
```

Issue an ingress key (or rely on host fallback):

```http
POST /api/services/ingress-api-keys
{ "sourceService": "order-service" }
```

Expose ports **80** (HTTP-01) and **443** (HTTPS) when ACME is enabled.

## Multi-tenant edge onboarding (SaaS)

Each edge is provisioned for exactly one tenant:

1. In the control plane, create a tenant (or use an existing one) and issue a
   per-tenant API key for it. The secret is shown once; only its hash is stored
   (`api_keys` table, keyed by tenant). Register the edge in `edge_gateways`.
2. Deploy this data plane with `GATEWAY_EDGE_API_KEY=<prefix>.<secret>` (and
   optionally `MENDR_TENANT_ID=<tenant-uuid>`).
3. The sync client authenticates every `/v1/sync/routeconfig` long-poll with that
   key (`X-Api-Key`); the control plane binds the tenant and scopes the snapshot,
   the sync-version counter, and long-poll wakeups to that tenant.

Because each edge is single-tenant and receives only its own routes, the local
Redis snapshot keyspace never mixes tenants.

## Notes

- Redis is local and persistent via AOF.
- This repository intentionally does not include Postgres, Kafka, AI analysis, or the dashboard.
