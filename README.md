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
- `GATEWAY_INTERNAL_API_KEY` - shared internal API key used for forwarded/internal calls

## Notes

- Redis is local and persistent via AOF.
- This repository intentionally does not include Postgres, Kafka, AI analysis, or the dashboard.
