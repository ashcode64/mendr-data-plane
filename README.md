# Mendr Data Plane

Lightweight Mendr edge data plane:

- `mendr-gateway` (OpenResty/Lua) — local proxy and route snapshot cache
- `mendr-edge-redis` — edge Redis for route config sync

Client services call the local edge at `http://localhost:8080`.

## For customers (Docker Hub install)

Use the files in [`release/`](release/) or the zip `release/mendr-edge-1.0.0.zip`:

1. Create a folder (e.g. `~/mendr-edge`)
2. Copy `docker-compose.yml` and `.env.example`
3. `cp .env.example .env` and set control plane URL + API key
4. `docker compose pull && docker compose up -d`

Image: **`teammendr/themendr:1.0.0`** (public on Docker Hub)

See [release/README.md](release/README.md) for full install steps.

## For developers (this repo)

Build from source with live-mounted nginx/lua configs:

```powershell
cp .env.example .env
# edit .env
docker compose -f docker-compose.dev.yml up -d --build
```

## Publish a new image (maintainers)

After creating the `teammendr/themendr` repo on Docker Hub:

```powershell
docker login
.\scripts\build-and-push.ps1 1.0.0
.\scripts\pack-release.ps1 1.0.0
```

Linux:

```bash
docker login
./scripts/build-and-push.sh 1.0.0
./scripts/pack-release.sh 1.0.0
```

## Required environment

- `MENDR_CONTROL_PLANE_URL` — cloud control plane base URL
- `GATEWAY_INTERNAL_API_KEY` — shared internal API key (must match control plane)

## Endpoints (via edge)

- `POST /api/gateway/proxy`
- `POST /api/services`
- `POST /api/services/{name}/contracts`
- `GET /health`

Registration and sync calls are forwarded to the Mendr control plane; proxy hot path stays local.
