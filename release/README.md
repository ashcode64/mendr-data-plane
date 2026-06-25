# Mendr Edge 1.0.0

Run the Mendr data plane locally without cloning the source repository.

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/macOS) or Docker Engine + Compose plugin (Linux)
- Mendr control plane URL and shared internal API key from your Mendr administrator

## Install

### Linux / macOS

```bash
mkdir mendr-edge && cd mendr-edge
# Copy docker-compose.yml and .env.example into this folder, then:
cp .env.example .env
# Edit .env — set MENDR_CONTROL_PLANE_URL and GATEWAY_INTERNAL_API_KEY
docker compose pull
docker compose up -d
curl http://localhost:8080/health
```

### Windows (PowerShell)

```powershell
mkdir mendr-edge
cd mendr-edge
# Copy docker-compose.yml and .env.example into this folder, then:
Copy-Item .env.example .env
notepad .env
docker compose pull
docker compose up -d
curl http://localhost:8080/health
```

## Configuration

| Variable | Description |
|----------|-------------|
| `MENDR_CONTROL_PLANE_URL` | Base URL of your Mendr control plane (e.g. `http://8.231.78.130:8095`) |
| `GATEWAY_INTERNAL_API_KEY` | Shared secret for sync and internal API calls — must match control plane |
| `MENDR_REDIS_HOST` | Leave as `mendr-edge-redis` |
| `MENDR_REDIS_PORT` | Leave as `6379` |
| `MENDR_JAVA_FALLBACK` | Leave as `false` for the Lua data plane |
| `MENDR_DOCKER_HOST_REWRITE` | Use `host.docker.internal` on Docker Desktop so the gateway can reach apps on your host |

## Usage

Point your services at the local Mendr edge:

```text
http://localhost:8080
```

Common endpoints:

- `GET /health` — edge health check
- `POST /api/gateway/proxy` — proxied inter-service calls
- `POST /api/services` — service registration (forwarded to control plane)

The Mendr dashboard runs on the control plane (typically port `3000`), not on the edge.

## Upgrade

When a new version is released, update the image tag in `docker-compose.yml`, then:

```bash
docker compose pull
docker compose up -d
```

## Stop

```bash
docker compose down
```

To remove local Redis snapshot data as well:

```bash
docker compose down -v
```

## Troubleshooting

**Image pull fails**

- Ensure Docker is running
- Image is public on Docker Hub: `teammendr/themendr:1.0.0`
- Try: `docker pull teammendr/themendr:1.0.0`

**Health check fails**

```bash
docker compose logs mendr-gateway --tail=100
```

**Route snapshots missing / sync errors**

- Verify `MENDR_CONTROL_PLANE_URL` is reachable from your machine
- Verify `GATEWAY_INTERNAL_API_KEY` matches the control plane `.env`
- Check gateway logs for `sync_client` messages
