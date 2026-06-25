#!/usr/bin/env bash
# Build and push Mendr data plane gateway image to Docker Hub.
# Prerequisites: docker login (as teammendr), Docker Hub repo teammendr/themendr created.

set -euo pipefail

VERSION="${1:-1.0.0}"
IMAGE="teammendr/themendr:${VERSION}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "Building ${IMAGE} from ${ROOT}/infra/nginx ..."
docker build -t "${IMAGE}" "${ROOT}/infra/nginx"

if [[ "${PUSH_LATEST:-0}" == "1" ]]; then
  docker tag "${IMAGE}" "teammendr/themendr:latest"
fi

echo "Pushing ${IMAGE} ..."
docker push "${IMAGE}"

if [[ "${PUSH_LATEST:-0}" == "1" ]]; then
  docker push "teammendr/themendr:latest"
fi

echo "Done. Image published: ${IMAGE}"
echo "Clients can use release/docker-compose.yml or mendr-edge-${VERSION}.zip"
