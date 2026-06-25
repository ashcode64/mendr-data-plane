#!/usr/bin/env bash
# Create mendr-edge release zip for manual client distribution.

set -euo pipefail

VERSION="${1:-1.0.0}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RELEASE_DIR="${ROOT}/release"
OUT="${RELEASE_DIR}/mendr-edge-${VERSION}.zip"

if [[ ! -f "${RELEASE_DIR}/docker-compose.yml" ]]; then
  echo "Missing ${RELEASE_DIR}/docker-compose.yml" >&2
  exit 1
fi

rm -f "${OUT}"
(
  cd "${RELEASE_DIR}"
  if command -v zip >/dev/null 2>&1; then
    zip -q "${OUT}" docker-compose.yml .env.example README.md
  else
    echo "zip not found; use PowerShell: .\\scripts\\pack-release.ps1" >&2
    exit 1
  fi
)

echo "Created ${OUT}"
