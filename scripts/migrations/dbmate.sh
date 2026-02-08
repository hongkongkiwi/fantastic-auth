#!/usr/bin/env bash
set -euo pipefail

DBMATE_BIN="${DBMATE_BIN:-dbmate}"
MIGRATIONS_DIR="${MIGRATIONS_DIR:-$(pwd)/migrations}"

if command -v "$DBMATE_BIN" >/dev/null 2>&1; then
  exec "$DBMATE_BIN" -d "$MIGRATIONS_DIR" "$@"
fi

# Fallback to Docker
if command -v docker >/dev/null 2>&1; then
  exec docker run --rm \
    -e DATABASE_URL="${DATABASE_URL:-}" \
    -v "$MIGRATIONS_DIR":/db/migrations \
    ghcr.io/amacneil/dbmate:2.12.0 \
    -d /db/migrations "$@"
fi

echo "dbmate not found and docker not available" >&2
exit 1
