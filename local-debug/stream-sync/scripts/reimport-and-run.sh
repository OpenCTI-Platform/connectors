#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
SOURCE_DIR="$ROOT_DIR/opencti-stream"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
FORCE_REPLAY=false

if [ "${1:-}" = "--fresh-importer-id" ]; then
  FORCE_REPLAY=true
fi

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE"
  exit 1
fi

if [ ! -d "$SOURCE_DIR" ]; then
  echo "Missing source directory: $SOURCE_DIR"
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

: "${MINIO_BUCKET:?MINIO_BUCKET is required in .env}"
: "${MINIO_FOLDER:?MINIO_FOLDER is required in .env}"
: "${MINIO_DST_PATH:?MINIO_DST_PATH is required in .env}"

CONTAINER_CLI=""
if command -v docker >/dev/null 2>&1; then
  CONTAINER_CLI="docker"
elif command -v podman >/dev/null 2>&1; then
  CONTAINER_CLI="podman"
else
  echo "Neither docker nor podman is available in PATH"
  exit 1
fi

if command -v docker-compose >/dev/null 2>&1; then
  COMPOSE_CMD="docker-compose"
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  COMPOSE_CMD="docker compose"
elif command -v podman-compose >/dev/null 2>&1; then
  COMPOSE_CMD="podman-compose"
else
  echo "No compose command found (docker-compose, docker compose, or podman-compose)."
  exit 1
fi

MINIO_CONTAINER="${MINIO_CONTAINER_NAME:-}"
if [ -z "$MINIO_CONTAINER" ]; then
  MINIO_CONTAINER="$($CONTAINER_CLI ps --format '{{.Names}}' | grep -E '^(opencti-dev-minio|minio)$' | head -n1 || true)"
fi
if [ -z "$MINIO_CONTAINER" ]; then
  MINIO_CONTAINER="$($CONTAINER_CLI ps --format '{{.Names}}' | grep 'minio' | head -n1 || true)"
fi
if [ -z "$MINIO_CONTAINER" ]; then
  echo "No running MinIO container found. Set MINIO_CONTAINER_NAME in your environment and retry."
  exit 1
fi

inbox_rel="${MINIO_FOLDER#/}"
if [[ "$MINIO_DST_PATH" == "$MINIO_BUCKET/"* ]]; then
  done_rel="${MINIO_DST_PATH#${MINIO_BUCKET}/}"
else
  done_rel="${MINIO_DST_PATH#/}"
fi

INBOX_DIR="/data/${MINIO_BUCKET}/${inbox_rel}"
DONE_DIR="/data/${MINIO_BUCKET}/${done_rel}"
LEGACY_DONE_DIR="/data/${MINIO_BUCKET}/opencti-stream-done"

if [ "$FORCE_REPLAY" = true ]; then
  if ! command -v uuidgen >/dev/null 2>&1; then
    echo "uuidgen is required for --fresh-importer-id"
    exit 1
  fi
  NEW_IMPORTER_ID="$(uuidgen | tr '[:upper:]' '[:lower:]')"
  tmp_file="$(mktemp)"
  awk -v v="$NEW_IMPORTER_ID" '
    BEGIN { done=0 }
    /^IMPORTER_CONNECTOR_ID=/ { print "IMPORTER_CONNECTOR_ID=" v; done=1; next }
    { print }
    END { if (!done) print "IMPORTER_CONNECTOR_ID=" v }
  ' "$ENV_FILE" > "$tmp_file"
  mv "$tmp_file" "$ENV_FILE"
  echo "Assigned fresh IMPORTER_CONNECTOR_ID=$NEW_IMPORTER_ID"

  set -a
  source "$ENV_FILE"
  set +a
fi

echo "Using container runtime: $CONTAINER_CLI"
echo "Using compose command: $COMPOSE_CMD"
echo "Using MinIO container: $MINIO_CONTAINER"
echo "Resetting MinIO debug paths..."
$CONTAINER_CLI exec "$MINIO_CONTAINER" sh -lc "mkdir -p '$INBOX_DIR' '$DONE_DIR' && rm -rf '$INBOX_DIR'/* '$DONE_DIR'/*"

# Cleanup legacy destination path used by older configs that overlaps source prefix.
if [ "$LEGACY_DONE_DIR" != "$DONE_DIR" ]; then
  $CONTAINER_CLI exec "$MINIO_CONTAINER" sh -lc "rm -rf '$LEGACY_DONE_DIR'"
fi

echo "Re-importing stream files from $SOURCE_DIR into $INBOX_DIR"
$CONTAINER_CLI cp "$SOURCE_DIR/." "$MINIO_CONTAINER:$INBOX_DIR/"

echo "Rebuilding and restarting importer..."
(
  cd "$ROOT_DIR"
  $COMPOSE_CMD --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build connector-stream-importer-local
)

echo "Importer status:"
(
  cd "$ROOT_DIR"
  $COMPOSE_CMD --env-file "$ENV_FILE" -f "$COMPOSE_FILE" ps connector-stream-importer-local
)

echo "Recent importer logs (last 2m):"
(
  cd "$ROOT_DIR"
  $COMPOSE_CMD --env-file "$ENV_FILE" -f "$COMPOSE_FILE" logs --since=2m connector-stream-importer-local | tail -n 120
)

echo "Done. Re-import requested and importer restarted."