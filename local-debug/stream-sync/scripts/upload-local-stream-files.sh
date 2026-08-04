#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
LOCAL_STREAM_DIR="$ROOT_DIR/opencti-stream"

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE"
  exit 1
fi

if [ ! -d "$LOCAL_STREAM_DIR" ]; then
  echo "Missing local stream directory: $LOCAL_STREAM_DIR"
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

: "${MINIO_ENDPOINT:?MINIO_ENDPOINT is required in .env}"
: "${MINIO_PORT:?MINIO_PORT is required in .env}"
: "${MINIO_ACCESS_KEY:?MINIO_ACCESS_KEY is required in .env}"
: "${MINIO_SECRET_KEY:?MINIO_SECRET_KEY is required in .env}"
: "${MINIO_BUCKET:?MINIO_BUCKET is required in .env}"
: "${MINIO_FOLDER:?MINIO_FOLDER is required in .env}"

if ! find "$LOCAL_STREAM_DIR" -type f -print -quit >/dev/null; then
  echo "No files found in $LOCAL_STREAM_DIR"
  exit 0
fi

MINIO_SCHEME="http"
if [ "${MINIO_SECURE:-false}" = "true" ]; then
  MINIO_SCHEME="https"
fi

TARGET_PATH="${MINIO_BUCKET}/${MINIO_FOLDER}"
echo "Preparing local files from $LOCAL_STREAM_DIR for upload to ${TARGET_PATH}"

UPLOAD_READY_DIR="$ROOT_DIR/.upload-ready"
rm -rf "$UPLOAD_READY_DIR"
mkdir -p "$UPLOAD_READY_DIR"

# Case 1: regular stream_*.json files already present.
for f in "$LOCAL_STREAM_DIR"/stream_*.json; do
  [ -f "$f" ] || continue
  cp "$f" "$UPLOAD_READY_DIR/"
done

# Case 2: MinIO backend layout with part.1 payloads in stream_*.json/*/part.1
for p in "$LOCAL_STREAM_DIR"/stream_*.json/*/part.1; do
  [ -f "$p" ] || continue
  base="$(basename "$(dirname "$(dirname "$p")")")"
  out="$UPLOAD_READY_DIR/$base"
  # Strip binary prefix and keep payload from first JSON object.
  first_json_offset="$(LC_ALL=C grep -aobm1 '{"version"' "$p" | cut -d: -f1 || true)"
  if [ -n "$first_json_offset" ]; then
    dd if="$p" of="$out" bs=1 skip="$first_json_offset" status=none
  fi
done

if ! ls "$UPLOAD_READY_DIR"/stream_*.json >/dev/null 2>&1; then
  echo "No importer-ready stream_*.json files produced from $LOCAL_STREAM_DIR"
  exit 1
fi

# Use the official minio client container to avoid local dependency installation.
CONTAINER_CLI=""
if command -v docker >/dev/null 2>&1; then
  CONTAINER_CLI="docker"
elif command -v podman >/dev/null 2>&1; then
  CONTAINER_CLI="podman"
else
  echo "Neither docker nor podman is available in PATH"
  exit 1
fi

"$CONTAINER_CLI" run --rm \
  --entrypoint /bin/sh \
  -v "$UPLOAD_READY_DIR":/upload:ro \
  minio/mc:latest \
  -c "
    set -e
    mc alias set local ${MINIO_SCHEME}://${MINIO_ENDPOINT}:${MINIO_PORT} ${MINIO_ACCESS_KEY} ${MINIO_SECRET_KEY}
    mc mb --ignore-existing local/${MINIO_BUCKET}
    mc rm --recursive --force local/${TARGET_PATH} || true
    mc cp --recursive /upload/stream_*.json local/${TARGET_PATH}/
  "

echo "Upload complete. Importer will pick up files on next run (${IMPORTER_RUN_EVERY:-configured interval})."
