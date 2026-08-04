#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT_DIR/.env"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"

if [ ! -f "$ENV_FILE" ]; then
  echo "Missing $ENV_FILE"
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

if [ -z "${OPENCTI_URL:-}" ] || [ -z "${OPENCTI_TOKEN:-}" ]; then
  echo "OPENCTI_URL and OPENCTI_TOKEN must be set in .env"
  exit 1
fi

ensure_connector_id() {
  local key="$1"
  local current
  current="$(grep -E "^${key}=" "$ENV_FILE" | head -n1 | cut -d '=' -f2-)"
  if [ -z "$current" ]; then
    current="$(uuidgen | tr '[:upper:]' '[:lower:]')"
    local tmp_file
    tmp_file="$(mktemp)"
    awk -v k="$key" -v v="$current" '
      BEGIN { done=0 }
      $0 ~ ("^" k "=") { print k "=" v; done=1; next }
      { print }
      END { if (!done) print k "=" v }
    ' "$ENV_FILE" > "$tmp_file"
    mv "$tmp_file" "$ENV_FILE"
    echo "Generated $key=$current"
  fi
}

ensure_connector_id "EXPORTER_CONNECTOR_ID"
ensure_connector_id "IMPORTER_CONNECTOR_ID"

# Reload env after potential updates.
set -a
source "$ENV_FILE"
set +a

if [ -z "${CONNECTOR_LIVE_STREAM_ID:-}" ]; then
  echo "No CONNECTOR_LIVE_STREAM_ID set. Creating a dedicated live stream..."
  stream_payload="$(jq -n '{
    query: "mutation Add($filters:String!){streamCollectionAdd(input:{name:\"Local Debug Stream\",description:\"Auto-created for stream exporter/importer debug\",stream_live:true,filters:$filters}){id name}}",
    variables: {
      filters: "{\"mode\":\"and\",\"filters\":[],\"filterGroups\":[]}"
    }
  }')"
  stream_id="$(curl -sS -m 15 "$OPENCTI_URL/graphql" \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $OPENCTI_TOKEN" \
    --data "$stream_payload" | jq -r '.data.streamCollectionAdd.id // empty')"

  if [ -z "$stream_id" ]; then
    echo "Failed to determine stream id. Ensure API is up and token has TAXIIAPI_SETCOLLECTIONS capability."
    exit 1
  fi

  tmp_file="$(mktemp)"
  awk -v sid="$stream_id" '
    BEGIN { done=0 }
    /^CONNECTOR_LIVE_STREAM_ID=/ { print "CONNECTOR_LIVE_STREAM_ID=" sid; done=1; next }
    { print }
    END { if (!done) print "CONNECTOR_LIVE_STREAM_ID=" sid }
  ' "$ENV_FILE" > "$tmp_file"
  mv "$tmp_file" "$ENV_FILE"

  export CONNECTOR_LIVE_STREAM_ID="$stream_id"
  echo "Configured CONNECTOR_LIVE_STREAM_ID=$stream_id"
fi

echo "Building and starting connectors..."
docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d --build

echo "Connector status:"
docker-compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" ps
