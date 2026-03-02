# OpenCTI Connector: Checkfirst Import

Ingest Checkfirst articles from the Checkfirst API into OpenCTI as STIX 2.1 bundles.

This is an `EXTERNAL_IMPORT` connector that:

- Fetches articles from a paginated REST API (`Api-Key` header auth)
- Maps each article to OpenCTI STIX objects: `Channel`, `Media-Content`, `URL`, and relationships
- Channels sourced from `https://t.me/` are typed as `Telegram`; all others as `website`
- Sends bundles via `helper.send_stix2_bundle`
- Persists page-based progress in OpenCTI connector state so reruns resume where they left off
- Records a `last_run` unix timestamp in state for operational visibility

## Requirements

- A running OpenCTI stack (platform + worker) at a version matching `pycti` in `src/requirements.txt`
- A dedicated OpenCTI token for the connector
- Access to the Checkfirst API (URL + API key)

## Configuration

All settings can be provided as environment variables or via `config.yml` (see `config.yml.sample`).

### OpenCTI / connector

| Variable | Description | Default |
|---|---|---|
| `OPENCTI_URL` | OpenCTI platform URL | — |
| `OPENCTI_TOKEN` | OpenCTI API token | — |
| `CONNECTOR_ID` | Stable UUID for this connector instance | — |
| `CONNECTOR_NAME` | Display name | `Checkfirst Import Connector` |
| `CONNECTOR_SCOPE` | Connector scope metadata | `checkfirst` |
| `CONNECTOR_LOG_LEVEL` | Log verbosity (`debug`, `info`, `warn`, `error`) | `info` |
| `CONNECTOR_DURATION_PERIOD` | ISO 8601 duration between runs | `P7D` |

### Checkfirst-specific

| Variable | Description | Default |
|---|---|---|
| `CHECKFIRST_API_URL` | Base URL of the Checkfirst API | — |
| `CHECKFIRST_API_KEY` | API key (sent as `Api-Key` request header) | — |
| `CHECKFIRST_API_ENDPOINT` | Endpoint path | `/v1/articles` |
| `CHECKFIRST_SINCE` | Only ingest articles published on or after this date. Accepts ISO 8601 absolute dates (`2024-01-01T00:00:00Z`) or durations relative to now (`P365D`, `P1Y`, `P6M`, `P4W`) | `P365D` |
| `CHECKFIRST_TLP_LEVEL` | TLP marking applied to all created objects (`clear`, `green`, `amber`, `amber+strict`, `red`) | `clear` |
| `CHECKFIRST_FORCE_REPROCESS` | Ignore saved state and restart from page 1 | `false` |
| `CHECKFIRST_MAX_ROW_BYTES` | Skip API rows exceeding this approximate byte size | unset |

See `.env.sample` for a ready-to-use local template.

## Run locally (without Docker)

1. Create a Python 3.12 virtualenv and install dependencies:
   ```sh
   python3.12 -m venv .venv
   .venv/bin/pip install -r src/requirements.txt
   ```

2. Configure `.env`:
   ```sh
   cp .env.sample .env
   # edit .env — set OPENCTI_URL, OPENCTI_TOKEN, CHECKFIRST_API_URL, CHECKFIRST_API_KEY
   ```

3. Run from this folder:
   ```sh
   .venv/bin/python -u src/main.py
   ```

## Run with Docker Compose

1. Configure `.env`:
   ```sh
   cp .env.sample .env
   # edit .env
   ```

2. Build and start:
   ```sh
   docker compose up --build
   ```

## Verify in OpenCTI

- **Data > Connectors** — confirm the connector registers and shows as active
- **Data > Ingestion** — confirm a new work item is created and completes
- Search for ingested objects:
  - `Media-Content` entities with `publication_date`
  - `Channel` entities (type `Telegram` or `website`)
  - `URL` observables
  - Relationships: `publishes`, `related-to`, `attributed-to`

## Notes

- STIX IDs are deterministic — reruns do not create duplicate entities.
- The connector saves the last successfully processed API page in OpenCTI state; on restart it resumes from the next page.
- The `since` filter is resolved to an absolute UTC datetime at connector startup; duration strings like `P365D` are supported for convenience.
- API requests use a 300-second timeout per page. The CheckFirst infrastructure can be slow to respond on large result pages, so a generous timeout is used to avoid spurious network errors.
