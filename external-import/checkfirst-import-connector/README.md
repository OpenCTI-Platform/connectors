# OpenCTI Connector: Checkfirst Import

Ingest Checkfirst articles from the Checkfirst API into OpenCTI as STIX 2.1 bundles.

This is an `EXTERNAL_IMPORT` connector that:

- Fetches articles from a paginated REST API (`Api-Key` header auth)
- Maps each article to OpenCTI-friendly STIX objects (`channel`, `media-content`, `url`) and relationships
- Sends bundles via `helper.send_stix2_bundle`
- Persists page-based progress using OpenCTI connector state so reruns resume where they left off

## Requirements

- A running OpenCTI stack (OpenCTI platform + worker)
- A dedicated OpenCTI token for the connector
- Access to the Checkfirst API (URL + API key)

## Configuration (environment variables)

OpenCTI standard variables:

- `OPENCTI_URL`
- `OPENCTI_TOKEN`
- `CONNECTOR_ID` (UUID, stable)
- `CONNECTOR_TYPE` (use `EXTERNAL_IMPORT`)
- `CONNECTOR_NAME`
- `CONNECTOR_SCOPE` (recommended: `media-content,channel,url`)
- `CONNECTOR_LOG_LEVEL` (e.g. `info` or `debug`)

Connector-specific:

- `CHECKFIRST_API_URL` (base URL, e.g. `https://api.checkfirst.example.com`)
- `CHECKFIRST_API_KEY` (sent as `Api-Key` header)
- `CHECKFIRST_API_ENDPOINT` (default: `/v1/articles`)
- `CHECKFIRST_SINCE` (ISO 8601 date; default: `2025-01-01T00:00:00Z` — only ingest articles published on or after this date)

Optional:

- `CHECKFIRST_TLP_LEVEL` (default: `clear`)
- `CHECKFIRST_FORCE_REPROCESS` (default: `false` — set to `true` to restart from page 1)
- `CHECKFIRST_MAX_ROW_BYTES` (skip rows exceeding this size)

See `.env.sample` in this folder for a working template.

## Run locally (without Docker)

1) Create a Python 3.11+ virtualenv and install requirements:

- `python3.11 -m venv .venv`
- `.venv/bin/pip install -r src/requirements.txt`

2) Configure `.env`

- Copy `.env.sample` to `.env`
- Set `OPENCTI_URL`, `OPENCTI_TOKEN`
- Set `CHECKFIRST_API_URL`, `CHECKFIRST_API_KEY`

3) Run

From this folder:

- `.venv/bin/python -u src/main.py`

## Run with Docker Compose

1) Create your connector `.env`

- Copy `.env.sample` to `.env`
- Fill in at least `OPENCTI_URL`, `OPENCTI_TOKEN`, `CHECKFIRST_API_URL`, `CHECKFIRST_API_KEY`

2) Start the connector

From this folder:

- `docker compose up --build`

## Verify in OpenCTI

- In **Data > Connectors**, confirm the connector is running
- In **Data > Ingestion**, confirm a new "work" is created and completes successfully
- Search for ingested objects:
	- `media-content` with `publication_date`
	- `channel`
	- `url`
	- relationships (`publishes`, `related-to`)

## Notes

- The mapping enforces deterministic STIX IDs for idempotency (reruns should not create duplicates).
- The connector persists the last processed API page in connector state; on restart it resumes from the next page.
- For one-shot runs (Run & Terminate), set `CONNECTOR_DURATION_PERIOD=PT0S` or use the platform toggle.
- Enjoy.