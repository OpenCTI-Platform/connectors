# OpenCTI Connector: Pravda Dataset

Ingest Pravda dataset CSV files into OpenCTI as STIX 2.1 bundles.

This is an `EXTERNAL_IMPORT` connector that:

- Reads one or more `.csv` / `.csv.gz` files from a dataset folder
- Maps each row to OpenCTI-friendly STIX objects (`channel`, `media-content`, `url`) and relationships
- Sends bundles via `helper.send_stix2_bundle`
- Persists progress using OpenCTI connector state so reruns only ingest newly appended rows

## Requirements

- A running OpenCTI stack (OpenCTI platform + worker + RabbitMQ)
- A dedicated OpenCTI token for the connector
- A dataset folder containing Pravda CSV files

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

- `PRAVDA_DATASET_PATH` (path inside the container, e.g. `/data_set`)
- `PRAVDA_INTERVAL_MINUTES` (default: `60`)
- `PRAVDA_BATCH_SIZE` (default: `1000`)

Optional run mode:

- `PRAVDA_RUN_MODE` (default: `loop`; allowed: `loop|once`)

Optional resource guards:

- `PRAVDA_MAX_FILE_BYTES`
- `PRAVDA_MAX_ROW_BYTES`
- `PRAVDA_MAX_ROWS_PER_FILE`

See `.env.sample` in this folder for a working template.

## Run with Docker Compose

1) Create your connector `.env`

- Copy `.env.sample` to `.env`
- Fill in at least `OPENCTI_URL`, `OPENCTI_TOKEN`, and `CONNECTOR_ID`

2) Mount the dataset folder

Edit `docker-compose.yml` (in this folder) so the connector sees your dataset at `PRAVDA_DATASET_PATH`.

By default, the compose file mounts the sample dataset shipped in `./data_test`.
For production, change the left side of the volume mount to your real dataset folder.

Example:

```yaml
volumes:
	- ./data_test:/data_set:ro
```

3) Start the connector

From this folder:

- Long-running (recommended):
	- `docker compose up --build`
- One-shot (smoke test):
	- `docker compose run --rm -e PRAVDA_RUN_MODE=once connector-pravda-dataset`

## Verify in OpenCTI

- In **Data > Connectors**, confirm the connector is running
- In **Data > Ingestion**, confirm a new “work” is created and completes successfully
- Search for ingested objects:
	- `media-content` with `publication_date`
	- `channel`
	- `url`
	- relationships (`publishes`, `related-to`)

To validate incremental behavior:

1) Run once
2) Run once again (should ingest 0 new rows)
3) Append a few rows to a CSV and run once again (should ingest only new rows)

## Portable folder

This folder is intentionally self-contained (Dockerfile, compose, src, sample dataset, and docs) so you can copy `opencti-connector-pravda-dataset/` into its own repository if you want.

## Notes

- The mapping enforces deterministic STIX IDs for idempotency (reruns should not create duplicates).
- If you want a local, OpenCTI-free bundle export for debugging mappings, run the connector in one-shot mode (`PRAVDA_RUN_MODE=once`) and inspect logs / OpenCTI work results.
