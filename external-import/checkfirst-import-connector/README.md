# OpenCTI Connector: Checkfirst Import

Ingest Checkfirst articles from the Checkfirst API into OpenCTI as STIX 2.1 bundles, tracking the Portal-Kombat / Pravda Network Russian influence operation.

This is an `EXTERNAL_IMPORT` connector that:

- On first run, sends a one-off bundle of known Pravda network infrastructure (36 `pravda-XX.com` domains, 60+ `news-pravda.com` subdomains, shared hosting IP `178.21.15.85`) attributed to the Portal-Kombat intrusion set per SGDSN/VIGINUM reports (Feb + Apr 2024)
- Fetches articles from a paginated REST API (`Api-Key` header auth)
- Maps each article to STIX 2.1 objects and sends them in batches
- Persists an `_id` cursor in OpenCTI connector state so reruns resume with keyset pagination (`after` / `next_cursor`)

## STIX object model

### First-run infrastructure bundle

Sent once on a fresh walk (no saved cursor, or `CHECKFIRST_FORCE_REPROCESS=true`):

```
IntrusionSet (Portal-Kombat)
  ← attributed-to ← Campaign 2023

Campaign 2023
  → uses → Infrastructure (pravda-XX.com)   [per domain, start_time = first_observed]
    → consists-of → DomainName (pravda-XX.com)
    → consists-of → IPv4Address (178.21.15.85, stop_time = 2024-12-31)
  DomainName (news-pravda.com subdomain)
    → related-to → Infrastructure (pravda-XX.com)
```

### Per-article ingestion

For each article row fetched from the API:

```
Campaign YYYY (per-year, first_seen = YYYY-01-01, special-cased 2023-09-01)
  ← attributed-to ← IntrusionSet (Portal-Kombat)
  → uses → Infrastructure (article domain)
    → consists-of → DomainName (article domain)
  → uses → Channel/website (article domain)   [start_time = publication date]
    → related-to → Infrastructure (article domain)
    → publishes → Media-Content (article)
    → related-to → Channel/source (Telegram or website origin)
  DomainName (article domain)
    → related-to → Channel/website (article domain)
  Media-Content (article)
    → related-to → Channel/source
    → related-to → URL (alternate URLs, if any)
  Channel/website (article domain)
    → related-to → DomainName (pravda-XX.com parent, if subdomain of news-pravda.com)
```

All STIX IDs are deterministic — reruns produce no duplicates.

## Requirements

- A running OpenCTI stack (platform + worker) at a version matching `pycti` in `src/requirements.txt`
- A dedicated OpenCTI token for the connector
- Access to the Checkfirst API (URL + API key)

## Configuration

Configuration parameters can be provided in either **`config.yml`** file, **`.env`** file or directly as **environment variables** (e.g. from **`docker-compose.yml`** for Docker deployments).

Priority: **YAML > .env > environment > defaults**.

### Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

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

3. Optional log file: set `CHECKFIRST_LOG_FILE` (e.g.
   `/var/log/checkfirst-connector/connector.log`) and mount its parent directory
   as a volume to keep JSON logs on the host. With `CONNECTOR_LOG_LEVEL=info`,
   `[BENCH]` timing lines are recorded too:
   ```sh
   grep BENCH logs/connector.log
   ```
   Tune parallelism with `CHECKFIRST_CONVERT_WORKERS` (process pool for Row → STIX;
   HTTP fetch and the `_id` watermark stay single-threaded). Default is `1`.

## Verify in OpenCTI

- **Data > Connectors** — confirm the connector registers and shows as active
- **Data > Ingestion** — confirm a new work item is created and completes
- After first run, search for:
  - 36 `Domain-Name` observables for `pravda-XX.com` domains
  - 36 `Infrastructure` objects wrapping those domains
  - 1 `IPv4-Addr` observable `178.21.15.85`
  - 60+ `Domain-Name` observables for `news-pravda.com` subdomains
  - `Campaign` objects per year (`Portal-Kombat 2023`, `Portal-Kombat 2024`, …)
  - `IntrusionSet` — Portal-Kombat
- Per article:
  - `Media-Content` with `publication_date`
  - `Channel` entities (type `Telegram` or `website`)
  - `Infrastructure` wrapping the publishing domain
  - Relationships: `uses`, `consists-of`, `publishes`, `related-to`

## Notes

- STIX IDs are deterministic — reruns do not create duplicate entities.
- The infrastructure bundle is sent only on a fresh walk (no cursor). Set `CHECKFIRST_FORCE_REPROCESS=true` to clear the cursor and resend it.
- The connector saves the last processed article `_id` as `last_cursor` in OpenCTI state; the next run requests `after=<last_cursor>` so new inserts (higher `_id`s) are picked up without re-walking the corpus.
- Legacy `last_page` state from offset pagination is ignored.
- The `since` and `until` filters are resolved to absolute UTC datetimes at connector startup; duration strings like `P365D` are supported for convenience. `until` is optional and bounds the import window, e.g. `CHECKFIRST_SINCE=2025-09-01T00:00:00Z` with `CHECKFIRST_UNTIL=2025-09-30T23:59:59Z` imports a single month. Both bounds are inclusive, and a date without a time (`2025-09-30`) means midnight UTC, so use `T23:59:59Z` to include the whole last day. The connector refuses to start if `until` is earlier than `since`.
- The saved cursor only records how far the walk went (`_id` order), not which window it walked. Widening `since` or `until` between runs therefore does not pick up older articles that now fall inside the window. After changing either, run once with `CHECKFIRST_FORCE_REPROCESS=true`, then set it back to `false`.
- API requests use a 300-second timeout per page. The Checkfirst infrastructure can be slow to respond on large result pages.
- `CHECKFIRST_CONVERT_WORKERS>1` parallelizes only Row → STIX conversion. Cursor advances only after a successful bundle send; a failed send stops the run without skipping ahead (no gaps).
- Bundle prepare/send runs on a background thread so the next convert batch can overlap. With `CONNECTOR_LOG_LEVEL=info`, grep logs for `[BENCH]`: `overlapped_with_send`, `prepare_seconds`, `to_stix2_seconds`, `send_bundle_seconds`, `wait_seconds`. `error` omits those lines.
- `CHECKFIRST_BUNDLE_SIZE` caps unique objects per OpenCTI send (default `10000`). Smaller → more work items, shorter per-send stalls; same deterministic STIX IDs / no data gaps if sends succeed.
- Article `Infrastructure` omits `first_seen` so the same domain dedupes across articles (known domains keep `first_seen` from the first-run infrastructure bundle).
