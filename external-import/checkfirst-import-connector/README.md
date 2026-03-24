# OpenCTI Connector: Checkfirst Import

Ingest Checkfirst articles from the Checkfirst API into OpenCTI as STIX 2.1 bundles, tracking the Portal-Kombat / Pravda Network Russian influence operation.

This is an `EXTERNAL_IMPORT` connector that:

- On first run, sends a one-off bundle of known Pravda network infrastructure (36 `pravda-XX.com` domains, 60+ `news-pravda.com` subdomains, shared hosting IP `178.21.15.85`) attributed to the Portal-Kombat intrusion set per SGDSN/VIGINUM reports (Feb + Apr 2024)
- Fetches articles from a paginated REST API (`Api-Key` header auth)
- Maps each article to STIX 2.1 objects and sends them in batches
- Persists page-based progress in OpenCTI connector state so reruns resume where they left off
- Records a `last_run` unix timestamp in state for operational visibility

## STIX object model

### First-run infrastructure bundle

Sent once when `start_page == 1` (first ever run, or `CHECKFIRST_FORCE_REPROCESS=true`):

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
| `CHECKFIRST_FORCE_REPROCESS` | Ignore saved state and restart from page 1 (also re-sends the infrastructure bundle) | `false` |
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
- The infrastructure bundle is sent only when `start_page == 1`. Set `CHECKFIRST_FORCE_REPROCESS=true` to resend it.
- The connector saves the last successfully processed API page in OpenCTI state; on restart it resumes from the next page.
- The `since` filter is resolved to an absolute UTC datetime at connector startup; duration strings like `P365D` are supported for convenience.
- API requests use a 300-second timeout per page. The Checkfirst infrastructure can be slow to respond on large result pages.
