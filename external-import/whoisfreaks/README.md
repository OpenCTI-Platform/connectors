# OpenCTI WhoisFreaks Connector

| Status | Date | Comment |
|--------|------|---------|
| Community / Pending verification | - | Prepared for Filigran review |

Ingests **WhoisFreaks** commercial domain threat intelligence and newly registered domain (NRD) feeds into OpenCTI as STIX 2.1 Domain-Name observables and Indicators.

## Features

- **Threat feeds**: malware, phishing, spam (stream API with offset/limit pagination)
     - Imports the latest available snapshot. The connector does not delete objects that disappear from later snapshots; manage retention through OpenCTI.
- **Latest day only**: each run ingests only the status endpoint's `last_update` date (no multi-day historical backfill). `WHOISFREAKS_IMPORT_SINCE` acts as a floor — if `last_update` is older than that date the feed is skipped
- **NRD feeds**: gTLD/ccTLD, with or without WHOIS enrichment
- **Per-feed toggle**: enable only the endpoints covered by your subscription
- **Scalable ingestion**: streamed CSV parsing, configurable page size, retries with backoff, and resumable state after successful runs
- **Clear subscription errors**: 401/403 produce actionable log messages and are skipped; other enabled feeds continue. Other processor failures abort the callback without saving state
- **Resumable**: day-level state plus per-day record offsets; failed feeds resume from the most recently saved offset, while abrupt termination may replay pages from the last completed callback


## STIX mapping (OpenCTI standard)

Every response column from WhoisFreaks is preserved. Mapping follows common
OpenCTI connector practice:

| STIX / OpenCTI element | Content |
|------------------------|---------|
| **Domain-Name** | Observable for each domain (`value` = domain) |
| **Description** | Short summary only (feed name, WHOIS available / confidence) |
| **Note** | Full response columns as a markdown table (empty fields omitted) |
| **x_whoisfreaks_*** custom properties | Non-empty columns on the observable (may not render in UI) |
| **Indicator** | Threat feeds always; NRD only when `WHOISFREAKS_CREATE_INDICATORS_FOR_NRD=true` |
| **Relationship** `based-on` | Indicator → Domain-Name |
| **Labels** | `whoisfreaks`, feed-specific labels |
| **Author** | Organization identity `WhoisFreaks` |
| **Marking** | Configured TLP level |

### NRD with WHOIS (`nrd_*_with_whois`)

- Domain-Name + short description
- Note with every **non-empty** CSV column in a markdown table (`| Field | Value |`)
- Optional Indicator + `based-on` relationship

### NRD without WHOIS (`nrd_*_without_whois`)

- Domain-Name + short description only (no Note)

### Threat feeds (`malware`, `phishing`, `spam`)

- Domain-Name + short description
- Note with all non-empty feed columns: `domain`, `threat_type`, `confidence`, `first_seen`, `last_seen`, `No_of_threat_matched_pivots`
- Indicator + `based-on` relationship

## Requirements

- Python >= 3.11
- OpenCTI Platform >= 7.261002.0
- `pycti==7.261021.1` (or matching your OpenCTI version)
- `connectors-sdk` matching your OpenCTI version
- WhoisFreaks API key with access to the feeds you enable

## Configuration

See [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md) for the full schema.

### Essential variables

| Environment variable | Description | Default |
|----------------------|-------------|---------|
| `OPENCTI_URL` | OpenCTI URL | required |
| `OPENCTI_TOKEN` | OpenCTI API token | required |
| `WHOISFREAKS_API_KEY` | WhoisFreaks API key | required |
| `WHOISFREAKS_FEED_TYPES` | Comma-separated threat feeds: `malware`, `phishing`, `spam` | all three |
| `WHOISFREAKS_NRD_FEED_TYPES` | Comma-separated NRD feeds (see below) | all four |
| `WHOISFREAKS_PAGE_LIMIT` | Records per HTTP page | `5000` |
| `WHOISFREAKS_CHECKPOINT_EVERY_PAGES` | Update in-memory offset every N pages; state is persisted at the end of the connector callback | `10` |
| `WHOISFREAKS_IMPORT_SINCE` | Floor date (ISO datetime or duration e.g. `P7D`); skip if `last_update` is older | `P1D` |
| `WHOISFREAKS_CREATE_INDICATORS_FOR_NRD` | Create Indicators for NRD (noisy at scale) | `false` |
| `WHOISFREAKS_TLP_LEVEL` | TLP marking | `clear` |

### Subscription-aligned toggles

Only list feeds included in your WhoisFreaks plan. Examples:

```yaml
# Threat-only plan
WHOISFREAKS_FEED_TYPES=malware,phishing
WHOISFREAKS_NRD_FEED_TYPES=

# NRD domains-only (no WHOIS)
WHOISFREAKS_FEED_TYPES=
WHOISFREAKS_NRD_FEED_TYPES=nrd_gtld_without_whois,nrd_cctld_without_whois
```

Valid NRD values:

- `nrd_gtld_with_whois`
- `nrd_cctld_with_whois`
- `nrd_gtld_without_whois`
- `nrd_cctld_without_whois`

If a feed returns HTTP 401/403, the connector logs a clear subscription message and skips that feed while continuing with the remaining enabled feeds. Other processor failures stop the callback and prevent state from being saved.

## Deployment

### Docker

```shell
docker build -t opencti/connector-whoisfreaks:latest .
```

Edit `docker-compose.yml` environment variables, then:

```shell
docker compose up -d
```

### Manual

1. Copy `config.yml.sample` to `config.yml` and set values.
2. Install dependencies from `pyproject.toml` (Poetry/uv/pip).
3. Run from `src`:

```shell
python3 main.py
```

## Behavior

1. On each scheduled run (`CONNECTOR_DURATION_PERIOD`), the connector loads persisted state.
2. It fetches a single WhoisFreaks `/v3.4/status` snapshot (shared by all processors).
3. For each **enabled** feed:
   - Targets only the status `last_update` day (skips if already ingested).
   - Skips if that day is not yet available according to status.
   - Paginates the stream API from the stored offset.
   - Transforms each page to STIX and sends bundles via the SDK.
     - Updates the in-memory offset every `checkpoint_every_pages` pages; the connector persists state at callback end only after all processors succeed.
   - When a day is complete, advances the day checkpoint and clears the offset.
4. Subscription denials (401/403) are isolated; other processor failures abort the callback and prevent state persistence.

### Scale guidance

| Setting | Recommendation for 10M–100M+ rows/day |
|---------|----------------------------------------|
| `page_limit` | 5000–10000 (bundle output is chunked at 10000 STIX objects) |
| `checkpoint_every_pages` | 5–20 |
| `create_indicators_for_nrd` | `false` (observables only) |
| Connector duration | Daily (`PT24H`) |

STIX IDs for indicators are deterministic (`Indicator.generate_id(pattern)`), so reprocessing a page after a crash is idempotent at the OpenCTI layer.

## Program flow

```
main.py
  → ConnectorSettings / ConnectorState
  → ThreatFeedProcessor × enabled feed_types
  → NRDProcessor × enabled nrd_feed_types
  → WhoisFreaksExternalImportConnector.start()   # SDK scheduler
       → callback()
            → state.load()
            → status_client.get_status()
            → for processor: set_status + process()
                 → collect()  # status gate + paginated iter from offset
                 → transform()  # page → STIX objects
                 → SDK sends bundles / work tracking
            → state.last_run = now; save()
```

## Debugging

Set `CONNECTOR_LOG_LEVEL=info` or `debug`. Subscription denials and checkpoint messages appear at error/debug levels respectively.

### Architecture & Design Notes

- **State persistence**: Processors update offsets in memory and the connector saves shared state only after all processors succeed. Subscription denials are handled within their processor; other failures abort the callback without saving. Abrupt termination can replay pages from the last completed callback; deterministic STIX IDs make replay idempotent.
- **Latest day only**: Both threat-feed and NRD processors ingest only the status `last_update` date. Older platform objects are not purged by the connector; use OpenCTI retention policies for cleanup.
- **Deterministic IDs**: Both Indicators and Notes use deterministic IDs (`Note.generate_id(None, content)`), ensuring full idempotency across re-runs without duplicate object creation in OpenCTI.

## Additional information

- Stream endpoints (`/v3.4/stream/...`, `/v3.3/stream/domainer/...`) are the supported ingestion path for this connector.
- Auth: API key sent as `X-API-KEY` header (not in URL query parameters, preventing credentials from leaking in logs).
- Author Identity: all objects reference organization `WhoisFreaks`.
