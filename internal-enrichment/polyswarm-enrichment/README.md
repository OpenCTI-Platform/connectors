# OpenCTI PolySwarm Connector

[![Tests](https://github.com/polyswarm/opencti-connectors/actions/workflows/tests.yml/badge.svg)](https://github.com/polyswarm/opencti-connectors/actions/workflows/tests.yml)

| Status | Date       | Comment                        |
|--------|------------|--------------------------------|
| Beta   | 2026-03-09 | Seeking upstream review/merge  |

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration](#configuration)
  - [OpenCTI Configuration](#opencti-configuration)
  - [Base Connector Configuration](#base-connector-configuration)
  - [PolySwarm Configuration](#polyswarm-configuration)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
  - [Data Flow](#data-flow)
  - [Enrichment Mapping](#enrichment-mapping)
  - [Generated STIX Objects](#generated-stix-objects)
  - [Relationship Types](#relationship-types)
  - [Multi-Community Mode](#multi-community-mode)
  - [polykg Integration (Optional)](#polykg-integration-optional)
  - [Quota](#quota)
- [Data Handling](#data-handling)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

[PolySwarm](https://polyswarm.io/) is a crowdsourced threat intelligence
marketplace where security engines compete to detect malware. This connector
enriches file hash observables by querying the PolySwarm API and importing
threat intelligence into OpenCTI. It also looks up URL, domain and IP
observables (lookup only, nothing is submitted).

Key features:

- **Multi-engine detection**: 60+ AV/ML engines via PolySwarm crowdsourced
  marketplace
- **PolyScore**: Proprietary threat score combining all engine verdicts
- **PolyUnite consensus**: Unified malware family classification across engines
- **Platform tags**: Curated artifact tags and malware family labels via TagLink
  API
- **Multi-community**: Parallel queries across private and default communities
- **Circuit breaker**: Automatic backoff on API failures (5 failures = 5 min
  cooldown)
- **Malware profile enrichment** (optional): Threat actors, MITRE ATT&CK TTPs,
  CVEs, target locations, industry sectors via polykg knowledge graph
- **Error reporting**: API errors surfaced as STIX Notes visible in OpenCTI
- **URL, domain and IP lookups**: latest PolySwarm URL scan verdict, scored from
  engine detections, plus files PolySwarm links to an IP or domain

---

## Installation

### Requirements

- OpenCTI Platform >= 6.0.6
- PolySwarm API key ([get one here](https://polyswarm.network/))
- Network access to `api.polyswarm.network`
- (Optional) polykg knowledge graph API for advanced profile enrichment

---

## Configuration

### OpenCTI Configuration

| Parameter    | Docker envvar  | Mandatory | Description                                          |
|--------------|----------------|-----------|------------------------------------------------------|
| `opencti_url`  | `OPENCTI_URL`  | Yes       | The URL of the OpenCTI platform                      |
| `opencti_token`| `OPENCTI_TOKEN`| Yes       | The default admin token configured in the platform   |

### Base Connector Configuration

| Parameter                    | Docker envvar                | Mandatory | Description                                                      |
|------------------------------|------------------------------|-----------|------------------------------------------------------------------|
| `connector_id`               | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` unique for this connector             |
| `connector_name`             | `CONNECTOR_NAME`             | No        | Display name (default: `PolySwarm Hash Enrichment`)              |
| `connector_scope`            | `CONNECTOR_SCOPE`            | No        | Observable types to enrich (default: `StixFile,Artifact,Url,Domain-Name,IPv4-Addr,IPv6-Addr`) |
| `connector_auto`             | `CONNECTOR_AUTO`             | No        | Enable/disable auto-enrichment (default: `false`)                |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | No        | Default confidence level (default: `80`)                         |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`        | No        | Log level: `debug`, `info`, `warning`, `error` (default: `info`) |
| `connector_max_tlp`          | `CONNECTOR_MAX_TLP`          | No        | Max TLP level to enrich (default: `TLP:RED`, no limit). Replaces the deprecated `POLYSWARM_MAX_TLP` |

### PolySwarm Configuration

| Parameter                            | Docker envvar                        | Mandatory | Description                                                                  |
|--------------------------------------|--------------------------------------|-----------|------------------------------------------------------------------------------|
| `polyswarm_api_key`                  | `POLYSWARM_API_KEY`                  | Yes       | PolySwarm API authentication key                                             |
| `polyswarm_community`                | `POLYSWARM_COMMUNITY`                | No        | Community: `default` or `private` (default: `default`)                       |
| `polyswarm_max_polling_time`         | `POLYSWARM_MAX_POLLING_TIME`         | No        | Maximum API polling time in seconds (default: `120`)                         |
| `polyswarm_replace_with_lower_score` | `POLYSWARM_REPLACE_WITH_LOWER_SCORE` | No        | Overwrite score even if lower (default: `true`). Set `false` to keep higher. |
| `polyswarm_network_related_files_max` | `POLYSWARM_NETWORK_RELATED_FILES_MAX` | No       | Max related file hashes imported per IP or domain lookup (default: `10`, `0` disables) |
| `polyswarm_network_url_send_query` | `POLYSWARM_NETWORK_URL_SEND_QUERY` | No | Send a URL's query string and fragment for lookup (default: `false`, only scheme, host and path are sent) |
| `polyswarm_network_indicator_min_detections` | `POLYSWARM_NETWORK_INDICATOR_MIN_DETECTIONS` | No | Malicious engine detections needed before a URL, domain or IP Indicator is created (default: `2`) |
| `polyswarm_quota_warn_below` | `POLYSWARM_QUOTA_WARN_BELOW` | No | Log a warning when the remaining daily API quota, or a sandbox or hunt allowance, falls below this number (default: `100`, `0` turns warnings off). See [Quota](#quota) |
| `polykg_api_url`                     | `POLYSWARM_POLYKG_API_URL`           | No        | polykg knowledge graph API URL (default: empty = disabled)                   |

---

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`.

Example `docker-compose.yml`:

```yaml
version: '3'
services:
  connector-polyswarm:
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_TYPE=INTERNAL_ENRICHMENT
      - CONNECTOR_NAME=PolySwarm Hash Enrichment
      - CONNECTOR_SCOPE=StixFile,Artifact,Url,Domain-Name,IPv4-Addr,IPv6-Addr
      # Keep false: auto-enrichment would send every in-scope URL, domain and IP to PolySwarm
      - CONNECTOR_AUTO=false
      - CONNECTOR_CONFIDENCE_LEVEL=80
      - CONNECTOR_LOG_LEVEL=info
      # - CONNECTOR_MAX_TLP=TLP:AMBER
      - POLYSWARM_API_KEY=ChangeMe
      - POLYSWARM_COMMUNITY=default
      # - POLYSWARM_REPLACE_WITH_LOWER_SCORE=true
    restart: always
    networks:
      - opencti-network

networks:
  opencti-network:
    external: true
```

### Manual Deployment

1. Clone the repository
2. Copy `config.yml.sample` to `config.yml` and configure
3. Install dependencies: `pip install -r src/requirements.txt`
4. Run: `cd src && python main.py`

---

## Usage

The connector enriches file hash observables by:

1. Querying the PolySwarm API for detection results and PolyScore
2. Fetching curated platform tags and malware families via TagLink API
3. Creating a Note with full analysis summary (detections, score, hashes)
4. Updating the observable's `x_opencti_score` from PolyScore
5. Creating an Indicator with the file hash STIX pattern
6. Creating a Malware object from PolyUnite family classification
7. (Optional) Enriching with malware profiles from polykg: threat actors,
   locations, CVEs, TTPs, sectors, campaigns

The connector enriches URL, domain and IP (v4 and v6) observables by:

1. Looking up the latest PolySwarm URL scan of the exact value (search only,
   nothing is submitted or uploaded)
2. Creating a Note with the malicious and total engine counts, the scan date
   (flagged when older than 90 days) and a link to the PolySwarm scan, with an
   external reference to that link
3. Updating the observable's `x_opencti_score` to the share of engines that
   flagged it (`round(100 * malicious / total)`), following
   `POLYSWARM_REPLACE_WITH_LOWER_SCORE`. For these observables the score is the
   share of engines that flagged the value (malicious / total). No score is
   set when no engine answered.
4. Creating an Indicator (confidence 50, valid for 30 days) only when at least
   `POLYSWARM_NETWORK_INDICATOR_MIN_DETECTIONS` engines flagged the value.
   URL engine counts are small (1 to 5), so a single detection is weak.
5. For IPs and domains, importing up to `POLYSWARM_NETWORK_RELATED_FILES_MAX`
   files PolySwarm links to the value, as file observables (SHA-256) with a
   `related-to` relationship
6. Creating a short "No Scan Found" Note when PolySwarm has no scan of the value

Private, reserved, shared (`100.64.0.0/10`), loopback, link-local and
multicast IPs (including IPv4-mapped IPv6 forms and non-canonical IPv4 forms
such as `127.1` or `2130706433`), internal domains (single label, `.local`,
`.internal`, `.lan`, `.corp`, `.home.arpa`, `.localhost`) and URLs containing
a username or password are skipped and never sent to PolySwarm. Observables
carrying a marking the connector can't resolve to a TLP are also skipped,
unless `CONNECTOR_MAX_TLP` is `TLP:RED`.

Notes, Indicators, relationships and related file observables created for a
URL, domain or IP carry the same markings as the source observable.

Trigger enrichment:
- Manually via the OpenCTI UI observable detail page
- Automatically if `CONNECTOR_AUTO=true`
- Via OpenCTI playbooks

---

## Behavior

### Data Flow

```mermaid
flowchart LR
    A[File Observable] --> B[PolySwarm Connector]
    B --> C{PolySwarm API}
    C --> D[Hash Search]
    D --> E[ArtifactInstance]
    E --> F[PolyScore + Detections]
    E --> G[PolyUnite Family]
    E --> H[TagLink Tags/Families]
    F --> I[Score Update]
    F --> J[Note]
    G --> K[Malware SDO]
    K --> L[Indicator]
    B --> M{polykg API}
    M -->|optional| N[Malware Profile]
    N --> O[Threat Actors]
    N --> P[Attack Patterns]
    N --> Q[Locations]
    N --> R[Vulnerabilities]
    N --> S[Sectors]
```

### Enrichment Mapping

| Observable Type   | Enrichment Data                                                     |
|-------------------|---------------------------------------------------------------------|
| StixFile/Artifact | PolyScore, detections, PolyUnite family, platform tags, hashes, Indicator, Malware, Note |
| Url               | Latest URL scan: engine detections, score, scan date, Note, Indicator (threshold) |
| Domain-Name, IPv4-Addr, IPv6-Addr | Latest URL scan as above, plus related file hashes          |

### Generated STIX Objects

| STIX Type        | Source             | Description                                                    |
|------------------|--------------------|----------------------------------------------------------------|
| `note`           | PolySwarm API      | Enrichment summary: detections, score, hashes, malware family, profile data. One per community in multi-community mode. |
| `indicator`      | PolySwarm API      | File hash indicator with STIX pattern `[file:hashes.'SHA-256' = '...']`. `x_opencti_score` from PolyScore. |
| `malware`        | PolyUnite + polykg | Malware family SDO (`is_family: true`). Includes `malware_types` from PolyUnite labels or profile. Aliases from `related_malware`. |
| `attack-pattern` | polykg             | MITRE ATT&CK techniques. Kill chain phases, external references to MITRE. Created from profile TTPs and malware-type-to-TTP mappings. |
| `threat-actor`   | polykg             | Threat actors attributed to malware family. Includes aliases (cross-referenced actors). |
| `location`       | polykg             | Countries: target locations and origin/attribution locations.  |
| `vulnerability`  | polykg             | CVEs exploited by malware family. External references to NVD.  |
| `identity`       | polykg             | Targeted industry sectors (`identity_class: "class"`).         |
| `intrusion-set`  | polykg             | Campaigns or intrusion sets using the malware.                 |
| `software`       | polykg             | Targeted operating systems/platforms.                          |
| `file`           | PolySwarm API      | Files PolySwarm links to an enriched IP or domain (SHA-256 only, no score). |
| `relationship`   | All sources        | Links between all above entities (see table below).            |

### Relationship Types

| Relationship     | Source                | Target              | Confidence |
|------------------|-----------------------|---------------------|------------|
| `indicates`      | Indicator             | Malware             | 100        |
| `based-on`       | Indicator             | Observable          | varies     |
| `related-to`     | IP / domain observable| File                | n/a        |
| `related-to`     | Malware               | Related Malware     | 80         |
| `uses`           | Threat Actor          | Malware             | 85         |
| `uses`           | Intrusion Set         | Malware             | 85         |
| `uses`           | Malware               | Attack Pattern      | 75         |
| `targets`        | Malware               | Location            | 75         |
| `targets`        | Malware               | Vulnerability       | 90         |
| `targets`        | Malware               | Identity (Sector)   | 75         |
| `targets`        | Threat Actor          | Location            | 75         |
| `targets`        | Threat Actor          | Identity (Sector)   | 75         |
| `originates-from`| Malware               | Location            | 70         |
| `located-at`     | Threat Actor          | Location            | 70         |

### Multi-Community Mode

When `POLYSWARM_COMMUNITY=private`, the connector queries **both** private and
default communities in parallel using a thread pool:

- Results from both communities are compared by `last_seen` timestamp
- The most recent data is used for scoring and enrichment
- **Separate Notes** are created for each community so both results are visible
- Each community has its own circuit breaker (5 failures = 5 min cooldown)

| Scenario                 | Behavior                                                |
|--------------------------|---------------------------------------------------------|
| Both have results        | Most recent used as primary; both get Notes             |
| Only private has results | Private data used; single Note                          |
| Only default has results | Default data used; single Note                          |
| Private fails, default OK| Default used; error Note for private failure            |
| Both fail                | Error Note listing both failures                        |

### polykg Integration (Optional)

The connector can optionally connect to a [polykg](https://github.com/polyswarm/polykg)
knowledge graph instance for advanced malware profile enrichment. **polykg is
not required** — the connector fully functions without it.

| With polykg                                    | Without polykg                                |
|------------------------------------------------|-----------------------------------------------|
| Malware family profiles with full metadata     | Basic Malware SDO from PolyUnite family name  |
| Threat actors with aliases and attribution     | No threat actor entities                      |
| MITRE ATT&CK techniques from profile TTPs     | No attack pattern entities                    |
| Target/origin locations (countries)            | No location entities                          |
| Exploited CVEs                                 | No vulnerability entities                     |
| Targeted industry sectors                      | No sector entities                            |
| Campaigns/intrusion sets                       | No intrusion set entities                     |
| `malware_types` from structured profile        | `malware_types` from PolySwarm labels fallback|

**polykg endpoints used:**

| Endpoint                              | When              | Purpose                                              |
|---------------------------------------|-------------------|------------------------------------------------------|
| `GET /v3/kg/opencti/attack-patterns`  | Connector startup | MITRE ATT&CK technique metadata + type-to-TTP maps  |
| `POST /v3/kg/profile`                 | Per enrichment    | Malware family profile (actors, CVEs, TTPs, etc.)    |
| `GET /v3/kg/profile`                  | Startup           | Health check (204 = reachable)                       |

If polykg is unreachable, the connector logs a warning and continues with
PolySwarm-only enrichment. A circuit breaker skips polykg for 5 minutes after
a connection failure to avoid blocking the single-threaded enrichment queue.

Set `POLYSWARM_POLYKG_API_URL` to enable (e.g. `http://polykg:4141`). Leave empty or
unset to disable.

### Quota

The connector reads your PolySwarm account's plan and quotas so you can see them in its log. This is read-only and on by default: at startup, and about once an hour after that, it makes one read-only request to the account endpoint (`GET /public/accounts`, through the SDK's `account_features()`), plus at most one more per minute after a quota error. The logic is in `src/polyswarm_enrichment/quota.py`. The account number in the response is never read or logged.

What is logged, at info level:

```
[QUOTA] plan Example Plan; daily API calls remaining 640 of 1000; sandbox_request: 300 of 500 remaining; usage window ends 2026-12-01T00:00:00+00:00
```

The sandbox and hunt allowances shown are the account features `sandbox_request`, `historical_hunt`, `live_hunt` and `manual_analysis`.

- **Warning.** When the remaining daily API quota, or one of those allowances, is below `POLYSWARM_QUOTA_WARN_BELOW` (default `100`), the connector logs a warning. Set it to `0` to turn warnings off.
- **Unlimited or exhausted.** A daily limit of `0` means the account has no cap: `daily_api_limit` and `daily_api_remaining` are both `0` on an uncapped plan (measured on an internal plan, where every feature also reports `base_uses` of `0`). Such an account is shown as unlimited and never warned about. A limit above `0` with nothing remaining means the quota is exhausted. A feature the plan does not include is reported as not on this plan. The API does not say how a capped plan reports an exhausted quota beyond these fields, so this reading of `0` as "no cap" is inferred from the SDK and from that measurement.
- **When a call fails because of quota.** The SDK raises `UsageLimitsExceededException` on HTTP 429. The error note the connector writes on the observable then says the quota is exhausted or the rate limit was hit, and lists the plan, the remaining daily API calls and sandbox or hunt allowances, and when the usage window ends (the account record's `window_end`; the API does not publish a separate daily reset time). If the quota cannot be read at that moment, the note says so.
- **Failures are harmless.** If the account cannot be read (network error, 5xx, a response in an unexpected shape), the connector logs a warning, tries again within a few minutes, and carries on enriching.

---

## Data Handling

What leaves your environment, and when. The connector sends data to PolySwarm only when it enriches an observable, which is manual by default (`CONNECTOR_AUTO=false`).

- **File observables: hashes only.** The observable's file hash (SHA-256, SHA-1 or MD5) is sent to PolySwarm to look up existing scan results, and the SHA-256 is used to look up associated indicators. Files are never uploaded.
- **URL, domain and IP observables.** The observable's value (the URL, domain or IP) is sent to PolySwarm for lookup. For URLs, only the scheme, host and path are sent by default: the query string and fragment are removed first, so tokens in them never leave OpenCTI. Set `POLYSWARM_NETWORK_URL_SEND_QUERY=true` to send the full URL. URLs containing a username or password are never sent. For IPs and domains, the same value is also used to search for related files. Private and internal values (see [Usage](#usage)) are never sent, and nothing is submitted for scanning.
- **Community.** Lookups are made in the community set in `POLYSWARM_COMMUNITY`. With `POLYSWARM_COMMUNITY=private`, each lookup is made in your private community and also in the public `default` community.
- **TLP.** Observables above `CONNECTOR_MAX_TLP` are never sent.
- **Malware profiles (opt-in).** With `POLYSWARM_POLYKG_API_URL` set, the detected malware family name is sent to that URL, together with your PolySwarm API key for authentication.
- **Account quota.** Once an hour the connector reads your account's plan and quotas from PolySwarm. Only your API key is sent; nothing from OpenCTI is.
- **Nothing else.** No other OpenCTI data (other entities, reports, markings or users) is sent.

---

## Debugging

Enable debug logging:

```
CONNECTOR_LOG_LEVEL=debug
```

### Common Issues

| Symptom                          | Cause                                    | Fix                                                    |
|----------------------------------|------------------------------------------|--------------------------------------------------------|
| No enrichment happening          | `CONNECTOR_AUTO=false` or wrong scope    | Set `CONNECTOR_AUTO=true`, scope to `StixFile,Artifact`|
| Error Note: "401 Access Denied"  | Invalid API key or no community access   | Verify `POLYSWARM_API_KEY`                             |
| Error Note: "429 Rate Limited"   | API quota exceeded                       | Reduce feeder rate or upgrade PolySwarm plan           |
| Error Note: "Circuit Breaker"    | 5+ consecutive API failures              | Check network; breaker resets after 5 min              |
| No profile enrichment            | polykg unreachable or not configured     | Set `POLYSWARM_POLYKG_API_URL` or verify polykg is running       |
| Score not updating               | Bundle import doesn't persist scores     | This is expected; connector uses explicit `update_field()` |

### Circuit Breaker

The connector implements circuit breaker protection on both the PolySwarm API
and polykg:

- **PolySwarm**: Per-community breaker. 5 failures = 5 min cooldown.
- **polykg profiles**: Connection-error breaker. Single failure = 5 min cooldown.
- **polykg attack patterns**: Loaded once at startup; no retry.

During cooldown, enrichment continues with reduced data rather than blocking.

---

## Additional Information

- **PolySwarm**: https://polyswarm.io/
- **PolySwarm API docs**: https://docs.polyswarm.io/
- **OpenCTI**: https://filigran.io/solutions/open-cti/
- **MITRE ATT&CK**: https://attack.mitre.org/

---

## File Structure

```
polyswarm-enrichment/
├── Dockerfile
├── docker-compose.yml
├── config.yml.sample
├── README.md
├── src/
│   ├── main.py                          # Entry point
│   ├── requirements.txt
│   └── polyswarm_enrichment/
│       ├── __init__.py
│       ├── connector.py                 # Orchestrator: message → enrichment → STIX bundle
│       ├── client_api.py                # PolySwarm API client + circuit breaker
│       ├── converter_to_stix.py         # PolySwarm data → STIX 2.1 objects
│       ├── attack_pattern_handler.py    # MITRE ATT&CK patterns from polykg
│       ├── malware_profile_loader.py    # Family profiles from polykg
│       ├── polyswarm_client.py          # Thin wrapper over polyswarm-api PyPI SDK
│       ├── settings.py                  # Pydantic configuration (connectors-sdk)
│       └── utils.py                     # Shared utilities
└── tests/
    ├── conftest.py
    ├── test-requirements.txt
    ├── cassettes/                       # VCR recorded API responses (auth scrubbed)
    └── test_*.py                        # Unit + integration tests
```

## License

Apache 2.0
