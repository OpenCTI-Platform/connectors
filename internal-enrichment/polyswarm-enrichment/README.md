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
- **Pivots** (optional, off by default): other files with the same imphash, and
  files PolySwarm sandbox reports associate with an ATT&CK technique
- **YARA hunting** (optional, off by default): run a PolySwarm historical hunt
  for a YARA Indicator and import the matched files. Writes to your PolySwarm
  account and spends hunt quota

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
| `polyswarm_rescan_older_than_days` | `POLYSWARM_RESCAN_OLDER_THAN_DAYS` | No | Rescan a sample PolySwarm already holds when its latest scan is older than this many days, or it has no completed scan (default: `0` = never). Each rescan spends PolySwarm scan quota |
| `polyswarm_rescan_timeout` | `POLYSWARM_RESCAN_TIMEOUT` | No | Seconds to wait for a rescan to finish (default: `300`). On timeout the previous result is used and the Note says so |
| `polyswarm_download_sample` | `POLYSWARM_DOWNLOAD_SAMPLE` | No | **Stores LIVE MALWARE in OpenCTI.** Download the sample for a File PolySwarm holds and create an Artifact from it (default: `false`). Spends PolySwarm download quota |
| `polyswarm_download_max_size_mb` | `POLYSWARM_DOWNLOAD_MAX_SIZE_MB` | No | Largest sample, in MB, that will be downloaded (default: `20`) |
| `polyswarm_pivot_imphash_max` | `POLYSWARM_PIVOT_IMPHASH_MAX` | No | Max other files with the same imphash imported per enriched file (default: `0` = off, range 0 to 100, e.g. `10`). Each enriched file with an imphash costs one extra search. Imported files are labelled `polyswarm-pivot-result` and never pivot again |
| `polyswarm_pivot_ttp_max` | `POLYSWARM_PIVOT_TTP_MAX` | No | Max files imported per enriched Attack-Pattern (default: `0` = off, range 0 to 100, e.g. `10`). Any value above 0 adds `Attack-Pattern` to the connector scope. Use with `CONNECTOR_AUTO=false` only (skipped when auto is on) |
| `polyswarm_yara_hunt_enabled` | `POLYSWARM_YARA_HUNT_ENABLED` | No | Hunt YARA Indicators in PolySwarm (default: `false`). **Writes to your PolySwarm account and spends hunt quota.** Adds `Indicator` to the scope. |
| `polyswarm_yara_hunt_window_days` | `POLYSWARM_YARA_HUNT_WINDOW_DAYS` | No | How many days back a hunt reaches: `30`, `60`, `90` or `180` (default: `30`) |
| `polyswarm_yara_hunt_timeout` | `POLYSWARM_YARA_HUNT_TIMEOUT` | No | Seconds to wait for a hunt before reporting it as still running (default: `300`, minimum `60`) |
| `polyswarm_yara_hunt_max_results` | `POLYSWARM_YARA_HUNT_MAX_RESULTS` | No | Max matched files imported per hunt (default: `50`) |
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

Optional pivots (both off by default, because each one spends PolySwarm API
lookups):

- Imphash pivot, `POLYSWARM_PIVOT_IMPHASH_MAX` above 0: when PolySwarm reports a
  PE imphash for the file being enriched, the connector searches PolySwarm for
  other files with the same imphash and imports up to that many as file
  observables (SHA-256), each linked to the enriched file with `related-to`,
  plus a Note naming the shared imphash. The imphash is the one the connector
  already reads for network IOC extraction; if `POLYSWARM_IOC_ENABLED` is off,
  it is read with one extra lookup. A shared imphash is a pivot, not proof that
  two files are related.
- Technique pivot, `POLYSWARM_PIVOT_TTP_MAX` above 0: enriching an
  Attack-Pattern that has a MITRE ATT&CK id (`x_mitre_id`, or a MITRE external
  reference) searches the PolySwarm metadata index for files whose sandbox
  reports list that technique, and imports up to that many as file observables
  with a `related-to` relationship (file to Attack-Pattern), plus a Note. The
  index search uses `cape_sandbox_v2.ttp` and `triage_sandbox_v0.ttp`. The
  dedicated IOC search by technique (`search_by_ioc` with `ttp`) returned no
  results for any technique tried, so it is not used. `Attack-Pattern` is added
  to the connector scope only when this setting is above 0. Without an ATT&CK
  id, nothing is sent.

Warnings:

- Do not use the technique pivot with `CONNECTOR_AUTO=true`. A MITRE ATT&CK
  import creates hundreds of Attack-Patterns, and each would trigger a search.
  When the helper reports auto-enrichment is on, the connector skips the
  technique pivot (Attack-Patterns are still left untouched).
- Files imported by either pivot are labelled `polyswarm-pivot-result`, and a
  file with that label is never pivoted again, so auto-enrichment can't follow
  the pivots outward level after level. Remove the label from a file if you do
  want it pivoted.
- Each pivot spends PolySwarm lookups from your quota. Keep the limits small.

Both pivots only search: nothing is submitted, scanned or uploaded. Objects
they create carry the same markings as the source entity.

Private, reserved, shared (`100.64.0.0/10`), loopback, link-local and
multicast IPs (including IPv4-mapped IPv6 forms and non-canonical IPv4 forms
such as `127.1` or `2130706433`), internal domains (single label, `.local`,
`.internal`, `.lan`, `.corp`, `.home.arpa`, `.localhost`) and URLs containing
a username or password are skipped and never sent to PolySwarm. Observables
carrying a marking the connector can't resolve to a TLP are also skipped,
unless `CONNECTOR_MAX_TLP` is `TLP:RED`.

Notes, Indicators, relationships and related file observables created for a
URL, domain or IP carry the same markings as the source observable.

#### Rescanning stale hashes (off by default)

By default the connector reads the latest scan PolySwarm already has. Set
`POLYSWARM_RESCAN_OLDER_THAN_DAYS` to a number of days (for example `30`) and,
for a file hash PolySwarm already holds, it asks PolySwarm to rescan the sample
when either:

- the latest scan is older than that many days, or
- PolySwarm has the sample but no completed scan (a scan that is still running
  is left to finish, not repeated).

The connector then waits up to `POLYSWARM_RESCAN_TIMEOUT` seconds (default
`300`) and enriches from the new result. If the rescan does not finish in time,
or fails, it enriches from the previous result and the Note has a "Rescan"
section saying so (after a quota error it also lists the account quota). Nothing is uploaded: the
rescan is of the copy PolySwarm already holds, and a hash PolySwarm does not
know is never rescanned. At most one rescan runs per enrichment, after the
result to use is chosen, in the community that result came from. With
`POLYSWARM_COMMUNITY=private` both communities are searched first, so a stale
copy in one community is not rescanned when the other holds a fresh one. The
age tested is that of the scan the enrichment would otherwise use. If PolySwarm
holds the sample with no completed scan and the rescan fails or times out, the
Note says that instead of "Hash Not Found".

Each rescan spends PolySwarm scan quota, which is why this is off. A rescan
also holds the enrichment for up to the timeout, so keep `CONNECTOR_AUTO=false`
or a low day limit on busy instances.

#### Downloading the sample as an Artifact (off by default)

> WARNING: this stores a live malware sample in your OpenCTI file storage.
> Anyone with access to the Artifact, and any other connector or export that
> reads Artifacts, can obtain the file. Turn it on only if your OpenCTI
> deployment is meant to hold malware (restricted access, isolated storage, no
> automatic export or scanning of uploads that could execute it). It also
> spends PolySwarm download quota.

With `POLYSWARM_DOWNLOAD_SAMPLE=true`, when you enrich a File (StixFile)
observable that PolySwarm holds, the connector downloads the sample and creates
an Artifact observable with the file content and its MD5, SHA-1 and SHA-256
hashes, plus a `related-to` relationship from the Artifact to the File. The
Artifact carries the same markings (TLP and others) as the File, is labelled
`polyswarm:live-malware-sample` and its description says it is a live malware
sample. The Artifact can then be used by other connectors, such as a sandbox
connector.

- Samples larger than `POLYSWARM_DOWNLOAD_MAX_SIZE_MB` (default `20`) are not
  stored. When PolySwarm reports the size the check happens before the
  download; otherwise the download is aborted as soon as the bytes received
  pass the limit.
- Size matters twice: the Artifact travels base64 encoded in one bundle, so a
  20 MB sample is about 27 MB on the wire and in the connector's memory. Raise
  the limit with care, and check your OpenCTI and RabbitMQ message size limits.
- If OpenCTI already has an Artifact with the file's SHA-256, nothing is
  downloaded; the existing Artifact is linked to the File with `related-to`.
- A sandbox connector with auto-enrichment on (for example
  `CONNECTOR_AUTO=true` on PolySwarm Sandbox) will detonate each new Artifact
  this creates. That spends sandbox quota and runs the malware in the sandbox,
  so decide on purpose whether the two connectors should be chained.
- The Artifact is created only if the downloaded bytes hash to the SHA-256
  PolySwarm reported.
- A skipped or failed download never stops the enrichment. The Note has a
  "Sample Download" section saying what happened.
- Only File observables are downloaded. Artifact observables already hold their
  file.
- The sample is held in the connector's memory while it is processed. No file
  is written inside the connector container.
### YARA hunting (off by default)

> **Warning.** With `POLYSWARM_YARA_HUNT_ENABLED=true`, enriching a YARA
> Indicator **creates a historical hunt in the PolySwarm account of the API key
> and spends hunt quota**. The hunt stays in that account (it can be deleted
> there). The YARA rule text is sent to PolySwarm. Leave this off unless you
> want that, and keep `CONNECTOR_AUTO=false` so only Indicators you choose are
> hunted.

When enabled, `Indicator` is added to the connector scope and only Indicators
whose pattern type is `yara` are handled. Any other Indicator is ignored
quietly. For a YARA Indicator the connector:

1. Compiles the rule locally when a YARA library is already installed in the
   image (none is added by the connector). Otherwise PolySwarm validates the
   rule when the hunt is created, and its error is reported in the note.
2. Starts a PolySwarm historical hunt with the rule and the window set in
   `POLYSWARM_YARA_HUNT_WINDOW_DAYS`, then polls its status until it finishes
   or `POLYSWARM_YARA_HUNT_TIMEOUT` seconds pass. The enrichment worker waits
   while it polls, so on a busy queue keep the timeout modest.
3. Imports up to `POLYSWARM_YARA_HUNT_MAX_RESULTS` matched files as file
   observables with their hashes, each linked from the Indicator with a
   `related-to` relationship.
4. Adds one Note on the Indicator with the hunt id, the window, the rule name,
   the number of matches PolySwarm reports, the number imported and, for the
   first three files, the first five matched strings PolySwarm returns.

Hunts are slow and the enrichment worker handles one message at a time, so the
default wait is short (`POLYSWARM_YARA_HUNT_TIMEOUT=300`). If the hunt is still
running at the timeout, the Note says so and gives the hunt id. The hunt keeps
running in PolySwarm. **Enrich the Indicator again later** to import the
matches of a slow hunt: the connector finds the hunt it already made for that
rule (in its saved state, then in the hunts of the account, which it names
`OpenCTI <rule name> <rule digest>`), and reads its results instead of starting
another hunt. A hunt that already finished is reused the same way, so enriching
the same rule again never creates a second hunt. Once the earlier hunt is older than its window
(30 days for a 30 day window), the next enrichment starts a fresh hunt and the
Note says so. To hunt sooner, delete the earlier hunt in PolySwarm first. A hunt that failed or
was cancelled is not reused. A hunt PolySwarm ends at its result cap (status
`LIMITED`) is imported like a finished one, and the Note says the match count
is a lower bound. Syncing YARA Indicators to a live ruleset is not part of this
feature.

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
| Attack-Pattern (only when `POLYSWARM_PIVOT_TTP_MAX` > 0) | Files whose sandbox reports list the technique, Note |

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
| `related-to`     | Enriched file (imphash pivot) | Other file  | n/a        |
| `related-to`     | File (technique pivot) | Attack Pattern     | n/a        |
| `related-to`     | YARA Indicator        | File (hunt match)   | n/a        |
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
- **Rescan (opt-in).** With `POLYSWARM_RESCAN_OLDER_THAN_DAYS` above 0, the SHA-256 of a sample PolySwarm already holds is sent to ask PolySwarm to rescan its own copy. This spends scan quota in the community that holds the sample. No file content is sent.
- **Sample download (opt-in).** With `POLYSWARM_DOWNLOAD_SAMPLE=true`, the SHA-256 of a File PolySwarm holds is sent to download the sample, and the sample is then stored in OpenCTI as an Artifact. This brings live malware into your OpenCTI storage (see [Usage](#usage)) and spends download quota. Nothing about the file leaves your environment, because it flows from PolySwarm to you.
- **Community.** Lookups are made in the community set in `POLYSWARM_COMMUNITY`. With `POLYSWARM_COMMUNITY=private`, each lookup is made in your private community and also in the public `default` community.
- **TLP.** Observables above `CONNECTOR_MAX_TLP` are never sent.
- **Malware profiles (opt-in).** With `POLYSWARM_POLYKG_API_URL` set, the detected malware family name is sent to that URL, together with your PolySwarm API key for authentication.
- **Account quota.** Once an hour the connector reads your account's plan and quotas from PolySwarm. Only your API key is sent; nothing from OpenCTI is.
- **Pivots (opt-in, off by default).** With `POLYSWARM_PIVOT_IMPHASH_MAX` above 0, the file's imphash (a 32 character hash of its import table, as reported by PolySwarm) is sent back to PolySwarm as a search value. With `POLYSWARM_PIVOT_TTP_MAX` above 0, the MITRE ATT&CK id of an enriched Attack-Pattern (for example `T1486`) is sent as a search value. Nothing else about the file or the Attack-Pattern is sent, and Attack-Patterns without an ATT&CK id are never sent. Both are searches, so each one spends API lookups from your quota.
- **YARA hunting (opt-in).** With `POLYSWARM_YARA_HUNT_ENABLED=true`, the full YARA rule text of each Indicator you enrich is sent to PolySwarm, and a historical hunt is created in your PolySwarm account (it spends hunt quota and stays in the account until you delete it). Indicators above `CONNECTOR_MAX_TLP`, and Indicators carrying a marking the connector can't resolve to a TLP (unless `CONNECTOR_MAX_TLP` is `TLP:RED`), are never sent. Nothing is sent for non-YARA Indicators.
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
