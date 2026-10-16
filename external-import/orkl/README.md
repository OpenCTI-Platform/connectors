# OpenCTI ORKL Connector

## Table of Contents

- [OpenCTI ORKL Connector](#opencti-orkl-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [ORKL connector extra parameters environment variables](#orkl-connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Behavior](#behavior)
    - [Incremental sync](#incremental-sync)
    - [Data mapping](#data-mapping)
  - [Resilience and rate limiting](#resilience-and-rate-limiting)
  - [Known caveats](#known-caveats)
    - [Duplicate threat actors](#duplicate-threat-actors)
    - [Tools may actually be malware](#tools-may-actually-be-malware)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

[ORKL](https://orkl.eu) is a free, community-driven library of publicly
released Cyber Threat Intelligence reports, sponsored by Sunet. It aggregates
PDF and web reports from major sources (MITRE, MISP Galaxy, ETDA, Secureworks,
and others), extracting full text and tagging the threat actors referenced in
each report. At the time of writing, ORKL holds roughly 29,000 library entries
and tracks around 1,900 threat actors.

This connector periodically polls the ORKL REST API and imports library
entries into OpenCTI as STIX **Reports**. Threat actors tagged on each report
are created as **Intrusion Sets** (or **Threat Actors**, depending on
configuration) and referenced from the report's `object_refs`; their
associated tools can optionally be imported as STIX **Tool** objects.

The ORKL API requires **no authentication** — it is a free, public service,
so there is no API key or token to configure.

## Installation

### Requirements

- OpenCTI Platform `>= 6.8.0`
- No ORKL account or API key required

## Configuration variables

There are a number of configuration options, which are set either in
`docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|------------------------------|-----------|-------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                       |
| OpenCTI Token | token      | `OPENCTI_TOKEN`              | Yes       | The default admin token set in the OpenCTI platform.   |

### Base connector environment variables

| Parameter               | config.yml      | Docker environment variable  | Default        | Mandatory | Description                                                            |
|--------------------------|-----------------|-------------------------------|-----------------|-----------|--------------------------------------------------------------------------|
| Connector ID             | id              | `CONNECTOR_ID`                 |                 | Yes       | A unique `UUIDv4` identifier for this connector instance.                |
| Connector Name           | name            | `CONNECTOR_NAME`               | `ORKL`          | No        | Name of the connector.                                                    |
| Connector Scope          | scope           | `CONNECTOR_SCOPE`              | `orkl`          | No        | The scope or type of data the connector is importing.                    |
| Log Level                | log_level       | `CONNECTOR_LOG_LEVEL`          | `error`         | No        | Determines the verbosity of logs: `debug`, `info`, `warn`, `warning`, or `error`. |
| Duration Period          | duration_period | `CONNECTOR_DURATION_PERIOD`    | `P1D`           | No        | The period of time to await between two runs of the connector (ISO 8601 duration). |

### ORKL connector extra parameters environment variables

| Parameter                        | config.yml                        | Docker environment variable            | Default                     | Mandatory | Description                                                                                                                                     |
|-----------------------------------|-------------------------------------|-------------------------------------------|-------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| API base URL                      | `orkl.api_base_url`                 | `ORKL_API_BASE_URL`                        | `https://orkl.eu/api/v1`      | No        | Base URL of the ORKL API.                                                                                                                          |
| Import start date                 | `orkl.import_start_date`            | `ORKL_IMPORT_START_DATE`                   | `P30D`                        | No        | How far back to look on the first import (ISO 8601 duration, e.g. `P30D` for 30 days, `P6M` for 6 months). Ignored on subsequent runs, which resume from the last run's cutoff. |
| TLP level                         | `orkl.tlp_level`                    | `ORKL_TLP_LEVEL`                           | `clear`                       | No        | TLP marking level applied to created STIX objects. Valid values: `clear`, `white`, `green`, `amber`, `amber+strict`, `red`.                        |
| Threat actor as Intrusion Set     | `orkl.threat_actor_as_intrusion_set`| `ORKL_THREAT_ACTOR_AS_INTRUSION_SET`       | `true`                        | No        | Create ORKL threat actors as Intrusion Sets (`true`) or as Threat Actors (`false`).                                                                |
| Ingest tools                      | `orkl.ingest_tools`                 | `ORKL_INGEST_TOOLS`                        | `false`                       | No        | Create Tool entities from the threat actors' tools. Disabled by default: the ORKL feed does not distinguish malware from tools, so enabling this will create Tool entities for what are in fact malware families. |

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-orkl:latest .
```

Configure the connector in `docker-compose.yml` (see `docker-compose.yml` in
this directory for the full sample), then start it:

```bash
docker compose up -d
```

### Manual Deployment

1. Create `config.yml` based on `config.yml.sample`.

2. Install dependencies:

```bash
pip3 install -r requirements.txt
```

3. Start the connector:

```bash
cd src && python3 main.py
```

## Behavior

### Incremental sync

ORKL exposes no server-side date filter on its `/library/entries` endpoint.
Instead, the connector pages through entries sorted by `updated_at`
descending (`order_by=updated_at&order=desc`) and stops as soon as it reaches
an entry whose `updated_at` is older than or equal to its cutoff — since
entries arrive newest-first, everything after that point is guaranteed to be
older too, so pagination (and the underlying HTTP requests) stop immediately.

The cutoff is:

- the connector's last successful run time minus a small safety overlap (a few
  minutes), on every run after the first. The overlap re-scans the boundary so
  entries updated while a run is still in progress cannot be permanently missed;
  re-processing them is harmless because every STIX id is deterministic;
- `import_start_date` before now (default 30 days), on the very first run.

Tombstoned entries (`deleted_at` set) are skipped but do not stop pagination,
since live entries may still follow them in the same page. Entries with an
unparseable `updated_at` are kept and processed rather than used to stop the
run, since their position relative to the cutoff can't be determined.

### Data mapping

| ORKL field                                                    | STIX object / property                                                     |
|-----------------------------------------------------------------|--------------------------------------------------------------------------|
| Library entry                                                    | `Report`                                                                   |
| `name`                                                            | `Report.name`                                                              |
| `description`                                                    | `Report.description`                                                       |
| best available *stable* date among publication/file-creation/file-modification/`ts_*` timestamps (update timestamps are excluded so a re-fetch never changes the id) | `Report.publication_date` (falls back to a fixed 1970-01-01 sentinel to keep the STIX id stable if no usable date exists) |
| `labels`                                                          | `Report.labels`                                                            |
| entry id                                                          | `Report` external reference (`source_name: "ORKL"`, `external_id`, and a `url` pointing at the ORKL API entry) |
| `sha1_hash`                                                       | `Report` external reference (SHA-1 of the source file)                    |
| `references[]` (original publisher links)                        | `Report` external references, one per usable URL                         |
| `files.pdf` / `files.text` / `files.img`                          | `Report` external references (`source_name: "ORKL Archive"`)              |
| `threat_actors[].main_name`                                      | `Intrusion Set.name` or `Threat Actor.name` (per `threat_actor_as_intrusion_set`) |
| `threat_actors[].other_aliases`                                  | `aliases` on the actor entity                                             |
| `threat_actors[].source_name` / `source_id`                      | actor external reference (`source_name: source_id or "ORKL"`, `external_id: source_name`) |
| `threat_actors[].tools[]` (only if `ingest_tools` is `true`)      | `Tool.name`, plus a `uses` `Relationship` from the actor to the tool       |

All emitted objects carry the ORKL `OrganizationAuthor` identity as
`created_by_ref` and the configured `tlp_level` as their marking. Every
actor, tool and relationship produced for an entry is also referenced from
that entry's `Report.object_refs`.

## Resilience and rate limiting

ORKL publishes no documented numeric request quota. Its own guidance
(https://orkl.eu/llms.txt) only asks clients to send a descriptive
`User-Agent` so its maintainers can identify and contact misbehaving clients.
The connector honors that by sending a fixed `User-Agent` on every request,
and additionally applies a defensive two-layer strategy so it never puts
undue load on this free community service:

- **Proactive throttling** — every outgoing request is paced at a
  self-imposed rate of **1 request/second**, regardless of how the server
  responds.
- **Reactive backoff** — on `408`/`429`/`5xx` responses, the client retries
  with an exponential backoff (factor `2.0`), honoring any `Retry-After`
  header, up to **5 attempts** before the run fails cleanly.
- Requests time out after **60 seconds**.
- Pagination is capped at **1000 pages** (at the API-capped page size of 100
  entries, roughly 10x a full backfill of ORKL's current ~29,500 entries) as
  a last-resort circuit breaker against a misbehaving or static/cached
  server; it also stops early if a page returns the same entry IDs as the
  previous one (a sign `offset` is not being honored).

These values are **in-code constants, not connector configuration options**.
They are deliberately not exposed as settings, to protect a free service
that the whole community relies on from being overloaded by
misconfiguration.

## Known caveats

### Duplicate threat actors

ORKL aggregates threat actor data from multiple upstream sources (MITRE,
MISP Galaxy, ETDA, and others), so a single report can list the **same**
real-world actor several times under slightly different names. For example,
one entry has been observed listing `SaintBear` (MISP Galaxy), `Ember Bear`
(MITRE), `Saint Bear` (MITRE) and `SaintBear` again (ETDA), all sharing the
alias `UAC-0056`.

The connector emits these **as-is** — it does not attempt fuzzy or
heuristic deduplication of actors across sources. Operators should expect to
merge such duplicates manually in OpenCTI.

### Tools may actually be malware

ORKL's `tools[]` field on a threat actor does **not** distinguish genuine
tools from malware families. Observed values mix legitimate tools (e.g.
PsExec, Mimikatz) with malware (e.g. Remcos, gh0st RAT). Because of this,
`ingest_tools` is **disabled by default**: enabling it will create STIX
`Tool` objects for entries that are, in reality, malware.

## Debugging

Enable verbose logging:

```env
CONNECTOR_LOG_LEVEL=debug
```

## Additional information

- This connector has not been tested against a live OpenCTI platform; it is
  validated with unit tests only (`external-import/orkl/tests`).
- **Reference**: [ORKL](https://orkl.eu) / [ORKL API](https://orkl.eu/api/v1)
