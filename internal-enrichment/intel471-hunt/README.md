# OpenCTI Intel 471 Hunter Connector

| Status       | Date | Comment |
|--------------|------|---------|
| Not verified | -    | -       |

Table of Contents

- [OpenCTI Intel 471 Hunter Connector](#opencti-intel-471-hunter-connector)
  - [Description](#description)
  - [Prerequisites](#prerequisites)
    - [Obtaining a Hunter API key](#obtaining-a-hunter-api-key)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
    - [What the connector emits](#what-the-connector-emits)
    - [Entity to Hunter query mapping](#entity-to-hunter-query-mapping)
    - [Cache](#cache)
  - [Debugging](#debugging)
    - [Running without OpenCTI](#running-without-opencti)
  - [Additional information](#additional-information)
    - [Known limitations](#known-limitations)
    - [Testing](#testing)

## Description

[Intel 471 Hunter](https://hunter.cyborgsecurity.io/) (formerly Cyborg Security Hunter) is a library of curated
threat hunt packages: sigma detections shipped alongside the analyst tradecraft needed to run them — runbooks,
mitigation guidance, validation procedures and running analyst notes.

This connector enriches OpenCTI entities with that detection coverage **on demand**. When an analyst triggers
enrichment on a supported entity, the connector queries Hunter with the matching filter (e.g. `actors=TeamPCP`,
`mitre_technique_ids=T1059.007`) and materialises every returned hunt package as a STIX 2.1 **Report**, mirroring
the shape used by Intel 471's intelligence reports.

The Report's `object_refs` — the OpenCTI **Entities** tab — carry the sigma detection as an **Indicator**, all the
context extracted from the hunt (Threat-Actor / Campaign / Malware / Vulnerability / Attack-Pattern / Tool / Sector /
Location) and the relationships connecting them. Analyst runbook, mitigation, validation and running-update Notes
attach to the Report.

### 🔎 Looking for Intel 471 intelligence streams?

This connector covers **detection content** only, and it is an *internal enrichment* connector: it runs when an
analyst asks it to, against one entity at a time.

If what you need is a scheduled feed of Intel 471 intelligence from **Titan or Verity471** — indicators, YARA rules,
intelligence reports, breach alerts, CVEs — use the [Intel 471 Connector v2](../../external-import/intel471_v2/)
instead. The two are complementary and can run side by side: v2 continuously ingests the intelligence, this
connector adds hunt packages to the entities you are investigating.

## Prerequisites

An Intel 471 Hunter subscription and a Hunter API key.

### Obtaining a Hunter API key

> [!IMPORTANT]
> **Hunter credentials are separate from your Verity471 / Titan credentials.** The Cyborg Security (Hunter) API is
> **not yet integrated with the Verity471 API**, and there is a **separate process for obtaining a Hunter key**.
> The Verity471 Client ID and Client Secret used by the
> [Intel 471 Connector v2](../../external-import/intel471_v2/) will **not** authenticate against Hunter, and a Hunter
> API key will not work against Verity471. Expect to hold and rotate two independent credentials until the platforms
> converge.

1. Sign in to the Hunter platform at [https://hunter.cyborgsecurity.io/](https://hunter.cyborgsecurity.io/) with your
   Hunter account.
2. Obtain an API key for your organisation from the Hunter platform.
3. Supply it to the connector as `HUNTER_API_KEY`. The connector sends it to the API as
   `Authorization: API-Key <key>`.

If you do not have Hunter access, or you are unsure which subscription covers it, contact your Intel 471 representative
or sales@intel471.com — Hunter access is provisioned separately from Titan/Verity471 API access.

You can verify a key outside OpenCTI before deploying:

```shell
curl -X GET 'https://api.hunter.cyborgsecurity.io/es/query?indexes=cyborg_usecases&actors=TeamPCP' \
  -H 'accept: application/json' \
  -H 'Authorization: API-Key <your key>'
```

The full `/es/query` parameter specification is published at
[https://api.hunter.cyborgsecurity.io/docs](https://api.hunter.cyborgsecurity.io/docs).

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 7.260824.0
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors/tree/master/connectors-sdk) library matching your OpenCTI version
- An Intel 471 Hunter subscription and API key (see above)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in
`config.yml` (for manual deployment).

_For more information regarding the `opencti` and `connector` options, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter        | config.yml       | Docker environment variable    | Default              | Mandatory | Description                                                                            |
|------------------|------------------|--------------------------------|----------------------|-----------|----------------------------------------------------------------------------------------|
| Connector ID     | id               | `CONNECTOR_ID`                 | /                    | Yes       | A unique `UUIDv4` identifier for this connector instance (generate with `uuidgen`).    |
| Connector Type   | type             | `CONNECTOR_TYPE`               | INTERNAL_ENRICHMENT  | Yes       | Should always be set to `INTERNAL_ENRICHMENT` for this connector.                      |
| Connector Name   | name             | `CONNECTOR_NAME`               | Intel 471 Hunter     | Yes       | Name of the connector.                                                                 |
| Connector Scope  | scope            | `CONNECTOR_SCOPE`              | See note below       | Yes       | The entity types the connector can be triggered on **and** the types it emits.         |
| Connector Auto   | auto             | `CONNECTOR_AUTO`               | false                | No        | `true` enables auto-enrichment on entity creation; `false` requires a manual trigger.  |
| Log Level        | log_level        | `CONNECTOR_LOG_LEVEL`          | error                | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

The default scope is:

```text
Report,Indicator,Note,Intrusion-Set,Threat-Actor,Threat-Actor-Group,Threat-Actor-Individual,Campaign,Attack-Pattern,Vulnerability,Malware,Tool,Sector,Country,Region
```

> [!WARNING]
> **Scope is also an import filter.** For internal-enrichment connectors, OpenCTI applies `CONNECTOR_SCOPE` as a
> type-filter on the *returned* bundle, silently discarding any object whose type is not listed — no error, no log,
> just a ticked work expectation. The scope must therefore include every type the connector **emits** (`Report`,
> `Indicator`, `Note`), not only the types it can be triggered on. Symptom if you get this wrong: entities and
> relationships appear, but the **Report never shows up** (relationship endpoints get back-created, containers do
> not).

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter          | config.yml              | Docker environment variable      | Default                                | Mandatory | Description                                                                                 |
|--------------------|-------------------------|----------------------------------|----------------------------------------|-----------|---------------------------------------------------------------------------------------------|
| API base URL       | api_base_url            | `HUNTER_API_BASE_URL`            | https://api.hunter.cyborgsecurity.io   | No        | Base URL of the Hunter API.                                                                 |
| API key            | api_key                 | `HUNTER_API_KEY`                 | /                                      | Yes       | Hunter API key, sent as `Authorization: API-Key <key>`.                                     |
| UI base URL        | ui_base_url             | `HUNTER_UI_BASE_URL`             | https://hunter.cyborgsecurity.io       | No        | Used to build external references back to the hunt. Leave empty to disable those links.     |
| Indexes            | indexes                 | `HUNTER_INDEXES`                 | cyborg_usecases                        | No        | Hunter index to query.                                                                      |
| Request timeout    | request_timeout_seconds | `HUNTER_REQUEST_TIMEOUT_SECONDS` | 30                                     | No        | HTTP timeout, in seconds, for calls to the Hunter API.                                      |
| Max results        | max_results_per_query   | `HUNTER_MAX_RESULTS_PER_QUERY`   | 100                                    | No        | Maximum number of hunt packages retrieved per query.                                        |
| Cache path         | cache_path              | `HUNTER_CACHE_PATH`              | /opt/connector/cache/cache.json        | No        | Location of the local `(hunt_uuid, last_updated)` cache. See [Cache](#cache).                |
| Cache TTL          | cache_ttl_hours         | `HUNTER_CACHE_TTL_HOURS`         | 24                                     | No        | Lifetime, in hours, of a cache entry.                                                        |
| Max TLP            | max_tlp                 | `HUNTER_MAX_TLP`                 | TLP:AMBER                              | No        | Highest TLP the connector will enrich. Entities above it are refused.                        |

## Deployment

### Docker Deployment

Before building the Docker container, make sure the `pycti` version pinned in `pyproject.toml` matches the version of
OpenCTI you are running.

Build the image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-intel471-hunt:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment, then start the container with the provided `docker-compose.yml`, or integrate it into the global
`docker-compose.yml` file of OpenCTI:

```shell
docker compose up -d
```

> [!WARNING]
> Mount the cache volume on a **dedicated subdirectory** (`/opt/connector/cache`), never on `/opt/connector`. The
> latter is the image `WORKDIR` holding the connector code: a named volume mounted there is seeded once from the
> first image and then shadows the code on every subsequent image update, silently pinning the container to stale
> code. The provided `docker-compose.yml` already does this correctly.

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`, and replace the configuration variables
(especially the "**ChangeMe**" ones) with the appropriate configurations for your environment.

Install the connector and its dependencies (preferably in a virtual environment):

```shell
python3 -m venv .venv && source .venv/bin/activate
pip3 install .
```

Then start the connector from the connector directory:

```shell
python3 -m src
```

Configuration is resolved by connectors-sdk in the order `environment variable` ->
`config.yml` -> default, so any value in `config.yml` can be overridden by its environment
variable.

## Usage

The connector is triggered manually by default (`CONNECTOR_AUTO=false`).

In OpenCTI, open a supported entity — a Threat-Actor, Intrusion-Set, Campaign, Attack-Pattern, Vulnerability,
Malware, Tool, Sector or Location — then open the **Enrichment** panel and launch **Intel 471 Hunter**.

Results appear as:

- **Analysis -> Reports** — one Report per hunt package, with the extracted context on its **Entities** tab and the
  analyst tradecraft in its **Notes**.
- **Observations -> Indicators** — the sigma detection for each hunt package.

Setting `CONNECTOR_AUTO=true` enriches supported entities automatically as they are created. On a busy platform this
generates considerably more Hunter API traffic, so start with manual triggering.

Navigate to **Data -> Ingestion -> Connectors -> Intel 471 Hunter** to observe completed works and works in progress.

**Pro-tip**: Creating a new user and API token for the connector can help you more easily track which STIX2 objects
were created by the connector.

## Behavior

### What the connector emits

For each hunt package returned by the query:

- **1 Report** (`report--<hunt_uuid>`, `report_types=["threat-hunting"]`) — the hunt package itself. Carries the
  title, description, `published` date, `x_opencti_score` (90/60/30 derived from Hunter severity), labels for
  threat categories / kill chains / target OSes, and external references back to the Hunter UI plus every URL in
  `references.{general,analysis,deep_dives,blog_links,malware_samples}`. Its `object_refs` (the **Entities** tab)
  contain the Indicator, every entity below, and the relationships between them.
- **1 Indicator** (`indicator--<hunt_uuid>`) with `pattern_type=sigma`, `pattern=<sigma yaml>`, the severity label
  and score, and a Hunter UI back-link — kept lean, since the context lives on the Report.
- **Notes** attached to the Report: analyst runbook, mitigation recommendations, validation, and one Note per
  `running_analyst_notes` entry (using its `analyst_note_date` / `analyst_note_type`).
- **Attack-Patterns** for every MITRE technique in `mapping.mitre.mitre_attack_payload`, with `kill_chain_phases`
  derived from the tactic list.
- **Intrusion-Sets** for `tags.actors`.
- **Campaigns** for `tags.campaigns`.
- **Malware** for `tags.threat_names`, only when `tags.threat_categories` contains `"Malware"` (otherwise the threat
  name lands as a label `threat:<name>`).
- **Vulnerabilities** for `tags.exploit_or_vulns` and `mapping.exploit_or_vulns`.
- **Tools** for `tags.tools` and `tags.tooling`.
- **Sectors** (Identity, `identity_class=class`) for `tags.target_industries`.
- **Countries** (Location, `x_opencti_location_type=Country`) for `tags.target_countries` and `tags.source_countries`.
- **Regions** (Location, `x_opencti_location_type=Region`) for `tags.target_regions` and `tags.source_regions`.
- **Relationships**: `Indicator --indicates--> {Intrusion-Set, Campaign, Malware, Vulnerability, Attack-Pattern,
  Tool, Sector, Country, Region}`, plus `Intrusion-Set --uses--> Attack-Pattern` when both are present. When the
  enrichment was triggered on an entity, the Indicator also `indicates` that entity, and the entity is added to the
  Report's Entities tab.

The connector identity (`Intel 471 — Hunter`, an organization) is set as `created_by_ref` on every object.
Re-enriching an updated hunt reuses the same `report--` / `indicator--` ids (both keyed on the hunt UUID), so OpenCTI
updates in place rather than creating duplicates.

### Entity to Hunter query mapping

| OpenCTI entity                             | Hunter parameter                                            |
|--------------------------------------------|-------------------------------------------------------------|
| Intrusion-Set / Threat-Actor (any flavour) | `actors`                                                    |
| Campaign                                   | `campaigns`                                                 |
| Attack-Pattern                             | `mitre_technique_ids` (preferred), else `mitre_technique_names` |
| Vulnerability                              | `exploit_or_vulns`                                          |
| Malware                                    | `threat_names`                                              |
| Tool                                       | `tools`                                                     |
| Sector                                     | `target_industries`                                         |
| Country / Location (sub-type Country)      | `target_countries` and `source_countries`                   |
| Region / Location (sub-type Region)        | `target_regions` and `source_regions`                       |

Aliases on the entity are included when present. Entity types outside this table — and generic Locations whose
sub-type Hunter does not model (City, Administrative-Area, Position) — are skipped.

Location triggers fan out to **two separate API calls** (`target_*` and `source_*`) and the connector unions the
results by hunt UUID. Hunter's content authors populate the source-attribution side far more consistently than the
target side, so a single `target_countries=X` call usually returns 0 even for common nation-state actors. The API
ANDs across query parameters within a single call, which is why this cannot be expressed as one request.

### Cache

The connector caches `(hunt_uuid, last_updated)` pairs to disk at `HUNTER_CACHE_PATH`. On repeated enrichments of the
same entity, hunts that have not been updated upstream are skipped. Cache entries also carry a TTL
(`HUNTER_CACHE_TTL_HOURS`, default 24h), so a failed push self-recovers on the next trigger.

The cache is local-file and single-process. Multi-replica deployments need a shared store (e.g. Redis); this is not
implemented yet.

## Debugging

The connector can be debugged by setting the appropriate log level (`CONNECTOR_LOG_LEVEL=debug`).

### Running without OpenCTI

Two scenarios run the connector's logic without an OpenCTI platform attached. Both run from the connector directory
after `pip install -e ".[dev]"`.

**Unit tests** — no network, no API key required:

```shell
pytest
```

**Full pipeline dry run** — live network, real STIX bundle, no OpenCTI. This is the closest thing to a real
enrichment: the same code path the connector takes in production, without OpenCTI on the other end.

```shell
export HUNTER_API_KEY=...

python3 -m src.dry_run \
  --entity-type Threat-Actor-Group \
  --entity-name TeamPCP \
  --out /tmp/teampcp-bundle.json
```

It constructs a fake OpenCTI entity with a deterministic synthesised STIX id, derives the Hunter filter through
`entity_mapper.build_query`, calls the live Hunter API, and builds the STIX bundle exactly as the connector would —
including trigger-entity linking, so you can verify each Indicator points at your synthesised STIX id and that no
duplicate entity is created for the triggering name. Progress goes to stderr; the bundle JSON goes to `--out`, or
stdout if omitted.

More examples:

```shell
# MITRE technique trigger
python3 -m src.dry_run --entity-type Attack-Pattern --entity-name JavaScript --mitre-id T1059.007

# Campaign
python3 -m src.dry_run --entity-type Campaign --entity-name "Shai-Hulud 2.0"

# Vulnerability
python3 -m src.dry_run --entity-type Vulnerability --entity-name CVE-2024-0001
```

Supported `--entity-type` values: `Threat-Actor`, `Threat-Actor-Group`, `Threat-Actor-Individual`, `Intrusion-Set`,
`Campaign`, `Attack-Pattern`, `Vulnerability`, `Malware`, `Tool`, `Sector`, `Country`, `Region`.

## Additional information

### Known limitations

- **`validation_encoded_zip`** (a base64 zip of Atomic Red Team payloads) is intentionally not extracted — the
  connector links out to the Hunter UI for validation artifacts instead.
- **The cache is single-process**, so multi-replica deployments need a shared store.
- **Renames in Hunter** (a changed hunt title or actor name) do not propagate cleanly, because the related entities
  use name-derived deterministic STIX ids.
- **Sigma metadata is normalised before import.** OpenCTI validates every sigma pattern with pySigma and rejects the
  Indicator outright if the rule does not parse. Hunter rules carry metadata pySigma refuses — `status: New`, rule
  `id`s that are not UUIDs, and nested `tags` lists — so the connector drops or coerces those optional keys before
  emitting the Indicator. The `detection` and `logsource` blocks, i.e. what the rule actually matches, are never
  touched. A hunt that ships no sigma rule at all yields a Report with no Indicator rather than a placeholder.

### Testing

```shell
pytest                            # everything (offline, fixture-driven)
pytest tests/test_stix_builder.py # builder tests against the captured fixture
```

The fixture `tests/fixtures/response.json` is a real Hunter capture (9 hunt packages, including the Shai-Hulud 2.0
supply-chain hunts). It exercises every code path: MITRE techniques, actors, campaigns, malware classification and
running analyst notes.
