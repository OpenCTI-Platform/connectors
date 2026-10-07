# OpenCTI Darkmoon Connector

Table of Contents

- [OpenCTI Darkmoon Connector](#opencti-darkmoon-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Exposing the Darkmoon findings to the connector](#exposing-the-darkmoon-findings-to-the-connector)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Behavior](#behavior)
    - [STIX mapping](#stix-mapping)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

[Darkmoon](https://github.com/ASCIT31/Dark-Moon) is an open-source (GPLv3) autonomous
AI penetration-testing CLI developed by ASC-IT. During a campaign the Darkmoon OSS
engine records every finding it validates (with its evidence) to a JSON findings store
on disk, and generates a local Markdown report from that store.

This **external-import** connector reads that on-disk JSON findings store and imports
each campaign into OpenCTI as structured threat intelligence: one `Vulnerability` per
finding, a `Note` carrying the finding's evidence (reproduction commands, raw HTTP
request/response, logs, remediation), an optional `Attack Pattern` for the finding's
MITRE ATT&CK technique, all grouped into a `Report` for the campaign.

The connector reads **local files only**. It does **not** connect to any Darkmoon web
dashboard or HTTP API, and it does not use any Darkmoon Pro-only feature (the web
dashboard, the PDF export and the remediation pull-request agent are Pro features and
are out of scope for this connector).

Typical use case: a team running Darkmoon OSS scans (locally or in CI) wants its
validated findings centralised in OpenCTI alongside the rest of its vulnerability and
threat intelligence, with full evidence preserved for triage.

## Installation

### Requirements

- Python >= 3.11 (3.12 recommended)
- OpenCTI Platform >= 6.8.12
- A Darkmoon OSS data directory reachable by the connector (see
  [Exposing the Darkmoon findings to the connector](#exposing-the-darkmoon-findings-to-the-connector))
- [`pycti`](https://pypi.org/project/pycti/) and
  [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors/tree/master/connectors-sdk)
  (installed from `src/requirements.txt`)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml`
(for Docker) or in `config.yml` (for manual deployment).

Find all the configuration variables available here:
[Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md).

_The `opencti` and `connector` options in `docker-compose.yml` and `config.yml` are the
same as for any other connector. For more information, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

### OpenCTI environment variables

| Parameter     | config.yml       | Docker environment variable | Mandatory | Description                                          |
|---------------|------------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | `opencti.url`    | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | `opencti.token`  | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml                   | Docker environment variable   | Default                              | Mandatory | Description                                                            |
|-----------------|------------------------------|-------------------------------|--------------------------------------|-----------|-----------------------------------------------------------------------|
| Connector ID    | `connector.id`               | `CONNECTOR_ID`                | /                                    | Yes       | A unique `UUIDv4` identifier for this connector instance.             |
| Connector Name  | `connector.name`             | `CONNECTOR_NAME`              | `Darkmoon`                           | No        | Name of the connector.                                                |
| Connector Scope | `connector.scope`            | `CONNECTOR_SCOPE`             | `Vulnerability,Note,Report,Attack-Pattern` | No  | The entity types the connector imports.                               |
| Log Level       | `connector.log_level`        | `CONNECTOR_LOG_LEVEL`         | `error`                              | No        | One of `debug`, `info`, `warn`, `error`.                              |
| Duration Period | `connector.duration_period`  | `CONNECTOR_DURATION_PERIOD`   | `PT1H`                               | No        | ISO-8601 duration between two runs of the connector.                  |

### Connector extra parameters environment variables

| Parameter             | config.yml                        | Docker environment variable           | Default      | Mandatory | Description                                                                                                                      |
|-----------------------|-----------------------------------|---------------------------------------|--------------|-----------|--------------------------------------------------------------------------------------------------------------------------------|
| Export path           | `darkmoon.export_path`            | `DARKMOON_EXPORT_PATH`                | /            | Yes       | Path, inside the connector container, to the mounted Darkmoon OSS data directory (must contain `campaigns/` and `vulnerabilities/`). |
| TLP level             | `darkmoon.tlp_level`              | `DARKMOON_TLP_LEVEL`                  | `red`        | No        | TLP marking applied to every created object. One of `clear`, `white`, `green`, `amber`, `amber+strict`, `red`.                  |
| Import since          | `darkmoon.import_since`           | `DARKMOON_IMPORT_SINCE`              | `P30D`       | No        | Initial checkpoint: import campaigns dated since this absolute date (e.g. `2026-01-01T00:00:00Z`) or relative period (e.g. `P30D`). |
| Import findings       | `darkmoon.import_findings`        | `DARKMOON_IMPORT_FINDINGS`           | `true`       | No        | Enable/disable the import of findings.                                                                                          |
| Import attack patterns| `darkmoon.import_attack_patterns` | `DARKMOON_IMPORT_ATTACK_PATTERNS`    | `true`       | No        | Create an Attack Pattern (and a relationship to the vulnerability) for each finding carrying a MITRE ATT&CK technique id.        |

## Exposing the Darkmoon findings to the connector

Darkmoon OSS writes its findings store to the engine's data directory. In the reference
Darkmoon `docker-compose.yml`, the host directory `darkmoon-settings` is bound to
`/root/.local/share/opencode`, so on the host the store is laid out as:

```
darkmoon-settings/
├── campaigns/<campaign_id>.json         # one campaign per file
├── vulnerabilities/<campaign_id>.json   # the findings for that campaign
└── targets.json                         # the assessed targets (optional)
```

Mount that host directory into the connector container (read-only is enough) and point
`DARKMOON_EXPORT_PATH` at the mount point, for example:

```yaml
    volumes:
      - /path/to/darkmoon-settings:/opt/darkmoon-data:ro
    environment:
      - DARKMOON_EXPORT_PATH=/opt/darkmoon-data
```

## Deployment

### Docker Deployment

The connector's Python dependencies are declared in `src/requirements.txt`. `pycti`
is not listed there directly: it is pulled in transitively by `connectors-sdk`, which
pins the compatible `pycti` version, so there is nothing to edit for it here. Run the
connector against an OpenCTI platform of a compatible version by aligning the
`opencti/connector-darkmoon` image tag with your OpenCTI release.

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-darkmoon:latest
```

Set the environment variables in `docker-compose.yml`, then start the container:

```shell
docker compose up -d
```

### Manual Deployment

Create a `config.yml` based on the provided `config.yml.sample`, replacing the
`ChangeMe` values with your environment's configuration.

Install the dependencies (preferably in a virtual environment) and run the connector:

```shell
cd src
pip install -r requirements.txt
python main.py
```

## Behavior

On each run the connector:

1. Lists the campaign files under `<export_path>/campaigns/`.
2. Keeps only campaigns dated strictly after the last imported campaign (first run uses
   `import_since`), so each run only imports new campaigns.
3. For each selected campaign, loads its findings from
   `<export_path>/vulnerabilities/<campaign_id>.json` and resolves its target from
   `targets.json`.
4. Converts the campaign to STIX 2.1 objects and sends them to OpenCTI.
5. Persists the date of the most recent imported campaign as the new checkpoint.

A malformed campaign, a single malformed finding, or a campaign with no parseable date
is logged and skipped rather than aborting the whole run. A finding whose optional
`evidence` object is missing or empty is still imported; its evidence note simply falls
back to a short placeholder when nothing was recorded.

### STIX mapping

| Darkmoon field(s)                                                                 | STIX 2.1 object / property                                                                                                       |
|-----------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `finding` (each)                                                                  | `Vulnerability`                                                                                                                  |
| `finding.cve` (when a valid `CVE-…`) else `finding.title`                          | `Vulnerability.name` (the finding title becomes an `alias` when the CVE is used as the name)                                     |
| `finding.description`, `finding.category`, `finding.endpoint`                      | `Vulnerability.description`                                                                                                      |
| `CWE-\d+` pattern detected in `title`/`category`/`description`                      | `Vulnerability.cwe_ids` (only when actually present — Darkmoon findings have no dedicated CWE field)                             |
| `finding.cvss_score`                                                              | `Vulnerability.cvss_v3_base_score` and `Vulnerability.score` (0–100)                                                             |
| `finding.cvss_vector`                                                             | `Vulnerability.cvss_v3_vector_string`                                                                                            |
| `finding.severity`                                                                | `Vulnerability.cvss_v3_base_severity` (critical/high/medium/low) and a `severity:<level>` label                                 |
| `finding.cve`                                                                     | external reference (`source_name: cve`) when a valid CVE id                                                                      |
| `finding.mitre_attack_id`                                                         | external reference (`source_name: mitre-attack`) + optional `Attack Pattern` (`mitre_id`) linked with a `related-to` relationship |
| `finding.iso27001_control`                                                        | external reference (`source_name: ISO 27001`)                                                                                    |
| `finding.id`, `finding.discovered_by_agent`                                       | external reference (`source_name: Darkmoon`) for traceability                                                                    |
| `finding.evidence` (commands, raw request/response, logs, explanation), `finding.remediation` | `Note` (linked to the vulnerability) holding the full evidence as Markdown                                          |
| `finding.status`                                                                  | `status:<status>` label on the vulnerability                                                                                     |
| `campaign` (each)                                                                 | `Report` grouping all the campaign's vulnerabilities, notes, attack patterns and relationships                                   |
| `campaign.date`                                                                   | `Report.published`                                                                                                               |
| `campaign.executive_summary`, `campaign.methodology`, `campaign.stats`            | `Report.description`                                                                                                             |

All created objects are attributed to a `Darkmoon` organization author and carry the
configured TLP marking.

> **Note on severity and exploitability:** Darkmoon qualifies each finding as
> `EXPLOITED` / `CONFIRMED` / `UNCONFIRMED` through the agent's adversarial self-review.
> This status is agent-asserted, not machine-verified; it is preserved on the imported
> objects (status label and evidence note) so analysts can triage against the evidence.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for verbose logging. Common issues:

- *Nothing is imported*: check that `DARKMOON_EXPORT_PATH` points to a directory that
  contains a `campaigns/` subdirectory, and that the campaigns are dated after
  `import_since` / the last checkpoint.
- *Export path does not exist*: the connector raises on a missing `export_path`; verify
  the volume mount.

## Additional information

- This connector is built and maintained by **ASC-IT**, the team behind Darkmoon.
- Darkmoon (OSS CLI, GPLv3): https://github.com/ASCIT31/Dark-Moon
- Darkmoon findings may contain privacy-gateway placeholders (e.g. tokenised hosts)
  depending on the user's Darkmoon privacy configuration; the connector imports the
  values exactly as stored on disk and does not attempt to de-anonymise them.
