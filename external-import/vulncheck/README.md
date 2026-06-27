# OpenCTI VulnCheck Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

The VulnCheck Connector for OpenCTI is a standalone Python process designed to
integrate VulnCheck's extensive threat intelligence into the OpenCTI platform.
VulnCheck aggregates data from a wide range of sources, providing actionable
insights into vulnerabilities, exploits, ransomware activity, threat actors,
and more.

## Table of Contents

<!--toc:start-->
- [OpenCTI VulnCheck Connector](#opencti-vulncheck-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration](#configuration)
    - [OpenCTI Configuration](#opencti-configuration)
    - [VulnCheck Connector Configuration](#vulncheck-connector-configuration)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
    - [Data Sources](#data-sources)
    - [Data Volume](#data-volume)
  - [Development](#development)
  - [Debugging](#debugging)
  - [Additional Information](#additional-information)
<!--toc:end-->

## Introduction

The VulnCheck Connector retrieves and translates data from VulnCheck into STIX
objects. It supports feeds for Known Exploited Vulnerabilities (KEVs), NVD-2,
ransomware, threat actors, exploits, botnets, initial access indicators, and IP
intelligence. Each data source is processed to create structured, meaningful
objects like vulnerabilities, malware, infrastructure, and relationships.

The VulnCheck Connector helps organizations enrich their threat intelligence
within OpenCTI by automating the ingestion of curated vulnerability and threat
actor data. This enables:

- **Proactive Risk Management**: Identify and prioritize vulnerabilities
actively exploited in the wild, improving patch management and defensive
measures.
- **Threat Actor Profiling**: Gain insights into ransomware groups, botnets,
and advanced persistent threat (APT) groups with detailed metadata and
associated tactics.
- **Contextual Analysis**: Link vulnerabilities to threat actors, exploits, and
malicious infrastructure to build a comprehensive understanding of potential
threats.
- **Enhanced Situational Awareness**: Integrate multi-source threat
intelligence into a unified platform, enabling more informed decision-making
for security operations and incident response teams.

## Installation

### Requirements

- OpenCTI Platform >= 6.6.11
- A Valid [VulnCheck](https://www.vulncheck.com/) API Key

## Configuration

There are several configuration options, which can be set either in
`docker-compose.yml` (for Docker deployments) or in `config.yml` (for manual
deployments).

### OpenCTI Configuration

Below are the parameters you'll need to set for OpenCTI:

| Parameter         | config.yml | Docker Environment Variable | Mandatory | Description                                  |
|-------------------|------------|-----------------------------|-----------|----------------------------------------------|
| OpenCTI URL       | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.            |
| OpenCTI Token     | `token`    | `OPENCTI_TOKEN`             | Yes       | The API token for authenticating with OpenCTI. |

### VulnCheck Connector Configuration

Below are the parameters you'll need to set for running the connector:

| Parameter                 | config.yml        | Docker Environment Variable          | Default                                                                                                                     | Mandatory   | Description                                                                   |
| -----------------         | ----------------  | ------------------------------------ |-----------------------------------------------------------------------------------------------------------------------------| ----------- | ----------------------------------------------------------------------------- |
| API Key                   | `api_key`         | `VULNCHECK_API_KEY`        | None                                                                                                                        | Yes         | The API key for authenticating with VulnCheck's API.                          |
| Connector ID              | `id`              | `CONNECTOR_ID`                       | /                                                                                                                           | Yes         | A unique `UUIDv4` identifier for this connector.                              |
| Connector Type            | `type`            | `CONNECTOR_TYPE`                     | EXTERNAL_IMPORT                                                                                                             | No          | Specifies the type of connector. Should always be set to `EXTERNAL_IMPORT`.   |
| Connector Name            | `name`            | `CONNECTOR_NAME`                     | VulnCheck                                                                                                                   | No          | The name of the connector as it will appear in OpenCTI.                       |
| Connector Scope           | `scope`           | `CONNECTOR_SCOPE`                    | None                                                                                                                        | Yes         | Required. Comma-separated STIX object types to import, e.g. `vulnerability,malware,threat-actor,infrastructure,location,ip-addr,indicator,external-reference,attack-pattern,course-of-action,x-mitre-data-source,report` (add `software` only if prepared for the volume — see [Data Volume](#data-volume)). |
| Connector Duration period | `duration_period` | `CONNECTOR_DURATION_PERIOD`          | PT1H                                                                                                                        | No          | The time period for which to fetch data. Default is 24 hours.                 |
| Log Level                 | `log_level`       | `CONNECTOR_LOG_LEVEL`                | info                                                                                                                        | No          | Sets the verbosity of logs. Options: `debug`, `info`, `warn`, `error`.        |
| API Base URL              | `api_base_url`    | `VULNCHECK_API_BASE_URL`   | <https://api.vulncheck.com/v3>                                                                                                | No          | The base URL for the VulnCheck API (e.g., `https://api.vulncheck.com/v3`).    |
| Data Sources              | `data_sources`    | `VULNCHECK_DATA_SOURCES`   | vulncheck-kev,nist-nvd2 | No          | Comma-separated data sources to collect. Available: `botnets,epss,exploits,initial-access,ipintel,nist-nvd2,ransomware,snort,suricata,threat-actors,vulncheck-kev,vulncheck-nvd2`. |
| NVD2 Pull History         | `nvd2_pull_history`        | `VULNCHECK_NVD2_PULL_HISTORY`        | false | No | First run only: when `true`, pull the full NVD2 history (no date filter). When `false`, the first run is bounded by `nvd2_max_date_range`. |
| NVD2 Max Date Range       | `nvd2_max_date_range`      | `VULNCHECK_NVD2_MAX_DATE_RANGE`      | 120   | No | First run only: how many days back (last-modified) to pull when not pulling full history. |
| NVD2 Last Mod Start Date  | `nvd2_last_mod_start_date` | `VULNCHECK_NVD2_LAST_MOD_START_DATE` | None  | No | Optional `YYYY-MM-DD` override for a manual backfill. Normally unset — runs are incremental via connector state. |
| NVD2 Last Mod End Date    | `nvd2_last_mod_end_date`   | `VULNCHECK_NVD2_LAST_MOD_END_DATE`   | None  | No | Optional `YYYY-MM-DD` override for a manual backfill. Normally unset (defaults to now). |

> [!NOTE]
> The `nist-nvd2` and `vulncheck-nvd2` sources ingest incrementally: each run
> requests only CVEs modified since the previous successful run (tracked in
> connector state via the VulnCheck index API's `lastModStartDate` /
> `lastModEndDate` parameters). The `nvd2_*` settings above only shape the very
> first run (empty state) and enable manual backfills — they do not need to be
> set for normal operation.
>
> `vulncheck-nvd2` is an enriched superset of `nist-nvd2` (same CVEs plus attack
> patterns, mitigations, data sources and CPEs). If **both** are listed in
> `data_sources`, the connector prefers `vulncheck-nvd2` and skips the redundant
> `nist-nvd2` ingest.

> [!IMPORTANT]
> The connector-specific environment variables were renamed from
> `CONNECTOR_VULNCHECK_*` to `VULNCHECK_*` (and the `config.yml` section from
> `connector_vulncheck:` to `vulncheck:`) when migrating to `connectors-sdk`.
> The old `CONNECTOR_VULNCHECK_*` names still work but emit a deprecation warning —
> update your deployment to the new names.

## Deployment

### Docker Deployment

Dependencies are declared in `pyproject.toml` (`pycti` is pulled in transitively
by `connectors-sdk`), so no manual version pinning is required before building.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configurations for your environment. Then, start the docker
container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables)
with the appropriate configurations for you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install .
```

Then, start the connector from vulncheck/src:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use,
and should update automatically at a regular interval specified in your
`docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of
entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's
state and force a new download of data by re-running the connector.

> [!NOTE]
> The VulnCheck Connector is designed to fetch data once every 24 hours. This
> approach ensures the connector remains efficient and minimizes the risk of
> overloading the VulnCheck API or the OpenCTI platform.

## Behavior

The VulnCheck Connector integrates VulnCheck's threat intelligence data into
the OpenCTI platform, converting raw data from various feeds into structured
STIX objects. Below is an overview of its behavior and functionality:

### Data Sources

The connector retrieves data from VulnCheck's API and imports it into OpenCTI
as STIX objects. The following types of data are processed:

- **VulnCheck KEV**: Populates OpenCTI with vulnerabilities actively exploited
in the wild, focusing on high-priority risks.
- **NVD-2**: Imports vulnerability information enriched with CVSS scores,
descriptions, and associated CPEs. Additionally includes MITRE ATT&CK
enrichments such as attack patterns (CAPEC and MITRE techniques), course of
actions (mitigations), and data sources for detection. (VulnCheck NVD-2 is
available for subscribers, NIST NVD-2 is available for community users)
- **Exploits**: Maps exploits to vulnerabilities and generates corresponding
Malware objects in OpenCTI.
- **EPSS Enrichment**: Adds vulnerabilities along with their EPSS scores and
percentiles, helping prioritize remediation efforts based on exploit
probability.
- **Ransomware**: Creates Malware objects for ransomware families, linking them
to associated vulnerabilities. When `report` is in scope, each ransomware family
is wrapped in a STIX Report for browsability in OpenCTI's Reports view.
- **Threat Actors**: Adds Threat Actor objects with external references,
relationships to targeted vulnerabilities, and descriptive metadata. When `report`
is in scope, each threat actor entry is wrapped in a STIX Report.
- **Botnets**: Ingests infrastructure data associated with botnet activities
and links them to targeted vulnerabilities. When `report` is in scope, each
botnet entry is wrapped in a STIX Report.
- **Initial Access Indicators**: Maps CPEs and vulnerabilities leveraged for
initial access tactics.
- **IP Intelligence**: Adds infrastructure and IP-related intelligence,
including countries and related vulnerabilities.
- **Snort/Suricata Rules**: Ingests Snort and Suricata rules as Indicators.

> [!NOTE]
> Source availability depends on your VulnCheck API key tier. Before each run the
> connector checks whether each configured source's endpoint is reachable for your
> key and **skips** (with a warning) any it cannot access, so you can list sources
> your key doesn't include without the run failing.

### Data Volume

> [!WARNING]
> Users should be aware of the significant resource impact when enabling the
> `software` scope for the VulnCheck Connector.
>
> For the data sources that include `software` objects in their scope
> (`vulncheck-nvd2,nist-nvd2,initial-access`), this creates a very large number
> of STIX objects and relationships between the `software` and `vulnerability`
> objects. Please ensure your deployed OpenCTI environment is clustered and
> prepared to handle this large volume of data before appending it to the
> `CONNECTOR_SCOPE` in the [connector
> configuration](#vulncheck-connector-configuration)
>
> Individual data sources can be be disabled by removing them from the
> `VULNCHECK_DATA_SOURCES` variable in the [connector
> configuration](#vulncheck-connector-configuration).

One way to separate these large data sources when `software` is in scope, is to create

- Primary Connector:
  - Sources: `botnets,epss,exploits,ipintel,ransomware,snort,suricata,threat-actors,vulncheck-kev`
  - Scope: `vulnerability,malware,threat-actor,infrastructure,location,ip-addr,indicator,external-reference,report`
  - This connector will handle the main threat intelligence data without
  `software`, ensuring timely ingestion.
- Secondary Connector:
  - Sources: `vulncheck-nvd2,nist-nvd2,initial-access` only
  - Scope: `vulnerability,software`
  - This connector will handle `software` data independently, which allows it
    to manage the high data volume without interfering with the ingestion of
    other data sources.

## Development

The connector is laid out as two packages under `src/`: `connector/` (settings,
the connector loop, STIX conversion, and per-source ingestion under
`connector/sources/`) and `vulncheck_client/` (the VulnCheck API client). Sources
are wired up in `connector/sources/registry.py`.

Install the connector with its test/dev extras and run the test suite:

```shell
pip install -e ".[test,dev]"
pytest
```

To add a new data source:

1. Add its name constant to `src/connector/sources/names.py`.
2. Create `src/connector/sources/<source>.py` with a `collect_<source>()` function.
3. Register it in `src/connector/sources/registry.py`.

## Debugging

The connector can be debugged by setting the appropiate log level. Note that
logging messages can be added using
`self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i. e.,
`self.helper.connector_logger.error("An error message")`.

---

## Additional Information

OpenCTI documentation for connectors:

- [OpenCTI Ecosystem](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76)
- [Connectors Deployment](https://docs.opencti.io/latest/deployment/connectors/)
- [Connectors Development](https://docs.opencti.io/latest/development/connectors/)
