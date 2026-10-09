# Google Threat Intelligence Enhanced Connector

| Status    | Date       | Comment                                                                     |
| --------- | ---------- | ---------------------------------------------------------------------------- |
| Community | 2026-08-18 | Enhanced fork of Filigran's official "Google Threat Intelligence" connector |

---

## About this connector

This is a heavily modified fork of Filigran's official **Google Threat Intelligence** connector
(Filigran Verified, last verified 2025-06-20 -
[source](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/google-ti-feeds)).
The base connector imports Reports and derives Campaigns, Threat Actors, Malware Families, and
Vulnerabilities only as objects nested inside a Report.

This **Enhanced** edition keeps that same reports-first pipeline but adds:

- Direct/standalone import of Campaigns, Threat Actors, Malware Families, and Vulnerabilities,
  independent of whether a Report references them.
- Origin filtering per entity type, not just for Reports.
- A choice of indicator scoring strategy: GTI's own verdict/severity, or raw AV detection ratio.
- Optional relationship-building between IOCs and the threat actors/malware a report already links
  them to.
- Automatic Malware --exploits--> Vulnerability relationships when a report contains both.

See [What's new in the Enhanced edition](#whats-new-in-the-enhanced-edition) below for details and
the configuration variables each one introduces.

---

## Introduction

Google Threat Intelligence Feeds Connector ingests threat intelligence from the Google Threat Intel API and feeds it into the OpenCTI solution, focusing -for now- on STIX entities tied to report objects.
It extracts and transforms relevant data types report, location, sector, malware, intrusion-set, attack-pattern, vulnerability, and raw IOCs delivering structured, and ingest that in an intelligible way into OpenCTI.

Most of the data is extracted from the reports, but some entities are extracted from the report's relationships.
More information can be found in the [Google Threat Intel API documentation](https://gtidocs.virustotal.com/reference/reports).

> This connector requires a Google Threat Intel API key to function. You can obtain one by signing up for the Google Threat Intel service.5
> Reports Analysis are only available to users with the Google Threat Intelligence (Google TI) Enterprise or Enterprise Plus licenses.5

---

## Quick start

Here’s a high-level overview to get the connector up and running:

1. **Set environment variables**:
        - inside `docker-compose.yml`
2. **Pull and run the connector** using Docker:
```bash
        docker compose up -d
```

---

## Installation

### Requirements

- OpenCTI Platform version **6.6.10** or higher
- Docker & Docker Compose (for containerized deployment)
- Valid GTI API credentials (token)

---

## Configurations Variables

### OpenCTI Configuration

Below are the required parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker Environment Variable | Mandatory | Description                                    |
| ---           | ---        | ---                         | ---       | ---                                            |
| OpenCTI URL   | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.               |
| OpenCTI Token | `token`    | `OPENCTI_TOKEN`             | Yes       | The API token for authenticating with OpenCTI. |

### Connector Configuration

Below are the required parameters you can set for running the connector:

| Parameter                 | config.yml        | Docker Environment Variable | Default                   | Mandatory | Description                                                                 |
| ---                       | ---               | ---                         | ---                       | ---       | ---                                                                         |
| Connector ID              | `id`              | `CONNECTOR_ID`              | /                         | Yes       | A unique `UUIDv4` identifier for this connector.                            |

Below are the optional parameters you can set for running the connector:

| Parameter                 | config.yml        | Docker Environment Variable | Default                                                                                                      | Mandatory | Description                                                                 |
| ---                       | ---               | ---                         | ---                                                                                                          | ---       | ---                                                                         |
| Connector Name            | `name`            | `CONNECTOR_NAME`            | Google Threat Intel Feeds                                                                                    | No        | The name of the connector as it will appear in OpenCTI.                     |
| Connector Scope           | `scope`           | `CONNECTOR_SCOPE`           | report,location,identity,attack_pattern,domain,file,ipv4,ipv6,malware,sector,intrusion_set,url,vulnerability | No        | The scope of data to import, a list of Stix Objects.                        |
| Connector Log Level       | `log_level`       | `CONNECTOR_LOG_LEVEL`       | error                                                                                                         | No        | Sets the verbosity of logs. Options: `debug`, `info`, `warn`, `error`.      |
| Connector Duration Period | `duration_period` | `CONNECTOR_DURATION_PERIOD` | PT2H                                                                                                         | No        | The duration period between two schedule for the connector.                 |
| Connector TLP Level       | `tlp_level`       | `CONNECTOR_TLP_LEVEL`       | AMBER+STRICT                                                                                                 | No        | The TLP level for the connector. Options: `WHITE`, `GREEN`, `AMBER`, `RED`. |
| Connector Queue Threshold | `queue_threshold` | `CONNECTOR_QUEUE_THRESHOLD` | 500                                                                                                          | No        | The threshold for the queue size before processing.                         |

### GTI Configuration

Below are the required parameters you'll need to set for Google Threat Intel:

| Parameter                             | config.yml              | Docker Environment Variable | Default    | Mandatory | Description                                                 |
| ---                                   | ---                     | ---                         | ---        | ---       | ---                                                         |
| Google Threat Intel API Key           | `gti.api_key`           | `GTI_API_KEY`               |            | Yes       | The API key for Google Threat Intel.                        |

Below are the optional parameters you can set for Google Threat Intel:

| Parameter                                 | config.yml              | Docker Environment Variable | Default                           | Mandatory | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ---                                       | ---                     | ---                         | ---                               | ---       | ---                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Google Threat Intel Import Start Date     | `gti.import_start_date` | `GTI_IMPORT_START_DATE`     | P1D                               | No        | The start date for importing data from Google Threat Intel.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Google Threat Intel API URL               | `gti.api_url`           | `GTI_API_URL`               | https://www.virustotal.com/api/v3 | No        | The API URL for Google Threat Intel.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Google Threat Intel Toggle Import Reports | `gti.import_reports`    | `GTI_IMPORT_REPORTS`        | True                              | No        | If set to `True`, the connector will import reports from Google Threat Intel.                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Google Threat Intel Report Types          | `gti.report_types`      | `GTI_REPORT_TYPES`          | All                               | No        | The types of reports to import from Google Threat Intel. Can be a string separated by comma for multiple values. Valid values are: `All`, `Actor Profile`, `Country Profile`, `Cyber Physical Security Roundup`, `Event Coverage/Implication`, `Industry Reporting`, `Malware Profile`, `Net Assessment`, `Network Activity Reports`, `News Analysis`, `OSINT Article`, `Patch Report`, `Strategic Perspective`, `TTP Deep Dive`, `Threat Activity Alert`, `Threat Activity Report`, `Trends and Forecasting`, `Weekly Vulnerability Exploitation Report` |
| Google Threat Intel Report Origins        | `gti.origins`           | `GTI_ORIGINS`               | All                               | No        | The origin of the reports to import from Google Threat Intel. Can be a string separated by comma for multiple values. Valid values are: `All`, `partner`, `crowdsourced`, `google threat intelligence`.                                                                                                                                                                                                                                                                                                                                                   |
| Google Threat Intel Toggle Import Campaigns | `gti.import_campaigns` | `GTI_IMPORT_CAMPAIGNS`      | False                              | No        | If set to `True`, imports Campaigns directly from Google Threat Intel, independent of whether a Report references them. |
| Google Threat Intel Toggle Import Threat Actors | `gti.import_threat_actors` | `GTI_IMPORT_THREAT_ACTORS` | False                          | No        | If set to `True`, imports Threat Actors directly from Google Threat Intel, independent of whether a Report references them. |
| Google Threat Intel Toggle Import Malware Families | `gti.import_malware_families` | `GTI_IMPORT_MALWARE_FAMILIES` | False                    | No        | If set to `True`, imports Malware Families directly from Google Threat Intel, independent of whether a Report references them. |
| Google Threat Intel Toggle Import Vulnerabilities | `gti.import_vulnerabilities` | `GTI_IMPORT_VULNERABILITIES` | False                     | No        | If set to `True`, imports Vulnerabilities directly from Google Threat Intel, independent of whether a Report references them. |
| Google Threat Intel Campaign Origins       | `gti.campaign_origins`  | `GTI_CAMPAIGN_ORIGINS`      | google threat intelligence         | No        | Origin filter applied when `GTI_IMPORT_CAMPAIGNS` is enabled. Same valid values as Report Origins. |
| Google Threat Intel Threat Actor Origins   | `gti.threat_actor_origins` | `GTI_THREAT_ACTOR_ORIGINS` | google threat intelligence      | No        | Origin filter applied when `GTI_IMPORT_THREAT_ACTORS` is enabled. Same valid values as Report Origins. |
| Google Threat Intel Malware Family Origins | `gti.malware_family_origins` | `GTI_MALWARE_FAMILY_ORIGINS` | google threat intelligence    | No        | Origin filter applied when `GTI_IMPORT_MALWARE_FAMILIES` is enabled. Same valid values as Report Origins. |
| Google Threat Intel Vulnerability Origins  | `gti.vulnerability_origins` | `GTI_VULNERABILITY_ORIGINS` | google threat intelligence     | No        | Origin filter applied when `GTI_IMPORT_VULNERABILITIES` is enabled. Same valid values as Report Origins. |
| Google Threat Intel Indicator Scoring      | `gti.indicator_scoring` | `GTI_INDICATOR_SCORING`     | gti_derived                        | No        | How indicator `x_opencti_score` is computed. `gti_derived`: from GTI's own verdict + severity (`gti_assessment`). `average_detection`: from the AV engine detection ratio (`last_analysis_stats`). |
| Google Threat Intel Enrich IOCs with Threat Actors/Malware | `gti.enrich_iocs_with_threat_actors_and_malware` | `GTI_ENRICH_IOCS_WITH_THREAT_ACTORS_AND_MALWARE` | False | No | If set to `True`, creates relationships between a report's IOCs and the threat actors/malware families that same report contains. |
| Google Threat Intel IOC Enrichment Threshold | `gti.ioc_enrichment_threshold` | `GTI_IOC_ENRICHMENT_THRESHOLD` | 250                       | No        | Skips the IOC enrichment relationships above for any report with more IOCs than this (fetching per-IOC detail on very large reports is what's expensive). Set to `0` to disable the threshold and always enrich. |

> 📅 The `import_start_date` can be formatted as a time zone aware datetime or as a duration (e.g., `1970-01-01T00:00:00+03:00` for January, 1st 1970 at 3AM in Timezone +3H or `P3D` for 3 days ago relative to NOW UTC).

## Development

## What's new in the Enhanced edition

### Direct entity import

`GTI_IMPORT_CAMPAIGNS`, `GTI_IMPORT_THREAT_ACTORS`, `GTI_IMPORT_MALWARE_FAMILIES`, and
`GTI_IMPORT_VULNERABILITIES` (all default `False`) each run their own fetch against the GTI API,
independent of `GTI_IMPORT_REPORTS`. In the base connector, these entity types only ever appear as
objects referenced by an imported Report - so anything GTI knows about that isn't attached to a
Report you've imported is missed. Turning these toggles on closes that gap.

### Per-entity-type origin filtering

`GTI_ORIGINS` still controls Report origins as before. `GTI_CAMPAIGN_ORIGINS`,
`GTI_THREAT_ACTOR_ORIGINS`, `GTI_MALWARE_FAMILY_ORIGINS`, and `GTI_VULNERABILITY_ORIGINS` apply the
same `All` / `partner` / `crowdsourced` / `google threat intelligence` filter independently to each
directly-imported entity type, so (for example) you can keep only Google-authored actor/malware data
while still taking Reports from every origin.

### Configurable indicator scoring

`GTI_INDICATOR_SCORING` picks how `x_opencti_score` is computed for indicators:
- `gti_derived` (default): derived from GTI's own verdict + severity assessment.
- `average_detection`: derived from the AV engine detection ratio instead.

### IOC enrichment relationships

When `GTI_ENRICH_IOCS_WITH_THREAT_ACTORS_AND_MALWARE` is enabled, every IOC in a report is related
to every threat actor/malware family that same report already contains - no extra GTI API calls are
made, since it reuses data already fetched for the report. `GTI_IOC_ENRICHMENT_THRESHOLD` (default
`250`) skips this step for reports with more IOCs than the threshold, since fetching per-IOC detail
on very large reports is what's expensive, not the relationship step itself. Set to `0` to disable
the threshold.

### Malware -> Vulnerability relationships

When a report contains both malware families and vulnerabilities, an `exploits` relationship is
created automatically between each malware/CVE pair found in that report. There's no separate
toggle for this - it runs whenever both entity types are present in the same report.

## Contributing

Please refer to [CONTRIBUTING.md](CONTRIBUTING.md).

### Running the Connector Locally

The connector is designed to be run in a Docker container. However, if you want to run it locally for development purposes, you can do so by following these steps:

1/ Clone the connector's repository:
```bash
    git clone <repository-url>
```

2/ Navigate to the connector directory
```bash
    cd external-import/google-ti-feeds
```

3/ Ensure you are using a Python 3.12 version

4/ Install the required dependencies:
```bash
pip install -e .[all]
```
(for legacy purposes, you can also use `pip install -r requirements.txt` that is in editable mode.)

5a/ Set the required variables:
In your shell:
```bash
        export OPENCTI_URL=<your_opencti_url>
        ...
```
OR sourcing a `.env` file:
```bash
        source .env
```
OR creating a "config.yml" file at the root of the project:
```yaml
       opencti:
           url: <your_opencti_url>
       ...
```

6/ Run the connector:
```bash
       GoogleTIFeeds
```
  or ignore 5b and run it with the environment variable:
```bash
      GoogleTIFeeds
```
 or by launching the main.py:
```bash
      python connector/__main__.py
```
 or by launching the module:
```bash
      python -m connector
```

### Commit

Note: Your commits must be signed using a GPG key. Otherwise, your Pull Request will be rejected.

### Linting and formatting

Added to the connectors linteing and formatting rules, this connector is developed and checked using ruff and mypy to ensure the code is type-checked and linted.
The dedicated configurations are set in the `pyproject.toml` file.
You can run the following commands to check the code:

```bash
   python -m isort .
   python -m black . --check
   python -m ruff check .
   python -m mypy .
   python -m pip_audit .
```

### Testing

To run the tests, you can use the following command:
```bash
    python -m pytest -svv
```
