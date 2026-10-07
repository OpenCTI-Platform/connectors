# OpenCTI Rösti Connector

| Status    | Date | Comment |
|-----------|------|---------|
| Community | -    | -       |

[Rösti](https://rosti.dev) (*Repackaged Öpen Source Threat Intelligence*) reads public threat reports from hundreds of security vendors, researchers and CERTs and turns them into machine-readable intelligence: IOCs, YARA rules, MITRE ATT&CK references and CVEs. Every IOC is checked against about 30 allowlists and gets a false-positive risk rating.

This connector brings that corpus into OpenCTI. Each Rösti report becomes an OpenCTI report that links to the original publication and contains its indicators, observables, YARA rules, ATT&CK objects and vulnerabilities, ready for detection, hunting and enrichment.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
  - [Docker deployment](#docker-deployment)
  - [Manual deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
  - [What is imported](#what-is-imported)
  - [IOC types](#ioc-types)
  - [Grouped IOCs](#grouped-iocs)
  - [Scores](#scores)
  - [Updates and removed IOCs](#updates-and-removed-iocs)
  - [Data quality checks](#data-quality-checks)
- [Debugging](#debugging)
- [Additional information](#additional-information)

## Introduction

On every run the connector asks the Rösti API for reports that were published or changed since its last run, oldest change first, and sends one STIX 2.1 bundle per report. What you get in OpenCTI:

- **Reports** with the original title, publication date, publisher, authors and links to the original article and to `rosti.dev/reports/<id>`.
- **Indicators and observables** for 19 IOC types, scored by their false-positive risk, labelled with the Rösti tags and flagged for detection when Rösti marks them as IDS-ready. IOCs that describe the same thing, such as the MD5, SHA-1 and SHA-256 of one file, are combined into one observable and one indicator.
- **YARA rules** as YARA indicators, checked to compile in OpenCTI.
- **MITRE ATT&CK** techniques, mitigations, groups, campaigns and software, merged with the objects of OpenCTI's MITRE ATT&CK connector.
- **CVEs** as vulnerabilities.

Use cases: block and detect infrastructure from fresh public reporting, hunt with YARA rules, and see which reports mention an actor, technique or vulnerability.

## Installation

### Requirements

- OpenCTI Platform >= 7.261002.0
- A Rösti API key: <https://rosti.dev/api>
- Rösti API version 2 (`https://api.rosti.dev/v2`). The connector supports all features of Rösti API v2.10.0.
- Recommended: the [MITRE ATT&CK connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/mitre), needed to link ATT&CK software (see [What is imported](#what-is-imported))

## Configuration variables

The connector is configured with environment variables or with a `config.yml` file (see [`config.yml.sample`](config.yml.sample)). The complete list, generated from the code, is in [`__metadata__/CONNECTOR_CONFIG_DOC.md`](__metadata__/CONNECTOR_CONFIG_DOC.md).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                |
|---------------|------------|-----------------------------|-----------|--------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.           |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The token of the connector's OpenCTI user. |

### Base connector environment variables

| Parameter       | config.yml      | Docker environment variable | Default | Mandatory | Description                                    |
|-----------------|-----------------|-----------------------------|---------|-----------|------------------------------------------------|
| Connector ID    | id              | `CONNECTOR_ID`              |         | Yes       | A unique `UUIDv4` for this connector instance. |
| Connector Name  | name            | `CONNECTOR_NAME`            | Rösti   | No        | Name shown in OpenCTI.                         |
| Log Level       | log_level       | `CONNECTOR_LOG_LEVEL`       | error   | No        | `debug`, `info`, `warn` or `error`.            |
| Duration Period | duration_period | `CONNECTOR_DURATION_PERIOD` | PT1H    | No        | Time between two runs (ISO 8601 duration).     |

### Connector extra parameters environment variables

| Parameter      | config.yml     | Docker environment variable | Default                    | Mandatory | Description                                                                 |
|----------------|----------------|-----------------------------|----------------------------|-----------|-----------------------------------------------------------------------------|
| API key        | api_key        | `ROSTI_API_KEY`             |                            | Yes       | Your Rösti API key.                                                         |
| API base URL   | api_base_url   | `ROSTI_API_BASE_URL`        | `https://api.rosti.dev/v2` | No        | Only change for testing.                                                    |
| Import since   | import_since   | `ROSTI_IMPORT_SINCE`        | `P30D`                     | No        | First run only: how far back to import (ISO 8601 date or duration).        |
| Import IOCs    | import_iocs    | `ROSTI_IMPORT_IOCS`         | true                       | No        | Import IOCs as indicators and observables.                                  |
| Import YARA    | import_yara    | `ROSTI_IMPORT_YARA`         | true                       | No        | Import YARA rules.                                                          |
| Import MITRE   | import_mitre   | `ROSTI_IMPORT_MITRE`        | true                       | No        | Link MITRE ATT&CK objects to reports.                                       |
| Import CVEs    | import_cve     | `ROSTI_IMPORT_CVE`          | true                       | No        | Import CVEs as vulnerabilities.                                             |
| IOC types      | ioc_types      | `ROSTI_IOC_TYPES`           | all                        | No        | Comma-separated list of Rösti IOC types, e.g. `domain,ip,url,sha256`.      |
| IDS only       | ids_only       | `ROSTI_IDS_ONLY`            | false                      | No        | Only import IOCs that Rösti flags as suitable for detection.               |
| Max risk level | max_risk_level | `ROSTI_MAX_RISK_LEVEL`      | 5                          | No        | Skip IOCs with a higher false-positive risk (0 = nothing found, 5 = very high). |
| Default score  | default_score  | `ROSTI_DEFAULT_SCORE`       | 50                         | No        | Score of IOCs without risk information.                                     |
| TLP            | tlp_level      | `ROSTI_TLP_LEVEL`           | clear                      | No        | TLP marking applied to every imported object.                               |

## Deployment

### Docker deployment

Build the image:

```shell
docker build . -t opencti/connector-rosti:latest
```

Fill in the `ChangeMe` values in [`docker-compose.yml`](docker-compose.yml), then start the connector:

```shell
docker compose up -d
```

### Manual deployment

Create `config.yml` from [`config.yml.sample`](config.yml.sample) and replace the `ChangeMe` values. Then install the dependencies (preferably in a virtual environment) and start the connector from the `src` directory:

```shell
pip3 install -r src/requirements.txt
cd src
python3 main.py
```

## Usage

The connector runs on its own every `CONNECTOR_DURATION_PERIOD`. To import again from the start, go to *Data → Ingestion → Connectors* in OpenCTI, open the Rösti connector and reset its state; the next run starts again at `ROSTI_IMPORT_SINCE`.

## Behavior

### What is imported

| Rösti                   | OpenCTI                                                                              |
|-------------------------|--------------------------------------------------------------------------------------|
| Report                  | Report (`threat-report`) linking to the original article and `rosti.dev/reports/<id>` |
| IOC                     | Indicator and observable, linked with `based-on`                                     |
| IOCs with one `entity_ref` | Combined: one File, or one indicator over URL, domain and IP (see [Grouped IOCs](#grouped-iocs)) |
| IOC false-positive risk | Score of the indicator and observable (see [Scores](#scores))                        |
| IOC tags                | Labels; also the indicator type (e.g. `proxy` → anonymization)                       |
| IOC `ids` flag          | Indicator "detection" flag                                                           |
| YARA rule               | Indicator with pattern type `yara`                                                   |
| MITRE technique         | Attack Pattern, merged with OpenCTI's ATT&CK data by ATT&CK ID                       |
| MITRE mitigation        | Course of Action, merged by ATT&CK ID                                                |
| MITRE group / campaign  | Intrusion Set / Campaign, merged by name                                             |
| MITRE software          | The existing Malware or Tool of that name                                            |
| CVE                     | Vulnerability                                                                        |

ATT&CK "software" is either malware or a tool, which are different entity types in OpenCTI. The connector links whichever of the two already exists in OpenCTI, normally created by the MITRE ATT&CK connector, so it never creates a duplicate of the wrong type. Without that connector, software references are not linked. Tactics and data sources are not imported.

### IOC types

| Rösti type                                  | Observable                                       | Indicator pattern                       |
|---------------------------------------------|--------------------------------------------------|-----------------------------------------|
| `ip`, `cidr`                                | IPv4-Addr / IPv6-Addr                            | `[ipv4-addr:value = '…']`               |
| `domain`                                    | Domain-Name                                      | `[domain-name:value = '…']`             |
| `url`                                       | Url                                              | `[url:value = '…']`                     |
| `email`                                     | Email-Addr                                       | `[email-addr:value = '…']`              |
| `md5`, `sha1`, `sha256`, `sha512`, `ssdeep` | File (hash)                                      | `[file:hashes.'SHA-256' = '…']`         |
| `sha224`                                    | none (OpenCTI cannot identify a file by SHA-224) | `[file:hashes.'SHA-224' = '…']`         |
| `filename`                                  | File (name)                                      | `[file:name = '…']`                     |
| `filepath`                                  | File (name), full path in the description        | `[file:name = '…']`                     |
| `mutex`                                     | Mutex                                            | `[mutex:name = '…']`                    |
| `user-agent`                                | User-Agent                                       | `[user-agent:value = '…']`              |
| `blockchain`                                | Cryptocurrency-Wallet                            | `[cryptocurrency-wallet:value = '…']`   |
| `ip:port`, `domain:port`                    | IP / Domain, port in the description             | pattern on the IP / domain              |
| `domain:ip`                                 | Domain and IP, linked with `resolves-to`         | pattern on the domain                   |
| `port`                                      | not imported (a bare port is not an indicator)   |                                         |

### Grouped IOCs

Rösti marks IOCs that belong together with the same `entity_ref`, for example the hashes and the file name of one dropped file, or the URL, domain and IP of one C2 server. The connector combines them:

| Group contains                                     | OpenCTI                                                                                                   |
|----------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| Hashes, file names, file paths                     | **One File** with all hashes (SHA-224 only in the pattern), the first name as name and the others as additional names; **one indicator** `[file:hashes.'MD5' = '…' OR file:hashes.'SHA-1' = '…']` (only names in the pattern when there is no hash) |
| URLs, domains, IPs (incl. `domain:port`, `ip:port`, `domain:ip`, `cidr`) | Their observables, the domain `resolves-to` each IP (only when the group has one domain), and **one indicator** `[url:value = '…'] OR [domain-name:value = '…'] OR [ipv4-addr:value = '…']` |
| Anything else                                      | Imported as single IOCs                                                                                    |

- File and network IOCs of the same group are never mixed: each part is combined on its own, and a part with only one IOC is imported as a single IOC.
- The indicator is `based-on` every observable of the group. It is named after the strongest hash (SHA-256 first) or after the URL, domain or IP, in that order.
- Tags of the group are merged and the first comment is used. Score, detection flag and date are the most cautious ones: the lowest score, detection only if every IOC is IDS-ready, and the earliest date. Observables keep their own score, except the combined File.
- OpenCTI merges files that share a hash, so a file imported earlier with only its MD5 becomes the same file once the group adds its SHA-1 and SHA-256.
- A group with two different hashes of the same kind cannot be one file; its IOCs are imported as single IOCs and a warning is logged.
- The IOCs of a group come one after the other from the API. When a group is at the end of a page of IOCs, the connector waits for the next page before converting it, so groups are never cut in two.

### Scores

A higher false-positive risk gives a lower OpenCTI score:

| Risk level | Meaning                       | Score                       |
|------------|-------------------------------|-----------------------------|
| 0          | nothing found                 | 80                          |
| -1         | informational (e.g. dyndns)   | 70                          |
| 1          | small                         | 60                          |
| 2          | moderate                      | 50                          |
| 3          | medium                        | 40                          |
| 4          | high                          | 25                          |
| 5          | very high                     | 10                          |
| –          | no risk information           | `ROSTI_DEFAULT_SCORE` (50)  |

### Updates and removed IOCs

- **Incremental.** The connector remembers the last report it sent and only asks for newer changes. Rösti timestamps have one-second resolution, so each run starts one second earlier and skips what it already sent.
- **Updated reports.** When a report changes, including when an IOC is added or removed, it is sent again as a whole. The report replaces its contents in OpenCTI instead of only adding to them, so removed IOCs disappear from the report. Objects added to a Rösti report by hand in OpenCTI are removed on its next update.
- **Removed IOCs.** The indicator itself stays in OpenCTI because other reports may contain it; OpenCTI's decay rules lower its score over time until it is revoked. The same applies when IOCs become a group: the report then contains the combined indicator, and the earlier single indicators stay in OpenCTI outside the report.
- **Interruptions, rate limits and quota.** The checkpoint advances after every report. Server errors and `429` responses with a `Retry-After` (the Rösti API sends at most 60 seconds) are retried. When the quota of the API key is used up, the API answers `429` with a "quota exceeded" problem; the run then ends with a warning showing the API's message (`detail`, and `reset` if present), and the first run after the reset continues where it stopped.
- **API usage.** One request per page of 100 reports, plus per report one for the report, one per 1,000 IOCs and one for its YARA rules if it has any.

### Data quality checks

OpenCTI rejects indicators and observables it considers malformed. The connector applies the same checks first, so one bad value never breaks an import:

- **YARA rules** are compiled with yara-python 4.5.4, the version OpenCTI uses. A rule that relies on a helper rule from the same report gets the helper added to its pattern. Rules that still do not compile are skipped and logged with a plain-language explanation of every problem found (for example a missing `{`, undefined or unused strings, a missing `import`). Rules of reports marked `hide_yara` are not imported. The check can also be run on its own: `python src/connector/test_yara_rule.py rule.yar`.
- **Domains, email addresses and file hashes** are validated with OpenCTI's own rules; invalid values are skipped and logged. In a group, only the invalid IOC is skipped; the rest of the group is still combined.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` to see every skipped IOC and every MITRE software entry that could not be linked. Skipped YARA rules are logged as warnings at any level. Each run is also listed with its status under *Data → Ingestion → Connectors* in OpenCTI.

## Additional information

- Rösti website and API keys: <https://rosti.dev>
- API documentation: <https://registry.scalar.com/@bin/apis/rosti-api@latest>
- Contact: <rosti@bin.re>
