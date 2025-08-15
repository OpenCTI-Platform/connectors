# OpenCTI CrowdSec External Import Connector

The CrowdSec External Import Connector allows OpenCTI to import IP address threat intelligence from CrowdSec's Cyber Threat Intelligence (CTI) API. This connector enriches IP observables with comprehensive threat data including reputation scores, attack patterns, MITRE techniques, vulnerabilities (CVEs), and behavioral analysis.

Key features:
* **Automated IP threat intelligence import** from CrowdSec CTI API using the `smoke/search` endpoint
* **Rich enrichment** with reputation scores, attack behaviors, MITRE ATT&CK techniques, and CVE information
* **Configurable labeling system** with customizable colors for different threat categories
* **STIX 2.1 compliant** observable creation and indicator generation
* **Relationship mapping** between observables, indicators, attack patterns, and vulnerabilities
* **Performance optimized** with configurable import thresholds and batch processing

Table of Contents

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
  - [OpenCTI environment variables](#opencti-environment-variables)
  - [Base connector environment variables](#base-connector-environment-variables)
  - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
    - [Label Configuration](#label-configuration)
    - [Label Colors](#label-colors)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
  - [Data Enrichment Process](#data-enrichment-process)
  - [Import Strategies](#import-strategies)
- [Debugging](#debugging)
  - [Log Levels](#log-levels)
  - [Common Issues](#common-issues)
- [Additional information](#additional-information)
  - [API Integration Details](#api-integration-details)
  - [Lucene Query Examples](#lucene-query-examples)
  - [STIX 2.1 Compliance](#stix-21-compliance)
  - [Related Connectors](#related-connectors)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Introduction

The CrowdSec External Import Connector integrates with CrowdSec's Cyber Threat Intelligence API to automatically import and enrich IP address observables in OpenCTI. CrowdSec maintains a comprehensive database of malicious IP addresses that have been observed attacking infrastructure across their global network.

This connector retrieves IP addresses using configurable Lucene queries from the CrowdSec CTI `smoke/search` endpoint and creates enriched observables with:

- **Reputation classifications**: malicious, suspicious, known, or safe
- **Attack behaviors**: SSH bruteforce, HTTP probing, etc.
- **MITRE ATT&CK techniques**: mapped attack patterns and tactics
- **CVE associations**: related vulnerabilities
- **Geolocation data**: origin and targeted countries
- **Temporal information**: first/last seen timestamps

## Installation

### Requirements

- OpenCTI Platform >= 5.3.7
- A CrowdSec CTI API key - [Get your API key](https://docs.crowdsec.net/docs/next/cti_api/getting_started/#getting-an-api-key)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter            | config.yml                       | Docker environment variable      | Default         | Mandatory | Description                                                  |
| -------------------- | -------------------------------- | -------------------------------- | --------------- | --------- | ------------------------------------------------------------ |
| Connector ID         | `connector.id`                   | `CONNECTOR_ID`                   | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.    |
| Connector Type       | `connector.type`                 | `CONNECTOR_TYPE`                 | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector. |
| Connector Name       | `connector.name`                 | `CONNECTOR_NAME`                 |                 | Yes       | Name of the connector.                                       |
| Connector Scope      | `connector.scope`                | `CONNECTOR_SCOPE`                |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Update existing data | `connector.update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | false           | No        | Whether to update data in the database                       |
| Log Level            | `connector.log_level`            | `CONNECTOR_LOG_LEVEL`            | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the CrowdSec connector:

| Parameter | config.yml | Docker environment variable | Default | Mandatory | Description |
|-----------|------------|----------------------------|---------|-----------|-------------|
| CrowdSec API Key | `crowdsec.key` | `CROWDSEC_KEY` | | Yes | CrowdSec CTI API key |
| Import Query | `crowdsec.import_query` | `CROWDSEC_IMPORT_QUERY` | `behaviors.label:"SSH Bruteforce"` | No | Lucene query to filter CrowdSec data |
| Query Time Range | `crowdsec.import_query_since` | `CROWDSEC_IMPORT_QUERY_SINCE` | `24` | No | Time window in hours for fetching data |
| Enrichment Threshold | `crowdsec.enrichment_threshold_per_import` | `CROWDSEC_ENRICHMENT_THRESHOLD_PER_IMPORT` | `2000` | No | Maximum IPs to enrich per import |
| Max TLP | `crowdsec.max_tlp` | `CROWDSEC_MAX_TLP` | `TLP:AMBER` | No | Maximum TLP level for processing |
| TLP Level | `crowdsec.tlp_level` | `CROWDSEC_TLP_LEVEL` | `amber` | No | TLP for created STIX objects |
| Create Indicators From | `crowdsec.indicator_create_from` | `CROWDSEC_INDICATOR_CREATE_FROM` | `malicious,suspicious,known` | No | Reputation types to create indicators from |
| Create Notes | `crowdsec.create_note` | `CROWDSEC_CREATE_NOTE` | `true` | No | Enable note creation for enrichments |
| Create Sightings | `crowdsec.create_sighting` | `CROWDSEC_CREATE_SIGHTING` | `true` | No | Enable sighting creation |
| Min Enrichment Delay | `crowdsec.min_delay_between_enrichments` | `CROWDSEC_MIN_DELAY_BETWEEN_ENRICHMENTS` | `86400` | No | Minimum seconds between enrichments |

#### Label Configuration

The connector supports extensive label customization:

| Parameter | config.yml | Docker environment variable | Default | Description |
|-----------|------------|----------------------------|---------|-------------|
| Scenario Name Labels | `crowdsec.labels_scenario_name` | `CROWDSEC_LABELS_SCENARIO_NAME` | `true` | Enable scenario name labels |
| Scenario Label Labels | `crowdsec.labels_scenario_label` | `CROWDSEC_LABELS_SCENARIO_LABEL` | `false` | Enable scenario label labels |
| CVE Labels | `crowdsec.labels_cve` | `CROWDSEC_LABELS_CVE` | `true` | Enable CVE-based labels |
| MITRE Labels | `crowdsec.labels_mitre` | `CROWDSEC_LABELS_MITRE` | `true` | Enable MITRE technique labels |
| Behavior Labels | `crowdsec.labels_behavior` | `CROWDSEC_LABELS_BEHAVIOR` | `false` | Enable behavior labels |
| Reputation Labels | `crowdsec.labels_reputation` | `CROWDSEC_LABELS_REPUTATION` | `true` | Enable reputation labels |

#### Label Colors

| Parameter | config.yml | Docker environment variable | Default | Description |
|-----------|------------|----------------------------|---------|-------------|
| Scenario Color | `crowdsec.labels_scenario_color` | `CROWDSEC_LABELS_SCENARIO_COLOR` | `#2E2A14` | Scenario label color |
| CVE Color | `crowdsec.labels_cve_color` | `CROWDSEC_LABELS_CVE_COLOR` | `#800080` | CVE label color |
| MITRE Color | `crowdsec.labels_mitre_color` | `CROWDSEC_LABELS_MITRE_COLOR` | `#000080` | MITRE technique label color |
| Behavior Color | `crowdsec.labels_behavior_color` | `CROWDSEC_LABELS_BEHAVIOR_COLOR` | `#808000` | Behavior label color |
| Malicious Color | `crowdsec.labels_reputation_malicious_color` | `CROWDSEC_LABELS_REPUTATION_MALICIOUS_COLOR` | `#FF0000` | Malicious reputation color |
| Suspicious Color | `crowdsec.labels_reputation_suspicious_color` | `CROWDSEC_LABELS_REPUTATION_SUSPICIOUS_COLOR` | `#FFA500` | Suspicious reputation color |
| Known Color | `crowdsec.labels_reputation_known_color` | `CROWDSEC_LABELS_REPUTATION_KNOWN_COLOR` | `#808080` | Known reputation color |
| Safe Color | `crowdsec.labels_reputation_safe_color` | `CROWDSEC_LABELS_REPUTATION_SAFE_COLOR` | `#00BFFF` | Safe reputation color |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from the src directory:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior

The CrowdSec connector operates by:

1. **Querying CrowdSec CTI API** using the configured Lucene query to retrieve IP addresses
2. **Creating IP observables** (IPv4-Addr or IPv6-Addr) in OpenCTI
3. **Enriching observables** with comprehensive threat intelligence data
4. **Generating STIX relationships** between observables, indicators, attack patterns, and locations

### Data Enrichment Process

For each imported IP address, the connector creates:

- **Observable**: IPv4-Addr or IPv6-Addr with basic IP information
- **Labels**: Configurable color-coded labels for reputation, scenarios, CVEs, and MITRE techniques
- **External References**: Links to CrowdSec CTI and related threat intelligence sources
- **Indicators**: Generated based on reputation (configurable which reputation types)
- **Attack Patterns**: Created from MITRE ATT&CK techniques with relationships to indicators
- **Vulnerabilities**: Generated from associated CVE information
- **Locations**: Country-based locations for geolocation context
- **Sightings**: Temporal information about when the IP was observed
- **Notes**: Detailed enrichment information including confidence levels and behavioral analysis

### Import Strategies

Import performance varies significantly based on:
- **Server specifications**: CPU cores, RAM, and Elasticsearch allocation
- **Enrichment configuration**: Number of enabled features affects processing time
- **Data volume**: Processing time scales with number of IPs imported

Typical benchmarks (import all possible enrichment on 8-core, 32GB RAM server):
- 2,000 IPs: ~1.5 hours
- 10,000 IPs: ~8.5 hours  
- 50,000 IPs: ~3.5 days


## Debugging

### Log Levels

Set the appropriate log level using `CONNECTOR_LOG_LEVEL` (or `log_level` in config.yml):
- `debug`: Detailed debugging information including API calls and data processing
- `info`: General operational information (default)
- `warn`: Warning messages for potential issues
- `error`: Error messages only

### Common Issues

**Authentication Errors**
- Verify your `CROWDSEC_KEY` is valid and has appropriate permissions
- Check CrowdSec API quota limits

**Import Failures**
- Review Lucene query syntax in `CROWDSEC_IMPORT_QUERY`
- Verify time range in `CROWDSEC_IMPORT_QUERY_SINCE` is reasonable
- Check OpenCTI connectivity and token validity

**Performance Issues**
- Reduce `CROWDSEC_ENRICHMENT_THRESHOLD_PER_IMPORT` for faster processing
- Disable unnecessary enrichment features (labels, sightings, etc.)
- Increase `DURATION_PERIOD` to avoid API rate limits

**TLP Level Conflicts**
- Ensure `CROWDSEC_MAX_TLP` is appropriate for your environment
- Verify `CROWDSEC_TLP_LEVEL` matches your organization's classification scheme

## Additional information

### API Integration Details

The connector integrates with CrowdSec's CTI API using the `smoke/search` endpoint documented at: https://crowdsecurity.github.io/cti-api/#/Freemium/get_smoke_search

### Lucene Query Examples

Configure `CROWDSEC_IMPORT_QUERY` with Lucene syntax:
- SSH attacks: `behaviors.label:"SSH Bruteforce" AND reputation:"malicious"`
- HTTP probing: `behaviors.label:"HTTP Admin Interface Probing"`
- Multiple attack types: `behaviors.label:("SSH Bruteforce" OR "HTTP Probing")`
- Reputation filtering: `reputation:("malicious" OR "suspicious")`

See [CrowdSec query documentation](https://docs.crowdsec.net/u/cti_api/search_queries/) for complete syntax reference.

### STIX 2.1 Compliance

All created objects follow STIX 2.1 specifications:
- **IPv4-Addr/IPv6-Addr**: Cyber Observable Objects
- **Indicators**: Pattern-based threat indicators
- **Attack-Patterns**: MITRE ATT&CK technique mappings
- **Vulnerabilities**: CVE-based vulnerability objects
- **Locations**: Country-based geolocation objects
- **Relationships**: `based-on`, `indicates`, `targets`, `related-to`

### Related Connectors

Consider pairing with:
- **CrowdSec Internal Enrichment Connector**: For enriching existing observables

