# OpenCTI GreedyBear Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | - | - |

The GreedyBear connector imports honeypot threat intelligence from a [GreedyBear](https://github.com/GreedyBear-Project/GreedyBear) instance into OpenCTI.

## Table of Contents

- [OpenCTI GreedyBear Connector](#opencti-greedybear-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
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
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

GreedyBear collects and scores indicators of compromise seen by honeypot sensors. This connector pulls those indicators on a schedule and creates the matching observables and indicators in OpenCTI, along with the autonomous system, country and MITRE ATT&CK technique behind each one.

An API key is optional. Without one the connector reads the public standard feed. With a key it also uses the advanced and ASN feeds, which add autonomous system names, captured-credential counts and the sensors that observed each indicator.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.13
- A reachable GreedyBear instance
- A GreedyBear API token (optional, enables the authenticated feeds)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml      | Docker environment variable | Default    | Mandatory | Description                                                                |
|-----------------|-----------------|-----------------------------|------------|-----------|----------------------------------------------------------------------------|
| Connector ID    | id              | `CONNECTOR_ID`              |            | Yes       | A unique `UUIDv4` identifier for this connector instance.                  |
| Connector Name  | name            | `CONNECTOR_NAME`            | GreedyBear | No        | Name of the connector.                                                     |
| Connector Scope | scope           | `CONNECTOR_SCOPE`           | IPv4-Addr,IPv6-Addr,Domain-Name,Autonomous-System,Location,Infrastructure | No | The scope of data the connector imports. |
| Log Level       | log_level       | `CONNECTOR_LOG_LEVEL`       | error      | No        | Determines the verbosity of the logs: `debug`, `info`, `warn`, or `error`.|
| Duration Period | duration_period | `CONNECTOR_DURATION_PERIOD` | PT6H       | No        | Interval between two runs, as an ISO 8601 duration (for example `PT6H`).   |

### Connector extra parameters environment variables

| Parameter              | config.yml             | Docker environment variable         | Default           | Mandatory | Description                                                                          |
|------------------------|------------------------|-------------------------------------|-------------------|-----------|--------------------------------------------------------------------------------------|
| API base URL           | api_base_url           | `GREEDYBEAR_API_BASE_URL`           |                   | Yes       | Base URL of your GreedyBear instance.                                                |
| API key                | api_key                | `GREEDYBEAR_API_KEY`                |                   | No        | DRF token for the authenticated feeds. Omit to use only the public standard feed.    |
| TLP level              | tlp_level              | `GREEDYBEAR_TLP_LEVEL`              | green             | No        | TLP marking for imported entities (`clear`, `white`, `green`, `amber`, `amber+strict`, `red`). |
| Operator name          | operator_name          | `GREEDYBEAR_OPERATOR_NAME`          | Honeypot Operator | No        | Organization shown as the author of the imported data.                               |
| Operator description   | operator_description   | `GREEDYBEAR_OPERATOR_DESCRIPTION`   |                   | No        | Description of the honeypot operator.                                                |
| Operator URL           | operator_url           | `GREEDYBEAR_OPERATOR_URL`           |                   | No        | URL of the honeypot operator.                                                        |
| Feed type              | feed_type              | `GREEDYBEAR_FEED_TYPE`              | all               | No        | Honeypot feed filter (`all` or a comma-separated list of honeypot names).            |
| Attack type            | attack_type            | `GREEDYBEAR_ATTACK_TYPE`            | all               | No        | Attack type filter (`all`, `scanner`, `payload_request`).                            |
| IoC type               | ioc_type               | `GREEDYBEAR_IOC_TYPE`              | all               | No        | IoC type filter (`all`, `ip`, `domain`).                                             |
| Prioritize             | prioritize             | `GREEDYBEAR_PRIORITIZE`            | recent            | No        | Standard feed ordering, used only as a fallback (`recent`, `persistent`, `likely_to_recur`, `most_expected_hits`). |
| Include mass scanners  | include_mass_scanners  | `GREEDYBEAR_INCLUDE_MASS_SCANNERS` | false             | No        | Include indicators flagged as mass scanners.                                         |
| Include Tor exit nodes | include_tor_exit_nodes | `GREEDYBEAR_INCLUDE_TOR_EXIT_NODES`| true              | No        | Include indicators flagged as Tor exit nodes.                                        |
| Max age                | max_age                | `GREEDYBEAR_MAX_AGE`               | 3                 | No        | Maximum age of entries in days (advanced feed).                                      |
| Feed size              | feed_size              | `GREEDYBEAR_FEED_SIZE`             | 5000              | No        | Maximum number of indicators per run.                                                |
| Min score              | min_score              | `GREEDYBEAR_MIN_SCORE`             |                   | No        | Minimum recurrence probability between 0.0 and 1.0. No filter when unset.            |
| Create indicators      | create_indicators      | `GREEDYBEAR_CREATE_INDICATORS`     | true              | No        | Create a STIX Indicator for every observable.                                        |
| Deep enrich            | deep_enrich            | `GREEDYBEAR_DEEP_ENRICH`           | false             | No        | Run a per-indicator enrichment call to add the destination ports, the days-seen count and FireHOL categories. Adds one API call per indicator. |

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-greedybear:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-greedybear:
    image: opencti/connector-greedybear:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=GreedyBear
      - CONNECTOR_SCOPE=IPv4-Addr,IPv6-Addr,Domain-Name,Autonomous-System,Location,Infrastructure
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT6H
      - GREEDYBEAR_API_BASE_URL=https://greedybear.example.com
      # - GREEDYBEAR_API_KEY=ChangeMe
      - GREEDYBEAR_TLP_LEVEL=green
      - GREEDYBEAR_OPERATOR_NAME=My Organization
      - GREEDYBEAR_CREATE_INDICATORS=true
      # - GREEDYBEAR_DEEP_ENRICH=false
    restart: always
```

Start the connector:

```bash
docker compose up -d
```

### Manual Deployment

1. Create `config.yml` based on `config.yml.sample`.

2. Install dependencies:

```bash
pip3 install -r src/requirements.txt
```

3. Start the connector from the `src` directory:

```bash
python3 main.py
```

## Usage

The connector runs automatically at the interval set in `CONNECTOR_DURATION_PERIOD`. To trigger a run immediately, go to **Data Management → Ingestion → Connectors**, find the connector and use the refresh button to reset its state and start a new run.

## Behavior

For each IP or domain that GreedyBear reports, the connector creates:

| GreedyBear data            | OpenCTI entity / property                | Description                                                  |
|----------------------------|------------------------------------------|--------------------------------------------------------------|
| IP or domain               | IPv4-Addr / IPv6-Addr / Domain-Name      | The observable, labelled with the honeypot type and reputation |
| recurrence probability     | Indicator `x_opencti_score`              | Score derived from the recurrence probability                |
| last seen                  | Indicator `valid_until`                  | Validity window anchored on the last observation             |
| autonomous system          | Autonomous-System (`belongs-to`)         | AS number, plus the AS name when an API key is set           |
| attacker country           | Location (`located-at`)                  | Country of the attacker                                      |
| scanner / payload_request  | Attack-Pattern (`indicates`)             | MITRE ATT&CK technique for the observed activity             |
| honeypot statistics        | Note                                     | Attack, interaction and login counts, recurrence and, with deep enrichment, the destination ports, captured credentials, sensors and days-seen |

The honeypot operator is created as an Organization and set as the author of every object. GreedyBear itself is added as a Tool used by that operator. The honeypot sensors are kept as labels rather than separate entities.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for verbose output, including the API requests and the number of objects sent per run.

## Additional information

The authenticated advanced and ASN feeds add the autonomous system names, captured-credential counts and sensor origins that the public feed does not carry. The `deep_enrich` option adds one enrichment request per indicator to retrieve the actual destination ports, the days-seen count and the FireHOL blocklist categories. It is useful for smaller, targeted feeds but slow for large ones, so it is disabled by default.
