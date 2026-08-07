# OpenCTI MITRE Fight Fraud (F3) Connector

## Introduction

The **MITRE Fight Fraud Framework™ (F3)** connector imports the F3 knowledge base into OpenCTI. F3 is a curated knowledge base of tactics and techniques used by financial fraud actors, derived from real-world observations of cyber fraud incidents.

The framework includes behaviors that characterize known fraud TTPs and references existing MITRE ATT&CK® cyber techniques as applicable to financial fraud. F3 provides a common structure and taxonomy to consistently describe and enumerate the material events of a cyber fraud incident, enabling stronger collaboration on fraud prevention, detection, and response across organizational teams.

The knowledge base is globally accessible, open, and available at no charge. More information at: https://ctid.mitre.org/fraud/

### Data Imported

This connector imports the following STIX objects from the F3 STIX bundle:

- **Attack Patterns** — Fraud techniques and sub-techniques
- **Identities** — Source identity (MITRE)
- **Relationships** — Links between attack patterns (sub-techniques)
- **x-mitre-matrix** — The F3 matrix
- **x-mitre-tactic** — F3 tactics (kill chain phases)
- **x-mitre-collection** — F3 collection metadata
- **Marking Definitions** — TLP and statement markings

### Kill Chain Phases (Tactics)

The F3 kill chain phases are imported in the following order:

| Order | Tactic Name          |
|-------|----------------------|
| 0     | Reconnaissance       |
| 1     | Resource Development |
| 2     | Initial Access       |
| 3     | Defense Evasion      |
| 4     | Positioning          |
| 5     | Execution            |
| 6     | Monetization         |

Table of Contents

- [OpenCTI MITRE Fight Fraud (F3) Connector](#opencti-mitre-fight-fraud-f3-connector)
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

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 6.8.13
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library matching your OpenCTI version

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter         | config.yml      | Docker environment variable   | Default                      | Mandatory | Description                                                                              |
| ----------------- | --------------- | ----------------------------- | ---------------------------- | --------- | ---------------------------------------------------------------------------------------- |
| Connector ID      | id              | `CONNECTOR_ID`                | /                            | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type    | type            | `CONNECTOR_TYPE`              | EXTERNAL_IMPORT              | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                            |
| Connector Name    | name            | `CONNECTOR_NAME`              | MITRE Fight Fraud (F3)      | No        | Name of the connector.                                                                   |
| Connector Scope   | scope           | `CONNECTOR_SCOPE`             | attack-pattern,identity,...  | No        | The scope or type of data the connector is importing.                                    |
| Log Level         | log_level       | `CONNECTOR_LOG_LEVEL`         | error                        | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Duration Period   | duration_period | `CONNECTOR_DURATION_PERIOD`   | PT1H                         | No        | Interval in ISO-8601 format between two runs of the connector.                           |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter                  | config.yml               | Docker environment variable              | Default | Mandatory | Description                                                |
| -------------------------- | ------------------------ | ---------------------------------------- | ------- | --------- | ---------------------------------------------------------- |
| Remove Statement Marking   | remove_statement_marking | `MITRE_FRAUD_REMOVE_STATEMENT_MARKING`   | false   | No        | Remove statement marking definitions from the STIX bundle. |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
docker build . -t opencti/connector-mitre-fraud:latest
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
your environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from `src` directory:

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

The connector fetches the MITRE Fight Fraud (F3) STIX bundle from `https://ctid.mitre.org/fraud/f3-stix.json`. It then:

1. **Filters revoked objects** — Removes any objects marked as revoked, along with their associated relationships.
2. **Optionally removes statement markings** — If `MITRE_FRAUD_REMOVE_STATEMENT_MARKING` is set to `true`, statement marking definitions and their references are removed from the bundle.
3. **Enriches kill chain phases** — Adds `x_opencti_order` to kill chain phases on attack patterns, ensuring the correct ordering of tactics in OpenCTI (Reconnaissance → Resource Development → Initial Access → Defense Evasion → Positioning → Execution → Monetization).
4. **Sends the bundle** — The enriched STIX bundle is sent to OpenCTI for ingestion.

## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, i.e., `self.helper.connector_logger.error("An error message")`.

