# OpenCTI OSSF Malicious Packages Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | - | - |

The OSSF Malicious Packages connector ingests malicious package advisories from the [ossf/malicious-packages](https://github.com/ossf/malicious-packages) GitHub repository into OpenCTI, creating File Observables, hash-based STIX Indicators, and `based-on` relationships between them.

## Table of Contents

- [OpenCTI OSSF Malicious Packages Connector](#opencti-ossf-malicious-packages-connector)
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
    - [Data Mapping](#data-mapping)
    - [Additional Notes](#additional-notes)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)
  - [Future Developments](#future-developments)

## Introduction

The [Open Source Security Foundation (OSSF)](https://openssf.org/) maintains a public repository of known-malicious open source packages (`ossf/malicious-packages`), published as OSV-format JSON advisories.

This connector clones/pulls that repository, parses each advisory, and creates a File Observable and a hash-based STIX Indicator (with a `based-on` relationship between them) for each malicious package hash in OpenCTI. Optionally, ingested Indicators can then be exported to a SIEM to build a blocking list.

- **Connector type:** External Import
- **Source:** GitHub repo [ossf/malicious-packages](https://github.com/ossf/malicious-packages)
- **Target:** OpenCTI
- **Schedule:** Hourly (configurable)

## Installation

### Requirements

- OpenCTI Platform >= 6.x
- Network access from the connector to `github.com` (to clone/pull the OSSF repository)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|------------------------------|-----------|-------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                       |
| OpenCTI Token | token      | `OPENCTI_TOKEN`               | Yes       | The default admin token set in the OpenCTI platform.   |

### Base connector environment variables

| Parameter          | config.yml       | Docker environment variable   | Default                              | Mandatory | Description                                                |
|---------------------|------------------|--------------------------------|----------------------------------------|-----------|-------------------------------------------------------------|
| Connector ID        | id               | `CONNECTOR_ID`                 | `3fda8b20-75f7-424d-ba15-f836b1a5bdfa` | No        | A unique `UUIDv4` identifier for this connector instance.    |
| Connector Type      | type             | `CONNECTOR_TYPE`               | `EXTERNAL_IMPORT`                      | No        | Must be `EXTERNAL_IMPORT` for this connector.                |
| Connector Name      | name             | `CONNECTOR_NAME`               | OSSF Malicious Packages                | No        | Name of the connector.                                        |
| Connector Scope     | scope            | `CONNECTOR_SCOPE`              | `file,indicator`                       | No        | The scope or type of data the connector is importing.         |
| Confidence Level    | confidence_level | `CONNECTOR_CONFIDENCE_LEVEL`   | 80                                     | No        | Confidence level assigned to created entities (0-100).        |
| Log Level           | log_level        | `CONNECTOR_LOG_LEVEL`          | info                                   | No        | Determines the verbosity of the logs: `debug`, `info`, `warn`, or `error`. |

### Connector extra parameters environment variables

| Parameter               | config.yml               | Docker environment variable     | Default                                    | Mandatory | Description                                                             |
|--------------------------|---------------------------|-----------------------------------|-----------------------------------------------|-----------|---------------------------------------------------------------------------|
| GitHub Repo URL          | ossf.github_repo_url       | `OSSF_GITHUB_REPO_URL`             |                                                | Yes       | URL of the OSSF malicious-packages GitHub repository to clone/pull.       |
| GitHub Branch            | ossf.branch                | `OSSF_GITHUB_BRANCH`               | main                                          | No        | Branch of the repository to track.                                        |
| Local Repo Path          | ossf.local_repo_path       | `OSSF_LOCAL_REPO_PATH`             | `/opt/ossf-malicous-packages-repo`            | No        | Local filesystem path where the repository is cloned.                     |
| Run Interval (seconds)   | ossf.run_interval_seconds  | `OSSF_RUN_INTERVAL_SECONDS`        | 86400                                         | No        | How often to check the repository for updates, in seconds.                |
| Default Score            | ossf.default_score         | `OSSF_DEFAULT_SCORE`               | 80                                             | No        | Default `x_opencti_score` assigned to created Indicators.                 |
| Source Name              | ossf.source_name           | `OSSF_SOURCE_NAME`                 | ossf/malicious-packages                       | No        | Author/source name label used on created entities.                        |

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-ossf-malicious-packages:latest .
