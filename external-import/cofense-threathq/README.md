# OpenCTI External Ingestion Connector Cofense ThreatHQ

Table of Contents

- [OpenCTI External Ingestion Connector Cofense ThreatHQ](#opencti-external-ingestion-connector-cofense-threathq)
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

## Status Filigran

| Status            | Date | Comment |
|-------------------|------|---------|
| Filigran Verified | -    | -       |

## Introduction

**Introducing Cofense**

Cofense is the Leader in Email Security
Cofense secures enterprise email systems with a combination of industry-leading security awareness training and threat detection and response solutions.

We’re the only email security provider with access to data from over 35 million Cofense-trained employees who actively report suspected phishing threats in real-time. When our users around the globe report suspected phish, those threat insights are fed back into our Phishing Detection and Response solution, unlocking unparalleled threat intelligence.

Cofense is the only email security company that can see and stop threats missed by all other standard email controls.
For more information on gaining access to Cofense Intelligence data at https://cofense.com/

**What is Cofense ThreatHQ ?**

indicator_type availables : 
- `URL`, 
- `Domain Name`, 
- `IPv4 Address`, 
- `File`, 
- `Email`

If you are already a customer, detailed documentation on the Intelligence API can be found at https://www.threathq.com/docs/

## Installation

### Requirements

- pycti==6.6.12
- validators==0.33.0
- pydantic>=2.10, <3
- requests~=2.32.3
- stix2~=3.0.1
- PyYAML==6.0.2
- aiohttp~=3.11.11
- tenacity~=9.0.0
- pydantic-settings==2.8.1
- python-dotenv>=1.0.1, <2

## Configuration variables environment

A variety of configuration options are available, and the connector will load them from a single source, following a specific order of precedence:

1. The `.env` file – This is the primary configuration source, if present. You can use the provided `.env.sample` as a reference.
2. The `config.yml` file – If no `.env` file is found, the connector will look for a `config.yml` file instead (a `config.yml.sample` is also available as a starting point).
3. System environment variables – If neither a `.env` nor a `config.yml` file is available, the connector will fall back to system environment variables.

A `docker-compose.yml` file is also available to simplify Docker-based deployments and supports passing environment variables through directly via the system environment.

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter `Connector`       | config.yml                    | Docker environment variable             | Default            | Mandatory | Description                                                                                      |
|-----------------------------|-------------------------------|-----------------------------------------|--------------------|-----------|--------------------------------------------------------------------------------------------------|
| ID                          | `id`                          | `CONNECTOR_ID`                          | /                  | Yes       | A unique `UUIDv4` identifier for this connector instance.                                        |
| Type                        | `type`                        | `CONNECTOR_TYPE`                        | `EXTERNAL_IMPORT`  | No        | Should always be set to `EXTERNAL_IMPORT` for this connector.                                    |
| Name                        | `name`                        | `CONNECTOR_NAME`                        | `Cofense ThreatHQ` | No        | Name of the connector.                                                                           |
| Scope                       | `scope`                       | `CONNECTOR_SCOPE`                       | `Cofense ThreatHQ` | No        | The scope or type of data the connector is importing, either a MIME type or Stix Object.         |
| Log level                   | `log_level`                   | `CONNECTOR_LOG_LEVEL`                   | `info`             | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.           |
| Duration period             | `duration_period`             | `CONNECTOR_DURATION_PERIOD`             | `PT5H`             | No        | Determines the time interval between each launch of the connector in ISO 8601, ex: `PT5H`.       |
| Queue threshold             | `queue_threshold`             | `CONNECTOR_QUEUE_THRESHOLD`             | `500`              | No        | Used to determine the limit (RabbitMQ) in MB at which the connector must go into buffering mode. |
| Run and terminate           | `run_and_terminate`           | `CONNECTOR_RUN_AND_TERMINATE`           | `False`            | No        | Launch the connector once if set to `True`.                                                      |
| Send to queue               | `send_to_queue`               | `CONNECTOR_SEND_TO_QUEUE`               | `True`             | No        | If set to `True`, the connector will send data to the queue.                                     |
| Send to directory           | `send_to_directory`           | `CONNECTOR_SEND_TO_DIRECTORY`           | `False`            | No        | If set to `True`, the connector will send data to a directory.                                   |
| Send to directory path      | `send_to_directory_path`      | `CONNECTOR_SEND_TO_DIRECTORY_PATH`      | `None`             | No        | The path to the directory where data will be sent if `CONNECTOR_SEND_TO_DIRECTORY` is `True`.    |
| Send to directory retention | `send_to_directory_retention` | `CONNECTOR_SEND_TO_DIRECTORY_RETENTION` | `7`                | No        | The number of days to retain data in the directory.                                              |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter `Cofense-ThreatHQ`     | config.yml                          | Docker environment variable                          | Default                           | Mandatory | Description                                                                                                                                                         |
|----------------------------------|-------------------------------------|------------------------------------------------------|-----------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Token user                       | `token_user`                        | `COFENSE_THREATHQ_TOKEN_USER`                        | /                                 | Yes       | Represents the token user in Cofense ThreatHQ.                                                                                                                      |
| Token password                   | `token_password`                    | `COFENSE_THREATHQ_TOKEN_PASSWORD`                    | /                                 | Yes       | Represents the token password in Cofense ThreatHQ.                                                                                                                  |
| Api base url                     | `api_base_url`                      | `COFENSE_THREATHQ_API_BASE_URL`                      | `https://www.threathq.com/apiv1/` | No        | Cofense ThreatHQ API base url used for REST requests.                                                                                                               |
| Api leaky bucket rate            | `api_leaky_bucket_rate`             | `COFENSE_THREATHQ_API_LEAKY_BUCKET_RATE`             | `10`                              | No        | Leaky bucket rate per second.                                                                                                                                       |
| Api leaky bucket capacity        | `api_leaky_bucket_capacity`         | `COFENSE_THREATHQ_API_LEAKY_BUCKET_CAPACITY`         | `10`                              | No        | Leaky bucket capacity.                                                                                                                                              |
| Api retry                        | `api_retry`                         | `COFENSE_THREATHQ_API_RETRY`                         | `5`                               | No        | Maximum number of retry attempts in case of API failure.                                                                                                            |
| Api backoff                      | `api_backoff`                       | `COFENSE_THREATHQ_API_BACKOFF`                       | `PT30S`                           | No        | Exponential backoff duration between API retries (ISO 8601 duration format).                                                                                        |
| Import start date                | `import_start_date`                 | `COFENSE_THREATHQ_IMPORT_START_DATE`                 | `P30D`                            | No        | The date from which data import should start, accepts several date formats (`YYYY-MM-DD`, `YYYY-MM-DD HH:MM:SS+HH:MM`, `P30D` - 30 days before connector start-up). |
| Import report PDF                | `import_report_pdf`                 | `COFENSE_THREATHQ_IMPORT_REPORT_PDF`                 | `True`                            | No        | Retrieves the pdf of the report generated by Cofense ThreatHQ.                                                                                                      |
| Impact to exclude                | `impact_to_exclude`                 | `COFENSE_THREATHQ_IMPACT_TO_EXCLUDE`                 | `No exclusion`                    | No        | List of report impact to exclude from import. Example: "None,Moderate,Major"                                                                                        |
| TLP level                        | `tlp_level`                         | `COFENSE_THREATHQ_TLP_LEVEL`                         | `amber+strict`                    | No        | TLP markings for exported data (Available: clear, green, amber, amber+strict, red).                                                                                 |
| Promote Observable as Indicators | `promote_observables_as_indicators` | `COFENSE_THREATHQ_PROMOTE_OBSERVABLES_AS_INDICATORS` | `True`                            | No        | This variable is used to create indicators based on observables from Cofense ThreatHQ.                                                                              |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.6.12`. If you don't, it will take the latest version, but
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

Then, start the connector from recorded-future/src:

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

Scope:
- Report
  - Credential Phishing
  - Malware Campaign
- Malwares (labels)
- Vulnerability (WIP)
- Observable
  - URL
  - File
  - Email-Subject
  - Email-Message
  - IPv4 Address
  - Domain Name
  - Asn (WIP)
- Location (WIP)
- Sector(Only Recipient NAICS Subsector(s))
- Promote observables as indicators (WIP)


## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
