# OpenCTI NVD - CVE connector

The NVD-CVE connector is a standalone Python process that collect data from the NVD (National Vulnerability Database).

## Summary

- [Introduction](#introduction)
- [Sources](#sources)

### Introduction

The NVD is the US government's source for standards-based vulnerability management data and  is a product of the NIST Computer Security Division, Information Technology Laboratory.

This data enables the automation of vulnerability management, security measurement, and compliance. NVD includes databases of vulnerability lists, software vulnerabilities, product names, and severity scores.

The CVE (Common Vulnerabilities and Exposures) is a dictionary of publicly known information security vulnerabilities and
other information security exposures. 

The CVE repository is maintained by [MITRE Corporation](https://www.mitre.org/) and is freely available.

This connector collects CVE data from the NVD, converts to STIX2 and imports them into OpenCTI at a regular intervals.

### Requirements

- OpenCTI Platform version 5.12.5 or higher
- An API Key for accessing

#### Request an API Key

[Request an API Key](https://nvd.nist.gov/developers/request-an-api-key)

### Configuration variables

Below are the parameters you'll need to set for OpenCTI:

|Parameter| config.yml | Docker environment variable  |Mandatory| Description                                                                                                             |
|--|------------|------------------------------|--|-------------------------------------------------------------------------------------------------------------------------|
| OpenCTI URL | url        | `OPENCTI_URL`                | Yes | The URL of the OpenCTI platform.                                                                                        |
| OpenCTI Token | token      | `OPENCTI_TOKEN`              | Yes                         | The default admin token set in the OpenCTI platform.                                                                    |

Below are the parameters you'll need to set for running the connector properly:

| Parameter            | config.yml | Docker environment variable      | Default                              | Mandatory | Description                                                                                                                                |
|----------------------|------------|----------------------------------|--------------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------|
| Connector ID         | id         | `CONNECTOR_ID`                   | /                                    | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                  |
| Connector Type       | type       | `CONNECTOR_TYPE`                 | EXTERNAL_IMPORT                      | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                                                                              |
| Connector Name       | name       | `CONNECTOR_NAME`                 | Common Vulnerabilities and Exposures | Yes       | Name of the connector.                                                                        |
| Connector Scope      | scope      | `CONNECTOR_SCOPE`                | identity,vulnerability               | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.                                                   |
| Confidence Level     |  confidence_level          | `CONNECTOR_CONFIDENCE_LEVEL`     | 75                                   | Yes       | The default confidence level for created sightings. It's a number between 0 and 100, with 100 being the most confident.                    |
| Update existing data |  update_existing_data          | `CONNECTOR_UPDATE_EXISTING_DATA` | False                                | No        | If an entity already exists, update its attributes with information provided by this connector. Takes 2 available values: `True` or `False` |
| Run and Terminate    |  run_and_terminate          | `CONNECTOR_RUN_AND_TERMINATE`    | False                                | No        | Launch the connector once if set to True. Takes 2 available values: `True` or `False`  |
| Log Level            |    log_level        | `CONNECTOR_LOG_LEVEL`            | info                                 | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

Below are the parameters you'll need to set for NVD-CVE:

| Parameter              | config.yml | Docker environment variable      | Default                                      | Mandatory | Description                                                                                                                                                         |
|------------------------|------------|----------------------------------|----------------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE Base URL           | base_url   | `CVE_BASE_URL`                   | https://services.nvd.nist.gov/rest/json/cves | Yes       | URL for the CVE API.                                                                                                                                                |
| CVE API Key            | api_key    | `CVE_API_KEY`                   | /                                            | Yes       | API Key for the CVE API.                                                                                                                                            |
| CVE Interval           | interval   | `CVE_INTERVAL`                   | 6                                            | Yes       | Interval in hours to check and import new CVEs. Must be strictly greater than 1, advice from NIST minimum 6 hours                                                   |
| CVE Max Date Range     | max_date_range   | `CVE_MAX_DATE_RANGE`                   | 120                                          | Yes       | Determines how many days to collect CVE. Maximum of 120 days.                                                                                                       |
| CVE Maintain Data      | maintain_data   | `CVE_MAINTAIN_DATA`                   | True                                         | No        | If set to `True`, import CVEs from the last run of the connector to the current time. Takes 2 values: `True` or `False`.                                            |
| CVE Pull History       | pull_history   | `CVE_PULL_HISTORY`                   | False                                        | No        | If set to `True`, import all CVEs from start year define in history start year configuration and history start year is required. Takes 2 values: `True` or `False`. |
| CVE History Start Year | history_start_year   | `CVE_HISTORY_START_YEAR`                   | 2023                                         | No        | Year in number. Required when pull_history is set to `True`.                                                                                                        |

For more details about the CVE API, see the documentation at the link below:
- [CVE API](https://nvd.nist.gov/developers/vulnerabilities)

### Deployment

#### Docker Deployment

Build a Docker Image using the provided `Dockerfile`. 

Example: 

```shell
docker build . -t opencti-nvd-cve-import:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

#### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`. 

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for you environment. 

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```
Or if you have Make installed, in nvd-cve/src:

```shell
make init
```

Then, start the connector from nvd-cve/src:

```shell
python3 main.py
```

### Behavior

### Usage

### Sources

- [NVD](https://nvd.nist.gov/info)
- [Computer Security Division](https://www.nist.gov/itl/csd)
