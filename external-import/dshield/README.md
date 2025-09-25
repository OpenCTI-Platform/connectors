# OpenCTI DShield connector

The DShield connector is a standalone Python process that collects data from the DShield.org Recommended Block List.
Idea:damians-filigran

## Summary

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
---

### Introduction

The [DShield.org](https://feeds.dshield.org/block.txt) Recommended Block List is a curated summary of the top attacking class C (/24) subnets observed over the past three days. It is maintained by the Internet Storm Center (ISC) at SANS and aggregates reports from distributed intrusion detection systems across the internet. The list is intended to help network defenders identify and block IP ranges that are most actively scanning or attacking systems.

### Requirements

- OpenCTI Platform version 6.7.7 or higher

### Configuration variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter              | config.yml           | Docker environment variable     | Default                               | Mandatory | Description                                                                                  |
|------------------------|----------------------|---------------------------------|---------------------------------------|-----------|----------------------------------------------------------------------------------------------|
| Connector ID           | id                   | `CONNECTOR_ID`                  | /                                     | Yes       | A unique `UUIDv4` identifier for this connector instance.                                    |
| Connector Name         | name                 | `CONNECTOR_NAME`                | Common Vulnerabilities and Exposures  | Yes       | Name of the connector.                                                                       |
| Connector Scope        | scope                | `CONNECTOR_SCOPE`               | identity,vulnerability                | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.     |
| Run and Terminate      | run_and_terminate    | `CONNECTOR_RUN_AND_TERMINATE`   | False                                 | No        | Launch the connector once if set to True. Takes 2 available values: `True` or `False`        |
| Log Level              | log_level            | `CONNECTOR_LOG_LEVEL`           | info                                  | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.       |
| Duration Period        | duration_period      | `CONNECTOR_DURATION_PERIOD`     | P1D                                   | Yes       | Determines the time interval between each launch of the connector in ISO 8601, ex: `PT30M`.  |


Below are the parameters you'll need to set for DShield connector:

| Parameter        | config.yml  | Docker environment variable | Default                             | Mandatory | Description                                                                                                                        |
|------------------|-------------|-----------------------------|-------------------------------------|-----------|------------------------------------------------------------------------------------------------------------------------------------|
| DShield Base URL | base_url    | `DSHIELD_API_BASE_URL`      | https://feeds.dshield.org/block.txt | Yes       | URL of DShield Blocking list .                                                                                                     |
| TLP Level        | tlp_level   | `DSHIELD_TLP_LEVEL`         | 'clear'                             | No        | Traffic Light Protocol Marking definition level for ingested objects should be in 'white', 'green', 'amber', 'amber+strict', 'red' |

For more details about this project, see the link below:

- [DShield Sensor](https://www.dshield.org/howto.html)

### Deployment

#### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
docker build . -t connector-dshield:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

#### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Or if you have Make installed, in dshield/src:

```shell
# Will install the requirements
make init
```

Then, start the connector from dshield/src:

```shell
python3 main.py
```

