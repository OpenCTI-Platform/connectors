# OpenCTI NTI Connector

The OpenCTI NTI Connector can be used to import knowledge from NSFOCUS Threat Intelligence feed. 

Table of Contents

- [OpenCTI NTI Connector](#opencti-nti-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [NTI Connector environment variables](#nti-connector-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [License](#license)
  - [Notices and Third-Party Software](#notices-and-third-party-software)

## Introduction

NSFOCUS Threat Intelligence (NTI) is a specialized threat intelligence cloud platform established by NSFOCUS Technology to promote the construction of a cybersecurity ecosystem and the application of threat intelligence, enhancing customers' offensive and defensive capabilities. 

Leveraging the company’s professional security team and strong research capabilities, NTI continuously observes and analyzes global cybersecurity threats and trends. 

## Installation

The OpenCTI NTI connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling NTI connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a Docker with the image `opencti/connector-NTI:latest`. We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI.

### Requirements

To use NTI-Connector, you need to apply for a NTI account.

For further details, please refer to our official website at https://nsfocusglobal.com, or reach out to us via email at nti-services@nsfocus.com.

- OpenCTI Platform >= 6.2.12

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter `Connector` | config.yml      | Docker environment variable | Default           | Mandatory | Description                                                                                          |
|-----------------------|-----------------|-----------------------------|-------------------|-----------|------------------------------------------------------------------------------------------------------|
| ID                    | id              | `CONNECTOR_ID`              | /                 | Yes       | A unique `UUIDv4` identifier for this connector instance.                                            |
| Type                  | type            | `CONNECTOR_TYPE`            | `EXTERNAL_IMPORT` | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                                        |
| Name                  | name            | `CONNECTOR_NAME`            | `NTI`             | Yes       | Name of the connector.                                                                               |
| Scope                 | scope           | `CONNECTOR_SCOPE`           | `nti`             | Yes       | Must be `nti`, not used in this connector.                                                           |
| Log Level             | log_level       | `CONNECTOR_LOG_LEVEL`       | /                 | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.               |
| Duration Period       | duration_period | `CONNECTOR_DURATION_PERIOD` | `P1D`             | Yes       | Determines the time interval between each launch of the connector in ISO 8601, ex: `PT24H` or `P1D`. |
| Queue Threshold       | queue_threshold | `CONNECTOR_QUEUE_THRESHOLD` | `500`             | No        | Used to determine the limit (RabbitMQ) in MB at which the connector must go into buffering mode.     |

### NTI Connector environment variables

Below are the parameters you'll need to set for the connector:

| Parameter `NTI` | config.yml    | Docker environment variable | Default                                 | Mandatory | Description                                                                                          |
|-----------------|---------------|-----------------------------|-----------------------------------------|-----------|------------------------------------------------------------------------------------------------------|
| Base URL        | base_url      | `NTI_BASE_URL`              | `https://nti.nsfocusglobal.com/api/v2/` | Yes       | The base URL for NTI Connector to pull data.                                                         |
| API key         | api_key       | `NTI_API_KEY`               | /                                       | Yes       | The NTI API key.                                                                                     |
| NTI TLP         | tlp           | `NTI_TLP`                   | `white`                                 | Yes       | TLP Marking for all data imported from NTI, possible values: white, green, amber, amber+strict, red. |
| Create IOC      | create_ioc    | `NTI_CREATE_IOC`            | `False`                                 | Yes       | A boolean (`True` or `False`), if true then indicators will be created for each import.              |
| Create IP       | create_ip     | `NTI_CREATE_IP`             | `False`                                 | Yes       | A boolean (`True` or `False`), if true then IP observables will be created for each import.          |
| Create Domain   | create_domain | `NTI_CREATE_DOMAIN`         | `False`                                 | Yes       | A boolean (`True` or `False`), if true then Domain observables will be created for each import.      |
| Create File     | create_file   | `NTI_CREATE_FILE`           | `False`                                 | Yes       | A boolean (`True` or `False`), if true then File observables will be created for each import.        |
| Create URL      | create_url    | `NTI_CREATE_URL`            | `False`                                 | Yes       | A boolean (`True` or `False`), if true then URL observables will be created for each import.         |
| PACKAGE TYPE    | package_type  | `NTI_PACKAGE_TYPE`          | `updated`                               | Yes       | NTI data package control. Only support `updated` for now.                                            |


## Deployment

### Docker Deployment

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find NTI connector, and click on the refresh button to reset the connector's state and force a new download of data by re-running the connector.

## Behavior

The NTI connector will pull latest feed packages. Feed packages are updated on a daily basis. The import process has the following steps:

 - Download feed packages from NTI.
 - Create indicators and `based-on` relationship between indicator and observables if `NTI_CREATE_IOC` is set to true.
 - If `NTI_CREATE_IP` is set to true, then create IP observables, `located-at` relationships between IP address and Locations, and `belongs-to` relationships between IP address and Autonomous System.
 - Create Domain observables and `resolves-to` relationship between Domain observables and IP observables if `NTI_CREATE_DOMAIN` is set to true.
 - Create File observables if `NTI_CREATE_FILE` is set to true.
 - Create URL observables if `NTI_CREATE_URL` is set to true.

## License

Copyright 2025 NSFOCUS

This project is licensed under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

You may not use this software except in compliance with the License.
See the [LICENSE](./LICENSE) file for the full license text.

## Notices and Third-Party Software

This project includes third-party libraries, each under their own respective license:

| Package     | License                |
|-------------|------------------------|
| pycti       | Apache License 2.0     |
| PyYAML      | MIT License            |
| requests    | Apache License 2.0     |
| validators  | BSD License            |

Their use complies with the terms of the Apache License 2.0.
