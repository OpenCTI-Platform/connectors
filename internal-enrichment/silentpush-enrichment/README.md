# Silent Push - OpenCTI Internal Enrichment Connector

Table of Contents

- [Silent Push - OpenCTI Internal Enrichment Connector](#silent-push---opencti-internal-enrichment-connector)
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
Silent Push takes a unique approach to identifying developing cyber threats by creating Indicators of Future Attacks (IOFA) that are more useful, and more valuable than industry-standard IOCs.

We apply unique behavioral fingerprints to attacker activity and search across our proprietary DNS database – containing the most complete, accurate, and timely view of global internet-facing infrastructure anywhere in the world – to reveal adversary infrastructure and campaigns prior to launch.

***We know first!***
## Installation

### Requirements

- OpenCTI Platform >= 6.4.2

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

| Parameter       | config.yml      | Docker environment variable | Default | Mandatory | Description                                                                              |
|-----------------|-----------------|-----------------------------|---------|-----------|------------------------------------------------------------------------------------------|
| Connector ID    | id              | `CONNECTOR_ID`              | /       | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type            | `CONNECTOR_TYPE`            |         | Yes       | Should always be set to `INTERNAL_ENRICHMENT` for this connector.                        |
| Connector Name  | name            | `CONNECTOR_NAME`            |         | Yes       | Name of the connector.                                                                   |
| Connector Scope | scope           | `CONNECTOR_SCOPE`           |         | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | log_level       | `CONNECTOR_LOG_LEVEL`       | info    | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Connector Auto  | connector_auto	 | `CONNECTOR_AUTO`            | True    | Yes       | Must be `true` or `false` to enable or disable auto-enrichment of observables            |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter                         | config.yml   | Docker environment variable | Default                            | Mandatory | Description                                                             |
|-----------------------------------|--------------|-----------------------------|------------------------------------|-----------|-------------------------------------------------------------------------|
| API base URL                      | api_base_url | SILENTPUSH_API_BASE_URL     | https://app.silentpush.com/api/v1/ | No        | The Silent Push API URL                                                 |
| API key                           | api_key      | SILENTPUSH_API_KEY          |                                    | Yes       | You need an API key, sign up at https://explore.silentpush.com/register |
| Signed or self signed Certificate | verify_cert  | SILENTPUSH_VERIFY_CERT      | True                               | No        |                                                                         |
| TLP classification                | max_tlp      |                             |                                    | No        |                                                                         |

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

Then, start the connector from silentpush-enrichment/src:

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

This connector enriches Domains, IPv4, IPv6 and URLs observables.
Also enriches indicators containing those types of observables.


## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

Anything needed please talk to us at [info@silentpush.com](mailto:info@silentpush.com)
