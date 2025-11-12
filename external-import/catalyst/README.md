# OpenCTI CATALYST Connector

This connector imports data from the CATALYST platform, provided by PRODAFT. The connector leverages the CATALYST API to retrieve threat intelligence and integrate it into your OpenCTI instance.

## Introduction

The CATALYST connector retrieves threat intelligence from the CATALYST platform and converts it into STIX format for integration into OpenCTI. It allows organizations to enrich their threat intelligence with data from CATALYST, including indicators and observables. This connector relies on the `python-catalyst` package to retrieve and convert the data.

## Installation

### Requirements

- OpenCTI Platform

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

| Parameter       | config.yml | Docker environment variable | Default         | Mandatory | Description                                                                              |
|-----------------|------------|-----------------------------|-----------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID    | id         | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type       | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                            |
| Connector Name  | name       | `CONNECTOR_NAME`            | CATALYST        | Yes       | Name of the connector.                                                                   |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           | catalyst        | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the CATALYST connector:

| Parameter       | config.yml       | Docker environment variable    | Default | Mandatory | Description                                                                                                                   |
|-----------------|------------------|-------------------------------|---------|-----------|-------------------------------------------------------------------------------------------------------------------------------|
| Base URL        | base_url         | `CATALYST_BASE_URL`           | /       | Yes       | The base URL for the CATALYST API.                                                                                           |
| **API Key**     | **api_key**      | **`CATALYST_API_KEY`**        | /       | **No**   | **Your CATALYST API key, which can be obtained through your CATALYST profile.. If not given, public endpoint will be used.** |
| TLP Filter      | tlp_filter       | `CATALYST_TLP_FILTER`         | ALL     | No        | Comma-separated list of TLP levels to fetch (options: CLEAR, GREEN, AMBER, RED, ALL)                                          |
| Category Filter | category_filter  | `CATALYST_CATEGORY_FILTER`    | ALL     | No        | Comma-separated list of categories to fetch (options: DISCOVERY, ATTRIBUTION, RESEARCH, FLASH_ALERT, ALL)                     |
| Sync Days Back  | sync_days_back   | `CATALYST_SYNC_DAYS_BACK`     | 730     | No        | Number of days to go back when no last_run is present                                                                          |
| Create Observables | create_observables | `CATALYST_CREATE_OBSERVABLES` | true    | No        | Whether to create observables from the data                                                                                    |
| Create Indicators  | create_indicators  | `CATALYST_CREATE_INDICATORS`  | false    | No        | Whether to create indicators from the data                                                                                     |

## Deployment

### Docker Deployment

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided docker-compose.yml:

```shell
docker compose up -d
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for your environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector:

```shell
python3 main.py
```

## Testing

To run tests on the connector, navigate to the tests directory and run pytest:

```shell
cd tests
pip install -r test-requirements.txt
pytest .
```
