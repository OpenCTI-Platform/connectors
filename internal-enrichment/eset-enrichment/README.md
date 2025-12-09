# ESET ETI Report Enrichment Connector

Connector for automatic enrichment of ETI reports.

## Introduction

ESET ETI Report objects are decorated with a url link to the [ESET Threat Intelligence](https://eti.eset.com) portal,
where the report can be downloaded in PDF format.
The connector automates downloading PDF reports and enriching MISP report STIX objects.

## Installation

### Requirements

- OpenCTI Platform >= 6.5.1
- ESET Threat Intelligence API key and secret. For more information, check the [ESET Threat Intelligence](https://help.eset.com/eti_portal/en-US/) documentation.

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

| Parameter       | config.yml | Docker environment variable | Default         | Mandatory | Description                                                                              |
|-----------------|------------|-----------------------------|-----------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID    | id         | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type       | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT | Yes       | Should always be set to `INTERNAL_ENRICHMENT` for this connector.                        |
| Connector Name  | name       | `CONNECTOR_NAME`            |                 | Yes       | Name of the connector.                                                                   |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Connector Auto  | auto       | `CONNECTOR_AUTO`            | True            | Yes       | Must be `true` or `false` to enable or disable auto-enrichment of observables            |

### ESET ETI Report Enrichment Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter  | config.yml  | Docker environment variable | Default | Mandatory | Description                                                 |
|------------|-------------|-----------------------------|---------|-----------|-------------------------------------------------------------|
| API key    | api_key     | `ESET_API_KEY`              |         | Yes       | The API key generated on ESET Threat Intelligence portal    |
| API secret | api_secret  | `ESET_API_SECRET`           |         | Yes       | The API secret generated on ESET Threat Intelligence portal |

For more information on how to create access credentials, visit [ETI online help](https://help.eset.com/eti_portal/en-US/access_credentials.html).

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20` (see [minimal version](#requirements) required by the connector).
If you don't, it will take the latest version, but sometimes the OpenCTI SDK fails to initialize.

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

Replace the configuration variables (provide all required variables) with the appropriate configurations for
your environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector:

```shell
python3 main.py
```

### Debugging ###

The connector can be debugged by setting appropriate log level (debug).
