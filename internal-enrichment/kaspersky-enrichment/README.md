# OpenCTI Internal Enrichment Connector Kaspersky

## Status Filigran

| Status            | Date          | Comment |
|-------------------|---------------|---------|
| Filigran Verified | 11/28/2025    | -       |

## Introduction

Kaspersky enrichment is used to investigate objects by using the Kaspersky Threat Intelligence Portal such as File, IPV4, Domain/Hostname and URL.

> [!NOTE]
> At this time, the connector only supports the enrichment of File-type observables. Enrichment for other observable types will be introduced in future releases.

## Requirements

- OpenCTI Platform >= 6.8.15

## Configuration variables environment

Find all the configuration variables available (default/required) here: [Connector Configurations](./__metadata__)

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.8.15`. If you don't, it will take the latest version, but
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

Then, start the connector from kaspersky-enrichment/src:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## API Endpoints in Use

| API                                             | Use in the connector     |
|-------------------------------------------------|--------------------------|
| https://tip.kaspersky.com/api/hash/{hash_value} | Enrich 'File' observable |


## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.
