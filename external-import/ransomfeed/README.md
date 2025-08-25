# OpenCTI Ransomfeed Connector

## Introduction
This custom connector for OpenCTI automatically imports ransomware claim data published by the official Ransomfeed.it external API. Each claim is transformed into OpenCTI-compatible STIX entities, thus enriching global ransomware threat intelligence. 

## Installation
```shell
pip install -r requirements.txt
python main.py
```

### Requirements

- OpenCTI Platform >= 6
- Python ≥ 3.8

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |


## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
docker build . -t ransomfeed-connector
docker run --rm ransomfeed-connector
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

* Automatic data retrieval via API (`GET`).
* Creation of:

  * `Intrusion Set` (gang ransomware)
  * `Identity` (victims)
  * `Incident` (attack)
  * `Indicator` (hash, if available)
* Relationships between objects:

  * `attributed-to`, `targets`, `indicates`
* Support for field geolocation `country`.


## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

## Additional information

In case of errors, bugs, or any other issues please feel free to contact the main developer [Dario Fadda](dario@ransomfeed.it).
Main project: [Github](https://github.com/ransomfeed/Ransomfeed_OpenCTI_connector).
