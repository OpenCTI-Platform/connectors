# OpenCTI RansomFeed Connector

## Introduction
This connector for OpenCTI automatically imports ransomware claim data from the RansomFeed API. Each claim is transformed into STIX 2.1 objects and sent to OpenCTI via RabbitMQ for processing by workers, enriching global ransomware threat intelligence. 

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

### Connector environment variables

| Parameter               | config.yml           | Docker environment variable        | Mandatory | Description                                                |
|-------------------------|----------------------|------------------------------------|-----------|-----------------------------------------------------------|
| Connector ID            | id                   | `CONNECTOR_ID`                     | Yes       | A unique identifier for this connector instance.          |
| Connector Type          | type                 | `CONNECTOR_TYPE`                   | Yes       | Must be `EXTERNAL_IMPORT`.                                |
| Connector Name          | name                 | `CONNECTOR_NAME`                   | Yes       | Name of the connector.                                    |
| Connector Scope         | scope                | `CONNECTOR_SCOPE`                  | Yes       | Scope of the connector (e.g., `ransomfeed`).              |
| Confidence Level        | confidence_level     | `CONNECTOR_CONFIDENCE_LEVEL`       | Yes       | Confidence level for created entities (0-100).            |
| Log Level               | log_level            | `CONNECTOR_LOG_LEVEL`              | Yes       | Log level (`debug`, `info`, `warning`, `error`).          |
| Duration Period         | duration_period      | `CONNECTOR_DURATION_PERIOD`        | Yes       | Interval between runs (ISO 8601 format, e.g., `PT1H`).    |

### RansomFeed-specific environment variables

| Parameter               | config.yml           | Docker environment variable        | Mandatory | Description                                                |
|-------------------------|----------------------|------------------------------------|-----------|-----------------------------------------------------------|
| API URL                 | api_url              | `RANSOMFEED_API_URL`               | Yes       | Base URL of the RansomFeed API.                           |
| TLP Level               | tlp_level            | `RANSOMFEED_TLP_LEVEL`             | No        | TLP marking level (default: `white`).                      |
| Create Indicators       | create_indicators    | `RANSOMFEED_CREATE_INDICATORS`     | No        | Create indicators from file hashes (default: `true`).     |


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

Then, start the connector from ransomfeed/src:

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

This connector follows OpenCTI best practices by creating STIX 2.1 objects and publishing them to RabbitMQ for processing by OpenCTI workers.

* **Data retrieval**: Automatic data retrieval via RansomFeed API.
* **STIX Objects created**:
  * `Identity` - Organization representing the victim
  * `Intrusion Set` - Ransomware group
  * `Report` - Contains all entities involved in the ransomware attack
  * `Location` - Country where the victim is located (if available)
  * `Domain Name` - Victim's website/domain (if available)
  * `Indicator` - File hash indicators (if available and enabled)
  * `Relationship` - Relationships between entities (`targets`, `located-at`, `belongs-to`)
  
* **Data modeling**: Following the pattern used in the `ransomwarelive` connector, this connector creates comprehensive **Report** entities (not Incidents) that contain all related entities and relationships for each ransomware attack.

* **Processing**: All STIX bundles are sent to OpenCTI's RabbitMQ queue for asynchronous processing by workers, rather than using direct GraphQL API calls.


## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

## Additional information

In case of errors, bugs, or any other issues please feel free to contact the main developer [Dario Fadda](dario@ransomfeed.it).
Main project: [Github](https://github.com/ransomfeed/Ransomfeed_OpenCTI_connector).
