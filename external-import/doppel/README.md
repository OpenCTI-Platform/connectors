# OpenCTI Doppel Connector

This connector fetches alerts from the Doppel API and imports them into OpenCTI as.

## Installation

### Requirements

- OpenCTI Platform version >= 6.x
- Access to a **Doppel tenant** (API key and API URL)


## 🔧 Configuration

The connector accepts config via:

- `docker-compose.yml` (Docker mode)
- `config.yml` (manual mode)

💡 Docker **env vars override** values in `config.yml`.


## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### 🔧 Configuration Parameters

These environment variables can be set via `config.yml` or in `docker-compose.yml`.

| Parameter               | Env Variable                 | Default          | Required | Description                                                   |
|------------------------|------------------------------|------------------|----------|---------------------------------------------------------------|
| OpenCTI URL            | `OPENCTI_URL`                | -                | Yes      | URL of the OpenCTI platform                                   |
| OpenCTI Token          | `OPENCTI_TOKEN`              | -                | Yes      | API token for OpenCTI                                         |
| Connector ID           | `CONNECTOR_ID`               | -                | Yes      | Unique UUID for this connector instance                       |
| Connector Name         | `CONNECTOR_NAME`             | -                | Yes      | Name to display inside OpenCTI                                |
| Connector Type         | `CONNECTOR_TYPE`             | `EXTERNAL_IMPORT`| Yes      | Should always be `EXTERNAL_IMPORT`                            |
| Connector Scope        | `CONNECTOR_SCOPE`            | -                | Yes      | Scope of the data being imported (e.g., `Indicator`)          |
| Log Level              | `CONNECTOR_LOG_LEVEL`        | `info`           | No       | Log verbosity (`debug`, `info`, `warn`, `error`)              |
| Doppel API URL         | `DOPPEL_API_URL`             | -                | Yes      | URL for Doppel alerts API                                     |
| Doppel API Key         | `DOPPEL_API_KEY`             | -                | Yes      | API Key to authenticate with Doppel                           |
| Update Existing Data   | `UPDATE_EXISTING_DATA`       | `true`           | No       | Whether to update existing STIX objects in OpenCTI            |
| Polling Interval       | `POLLING_INTERVAL`           | `3600`           | No       | Interval (in seconds) between API polling                     |
| Historical Polling Days| `HISTORICAL_POLLING_DAYS`    | `30`             | No       | Days of historical data to pull on first run                  |

### Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.8.5`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in the main OpenCTI `docker-compose.yml` file with the appropriate configurations for your environment.
Then, start the container using that updated docker-compose.yml.
 

## Additional note
Although the Doppel connector folder contains its own `docker-compose.yml`, it’s not used directly. Instead, the connector should be integrated into the main OpenCTI `docker-compose.yml` alongside the other services.

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

## Additional note
If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `polling_interval`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior


## Debugging

The connector can be debugged by setting the appropiate log level.

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
