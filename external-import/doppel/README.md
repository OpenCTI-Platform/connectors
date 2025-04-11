# OpenCTI Doppel Connector

This connector fetches alerts from the Doppel API and imports them into OpenCTI.



### Requirements

- OpenCTI Platform version >= 6.x
- Access to a **Doppel tenant** (API key and API URL)



##  Configuration

There are a number of configuration options, which can be set either in the main OpenCTI docker-compose.yml (for Docker deployment) or in the connector’s config.yml (for manual/standalone deployment).

 Docker **env variables override** values in `config.yml`.


###  Configuration Parameters


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

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```
Example:
docker build -t doppel-connector:latest . (Use same image name in `docker-compose.yml`)

Make sure to replace the environment variables in the main OpenCTI `docker-compose.yml` file with the appropriate configurations for your environment.
Then, start the container using that updated docker-compose.yml.

```shell
docker compose up -d
# -d for detached
```
 

> ⚠️ **Note**  
> Although the Doppel connector folder contains its own `docker-compose.yml`, it’s not used directly.  
> The connector should be integrated into the **main OpenCTI `docker-compose.yml`** file alongside the other services.


### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from doppel/src:

```shell
python3 main.py
```

> ⚠️ **Note**  
>If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `polling_interval`.

## Verification

To verify the connector is working, you can navigate to Data->Entities in the OpenCTI platform and see the new imported data there. For troubleshooting or additional verification, please view the Connector logs.


## Debugging

The connector can be debugged by setting the appropriate log level.

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
