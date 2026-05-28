# Echo CTI External Import Connector

The OpenCTI Echo CTI connector can be used to import threat intelligence data (IOCs) from the Echo CTI platform.
The connector fetches indicators such as IPs, URLs, hashes, and IP ranges from the Echo CTI API and imports them into OpenCTI.

## Installation

The OpenCTI Echo CTI connector is a standalone Python process that must have access
to the OpenCTI platform and RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector can be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-echocti:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that can be used independently or
integrated into the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.

### Configuration variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter `OpenCTI` | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------------|------------|-----------------------------|-----------|------------------------------------------------------|
| URL                 | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| Token               | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter `Connector` | config.yml          | Docker environment variable   | Default     | Mandatory | Description                                                                                      |
|-----------------------|---------------------|-------------------------------|-------------|-----------|--------------------------------------------------------------------------------------------------|
| ID                    | `id`                | `CONNECTOR_ID`                | /           | Yes       | A unique `UUIDv4` identifier for this connector instance.                                        |
| Name                  | `name`              | `CONNECTOR_NAME`              | `Echo CTI`  | Yes       | Full name of the connector: `Echo CTI`.                                                          |
| Scope                 | `scope`             | `CONNECTOR_SCOPE`             | `echocti`   | Yes       | Must be `echocti`, not used in this connector.                                                   |
| Run and Terminate     | `run_and_terminate` | `CONNECTOR_RUN_AND_TERMINATE` | `False`     | No        | Launch the connector once if set to True. Takes 2 available values: `True` or `False`.           |
| Duration Period       | `duration_period`   | `CONNECTOR_DURATION_PERIOD`   | /           | Yes       | Determines the time interval between each launch of the connector in ISO 8601, ex: `PT1H`.       |
| Queue Threshold       | `queue_threshold`   | `CONNECTOR_QUEUE_THRESHOLD`   | `500`       | No        | Used to determine the limit (RabbitMQ) in MB at which the connector must go into buffering mode. |
| Log Level             | `log_level`         | `CONNECTOR_LOG_LEVEL`         | /           | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.           |

Below are the parameters you'll need to set for Echo CTI connector:

| Parameter `Echo CTI`       | config.yml           | Docker environment variable    | Default                                  | Mandatory | Description                                                                                |
|----------------------------|----------------------|--------------------------------|------------------------------------------|-----------|--------------------------------------------------------------------------------------------|
| API URL                    | `api_url`            | `ECHOCTI_API_URL`              | `https://api.echocti.com/ioc2/feeds`     | No        | The Echo CTI API endpoint URL.                                                             |
| Client ID                  | `client_id`          | `ECHOCTI_CLIENT_ID`            | `ChangeMe`                               | Yes       | Your Echo CTI client ID.                                                                   |
| Client Secret              | `client_secret`      | `ECHOCTI_CLIENT_SECRET`        | `ChangeMe`                               | Yes       | Your Echo CTI client secret.                                                               |
| Verify SSL                 | `verify_ssl`         | `ECHOCTI_VERIFY_SSL`           | `true`                                   | No        | Whether to verify SSL certificates.                                                        |
| Type                       | `type`               | `ECHOCTI_TYPE`                 | `all`                                    | No        | IOC type filter: `ip`, `url`, `hash`, `ip-range`, `all` (comma-separated for multiple).   |
| State                      | `state`              | `ECHOCTI_STATE`                | `active`                                 | No        | IOC state filter: `active`, `removed`, `false-positive`, `white-listed`, `all`.           |
| Time Since Created         | `time_since_created` | `ECHOCTI_TIME_SINCE_CREATED`   | /                                        | No        | Time filter for creation: `1h`, `1d`, `7d`, `30d`, `1y`.                                  |
| Time Since Updated         | `time_since_updated` | `ECHOCTI_TIME_SINCE_UPDATED`   | /                                        | No        | Time filter for last update: `1h`, `1d`, `7d`, `30d`, `1y`.                               |
| Max Count                  | `max_count`          | `ECHOCTI_MAX_COUNT`            | `0`                                      | No        | Maximum number of IOCs to fetch (0 = all).                                                 |
| Vendor                     | `vendor`             | `ECHOCTI_VENDOR`               | /                                        | No        | Optional vendor filter.                                                                    |
| Tag                        | `tag`                | `ECHOCTI_TAG`                  | /                                        | No        | Optional tag filter.                                                                       |
| Default Confidence         | `default_confidence` | `ECHOCTI_DEFAULT_CONFIDENCE`   | `50`                                     | No        | Default confidence score for indicators (0-100).                                           |

## Deployment

### Docker Deployment

Build and run the connector using Docker:

```bash
docker build -t opencti/connector-echocti:latest .
docker compose up -d
```

### Manual Deployment

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Copy and configure the sample configuration:
```bash
cp src/config.yml.sample src/config.yml
# Edit src/config.yml with your settings
```

3. Run the connector:
```bash
cd src
python -m echocti
```

## Behavior

The connector will:
1. Connect to the Echo CTI API using the provided credentials
2. Fetch IOCs based on the configured filters (type, state, time range, etc.)
3. Convert the IOCs to STIX 2.1 format
4. Send the STIX bundle to OpenCTI
5. Wait for the configured duration period before the next run
