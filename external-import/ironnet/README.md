# OpenCTI IronNet Connector

The OpenCTI IronNet connector can be used to import knowledge from the IronNet IronRadar threat intel feed.

**Note**: Requires subscription to the [IronRadar](https://www.ironnet.com/products/ironradar) threat intel feed.

## Installation

The OpenCTI IronNet connector is a standalone Python process that must have access
to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-ironnet:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

The connector can be configured with the following variables:

| Config Parameter           | Docker env var                     | Default                                          | Description                                                    |
|----------------------------|------------------------------------|--------------------------------------------------|----------------------------------------------------------------|
| `api_url`                  | `IRONNET_API_URL`                  | `https://api.threatanalysis.io/prod/all/1d/json` | The URL for the IronNet APIs.                                  |
| `api_key`                  | `IRONNET_API_KEY`                  | `ChangeMe`                                       | The IronNet API client secret.                                 |
| `verify`                   | `IRONNET_VERIFY`                   | `true`                                           | Verify SSL connections to the IronNet API.                     |
| `create_indicators`        | `IRONNET_CREATE_INDICATORS`        | `true`                                           | If true then indicators will be created from the data.         |
| `create_ip_indicators`     | `IRONNET_CREATE_IP_INDICATORS`     | `false`                                          | If true then IP based indicators will also be created.         |
| `ip_indicator_valid_until` | `IRONNET_IP_INDICATOR_VALID_UNTIL` | `P90D`                                           | ISO8601 time-delta for how long IP indicators should be valid. |
| `update_existing_data`     | `CONNECTOR_UPDATE_EXISTING_DATA`   | `true`                                           | Update existing data bundle flag.                              |
| `interval`                 | `CONNECTOR_INTERVAL`               | `86400`                                          | Interval in minutes between runs.                              |
| `loop_interval`            | `CONNECTOR_LOOP_INTERVAL`          | `600`                                            | Interval in minutes between loops.                             |

## Filtering

The URL has several query parameters that can be used to filter the data received, such as IP/domain, confidence level, or the threat_type. See the API docs [here](https://api.threatanalysis.io/prod/docs/index.html).

Example: `https://api.threatanalysis.io/prod/all/1d/json?filter=domain&confidence=high&threat_type=recon`
