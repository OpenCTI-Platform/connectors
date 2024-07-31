# ZeroFox Threat Intelligence Connector

The OpenCTI ZeroFox connector can be used to import knowledge from the ZeroFox
 platform. The connector leverages the Threat Intelligence data feeds to get data about ...

**Note**: Requires subscription to the ZeroFox CTI feeds. The subscription
details dictate what feeds are available to the connector.
In order to get a suscription, please contact 

## Installation

The OpenCTI ZeroFox connector is a standalone Python process that must have access
to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration as exported environment variables or within a Docker with
the image `opencti/connector-zerofox:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.


### Requirements

- OpenCTI Platform >= 6.2.9

### Configuration

| Parameter                        | Docker envvar                    | Mandatory    | Description                                                                                     |
| -------------------------------- | -------------------------------- | ------------ | ----------------------------------------------------------------------------------------------- |
| `opencti_url`                    | `OPENCTI_URL`                    | Yes          | The URL of the OpenCTI platform.                                                                |
| `opencti_token`                  | `OPENCTI_TOKEN`                  | Yes          | The default admin token configured in the OpenCTI platform parameters file.                     |
| `connector_id`                   | `CONNECTOR_ID`                   | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                              |
| `connector_name`                 | `CONNECTOR_NAME`                 | Yes          | Option `ZeroFox`                                                                                |
| `connector_scope`                | `CONNECTOR_SCOPE`                | Yes          | Supported scope: Template Scope (MIME Type or Stix Object)                                      |
| `connector_run_every`            | `CONNECTOR_RUN_EVERY`            | No           | How often data ingestion occurs, in format `{number}{s, m, h, d}`, reccommended value is 24h    |
| `connector_first_run`            | `CONNECTOR_FIRST_RUN`            | No           | The scope of data queried when the connector is initialized in format `{number}{s, m, h, d}`, defaults to 1d|
| `connector_update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | No           | If an entity already exists, update its attributes with information provided by this connector. |
| `username`                       | `ZEROFOX_USERNAME`               | Yes          | A ZeroFox platform username                                                                     |
| `password`                       | `ZEROFOX_PASSWORD`               | Yes          | A personal access token for accesing the ZeroFox API                                            |
| `zerofox_collectors`             | `ZEROFOX_COLLECTORS`             | No           | A comma-separated list of collector names to use by the connector. Uses all of them if ommited  |

