# OpenCTI Urlscan.io Connector

## Installation

The Urlscan connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ server. 
RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a Docker with the image `opencti/connector-urlscan:latest`. 
We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

| Parameter                        | Docker envvar                    | Mandatory | Description                                                                                        |
|----------------------------------|----------------------------------|-----------|----------------------------------------------------------------------------------------------------|
| `opencti_url`                    | `OPENCTI_URL`                    | Yes       | The URL of the OpenCTI platform.                                                                   |
| `opencti_token`                  | `OPENCTI_TOKEN`                  | Yes       | The default admin token configured in the OpenCTI platform parameters file.                        |
| `connector_id`                   | `CONNECTOR_ID`                   | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                 |
| `connector_type`                 | `CONNECTOR_TYPE`                 | Yes       | Must be `EXTERNAL_IMPORT` (this is the connector type).                                            |
| `connector_name`                 | `CONNECTOR_NAME`                 | Yes       | The name of the connector, can be just "ThreatMatch"                                               |
| `connector_scope`                | `CONNECTOR_SCOPE`                | Yes       | Must be `threatmatch`, not used in this connector.                                                 |
| `connector_confidence_level`     | `CONNECTOR_CONFIDENCE_LEVEL`     | Yes       | The default confidence level for created relationships (0 -> 100).                                 |
| `connector_update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | Yes       | If an entity already exists, update its attributes with information provided by this connector.    |
| `connector_log_level`            | `CONNECTOR_LOG_LEVEL`            | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).      |
| `connector_create_indicators`    | `CONNECTOR_CREATE_INDICATORS`    | No        | Create indicators for each observable processed.                                                   |
| `connector_tlp`                  | `CONNECTOR_TLP`                  | No        | The TLP to apply to any indicators and observables, this could be `white`,`green`,`amber` or `red` |
| `connector_labels`               | `CONNECTOR_LABELS`               | No        | Comma delimited list of labels to apply to each observable.                                        | 
| `connector_interval`             | `CONNECTOR_INTERVAL`             | No        | An interval (in minutes) for data gathering from Urlscan.                                          |
| `urlscan_url`                    | `URLSCAN_URL`                    | Yes       | The Urlscan URL.                                                                                   |
| `urlscan_api_key`                | `URLSCAN_API_KEY`                | Yes       | The Urlscan client secret.                                                                         |
