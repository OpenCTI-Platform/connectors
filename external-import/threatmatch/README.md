# OpenCTI ThreatMatch Connector

## Installation

The ThreatMatch connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a Docker with the image `opencti/connector-threatmatch:latest`. We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

| Parameter                         | Docker envvar                     | Mandatory    | Description                                                                                         |
| --------------------------------- | --------------------------------- | ------------ | --------------------------------------------------------------------------------------------------- |
| `opencti_url`                     | `OPENCTI_URL`                     | Yes          | The URL of the OpenCTI platform.                                                                    |
| `opencti_token`                   | `OPENCTI_TOKEN`                   | Yes          | The default admin token configured in the OpenCTI platform parameters file.                         |
| `connector_id`                    | `CONNECTOR_ID`                    | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                  |
| `connector_type`                  | `CONNECTOR_TYPE`                  | Yes          | Must be `EXTERNAL_IMPORT` (this is the connector type).                                             |
| `connector_name`                  | `CONNECTOR_NAME`                  | Yes          | The name of the connector, can be just "ThreatMatch"                                                |
| `connector_scope`                 | `CONNECTOR_SCOPE`                 | Yes          | Must be `threatmatch`, not used in this connector.                                                  |
| `connector_confidence_level`      | `CONNECTOR_CONFIDENCE_LEVEL`      | Yes          | The default confidence level for created relationships (a number between 1 and 4).                  |
| `connector_update_existing_data`  | `CONNECTOR_UPDATE_EXISTING_DATA`  | Yes          | If an entity already exists, update its attributes with information provided by this connector.     |
| `connector_log_level`             | `CONNECTOR_LOG_LEVEL`             | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).       |
| `threatmatch_url`                 | `THREATMATCH_URL`                 | Yes          | The ThreatMatch URL.                                                                                |
| `threatmatch_client_id`           | `THREATMATCH_CLIENT_ID`           | Yes          | The ThreatMatch client ID.                                                                          |
| `threatmatch_client_secret`       | `THREATMATCH_CLIENT_SECRET`       | Yes          | The ThreatMatch client secret.                                                                      |
| `threatmatch_interval`            | `THREATMATCH_INTERVAL`            | No           | An interval (in minutes) for data gathering from ThreatMatch                                        |
| `threatmatch_import_from_date`    | `THREATMATCH_IMPORT_FROM_DATE`    | No           | A date formatted `YYYY-MM-DD HH:MM` to import elements only from this date                          |
| `threatmatch_import_profiles`     | `THREATMATCH_IMPORT_PROFILES`     | No           | A boolean (`True` or `False`), import profiles collection from ThreatMatch.                         |
| `threatmatch_import_alerts`       | `THREATMATCH_IMPORT_ALERTS`       | No           | A boolean (`True` or `False`), import alerts collection from ThreatMatch.                           |
| `threatmatch_import_reports`      | `THREATMATCH_IMPORT_REPORTS`      | No           | A boolean (`True` or `False`), import reports collection from ThreatMatch                           |