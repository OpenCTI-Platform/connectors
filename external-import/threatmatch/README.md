# OpenCTI ThreatMatch Connector

## Installation

The ThreatMatch connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ.
RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration
in the `config.yml` file or within a Docker with the image `opencti/connector-threatmatch:latest`. We provide an example
of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global
`docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port
configured in the OpenCTI platform.

## Configuration

| Parameter                      | Docker envvar                  | Mandatory | Description                                                                                                                                             |
|--------------------------------|--------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                  | `OPENCTI_URL`                  | Yes       | The URL of the OpenCTI platform.                                                                                                                        |
| `opencti_token`                | `OPENCTI_TOKEN`                | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                                             |
| `connector_id`                 | `CONNECTOR_ID`                 | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                      |
| `connector_name`               | `CONNECTOR_NAME`               | Yes       | The name of the connector, can be just "ThreatMatch"                                                                                                    |
| `connector_scope`              | `CONNECTOR_SCOPE`              | Yes       | Must be `threatmatch`, not used in this connector.                                                                                                      |
| `connector_log_level`          | `CONNECTOR_LOG_LEVEL`          | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                           |
| `connector_duration_period`    | `CONNECTOR_DURATION_PERIOD`    | Yes       | The duration period in ISO 8601 format, e.g., `P1D` for one day. This is the period of time to process.                                                 |
| `threatmatch_url`              | `THREATMATCH_URL`              | Yes       | The ThreatMatch URL.                                                                                                                                    |
| `threatmatch_client_id`        | `THREATMATCH_CLIENT_ID`        | Yes       | The ThreatMatch client ID.                                                                                                                              |
| `threatmatch_client_secret`    | `THREATMATCH_CLIENT_SECRET`    | Yes       | The ThreatMatch client secret.                                                                                                                          |
| `threatmatch_import_from_date` | `THREATMATCH_IMPORT_FROM_DATE` | No        | to import elements from X Days as ISO 8601 format, e.g., `P30D` ~~or a date formatted `YYYY-MM-DD HH:MM`~~ (deprecated)                                 |
| `threatmatch_import_profiles`  | `THREATMATCH_IMPORT_PROFILES`  | No        | A boolean (`True` or `False`), import profiles collection from ThreatMatch.                                                                             |
| `threatmatch_import_alerts`    | `THREATMATCH_IMPORT_ALERTS`    | No        | A boolean (`True` or `False`), import alerts collection from ThreatMatch.                                                                               |
| `threatmatch_import_iocs`      | `THREATMATCH_IMPORT_IOCS`      | No        | A boolean (`True` or `False`), import iocs collection from ThreatMatch                                                                                  |
| `threatmatch_tlp_level`        | `THREATMATCH_TLP_LEVEL`        | No        | The TLP level to use for the imported elements missing a TLP level. It can be `white`, `green`, `amber`, `amber+strict`, or `red`. Defaults to `amber`. |
