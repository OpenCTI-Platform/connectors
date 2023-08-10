# OpenCTI Logrhythm Connector

This connector allows organizations to feed a **logrhythm** lists using OpenCTI knowledge.

Note:
For a performance reasons, the connector designed to create multiple lists using the base name provided in the configuration `lr_list_name: opencti` and the list in Logrhythm will be like that `opencti_Url`.
It will be better to build a use case for each type.
## Installation

### Requirements

- OpenCTI Platform >= 5.0.0

### Configuration

| Parameter                               | Docker envvar                           | Mandatory    | Description                                                                                                                           |
|-----------------------------------------|-----------------------------------------| ------------ |---------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                           | `OPENCTI_URL`                           | Yes          | The URL of the OpenCTI platform.                                                                                                      |
| `opencti_token`                         | `OPENCTI_TOKEN`                         | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                           |
| `connector_id`                          | `CONNECTOR_ID`                          | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                    |
| `connector_type`                        | `CONNECTOR_TYPE`                        | Yes          | Must be `STREAM` (this is the connector type).                                                                                        |
| `connector_name`                        | `CONNECTOR_NAME`                        | Yes          | The name of the logrhythm instance, to identify it if you have multiple logrhythm connectors.                                         |
| `connector_scope`                       | `CONNECTOR_SCOPE`                       | Yes          | Must be `logrhythm`, not used in this connector.                                                                                      |
| `connector_confidence_level`            | `CONNECTOR_CONFIDENCE_LEVEL`            | Yes          | The default confidence level for created sightings (a number between 1 and 4).                                                        |
| `connector_log_level`                   | `CONNECTOR_LOG_LEVEL`                   | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                         |
| `connector_consumer_count`              | `CONNECTOR_CONSUMER_COUNT`              | No           | Number of consumer/worker that will push data to logrhythm.                                                                           |
| `connector_live_stream_start_timestamp` | `CONNECTOR_LIVE_STREAM_START_TIMESTAMP` | No           | Start timestamp used on connector first start.                                                                                        |
| `lr_url`                                | `LR_URL`                                | Yes          | The logrhythm instances REST API URLs as array                                                                                        |
| `lr_token`                              | `LR_TOKEN`                              | Yes          | The logrhythm login users as array (same order as URLs)                                                                               |
| `lr_ssl_verify`                         | `LR_SSL_VERIFY`                         | Yes          | Enable the SSL certificate check for all instances (default: `true`)                                                                  |
| `lr_entity_name`                        | `LR_ENTITY_NAME`                        | Yes          | The entity name from logrhythm, should be the name from database could be acquired from LR client console or API call to /identities/ |
| `lr_list_name`                          | `LR_list_NAME`                          | Yes          | The name of the list set base name Ex Opencti.                                                                                        |
| `lr_ignore_types`                       | `LR_IGNORE_TYPES`                       | Yes          | The list of entity types to ignore.                                                                                                   |
| `metrics_enable`                        | `METRICS_ENABLE`                        | No           | Whether or not Prometheus metrics should be enabled.                                                                                  |
| `metrics_addr`                          | `METRICS_ADDR`                          | No           | Bind IP address to use for metrics endpoint.                                                                                          |
| `metrics_port`                          | `METRICS_PORT`                          | No           | Port to use for metrics endpoint.                                                                                                     |