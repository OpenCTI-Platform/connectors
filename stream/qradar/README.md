# OpenCTI qradar connector

This connector allows organizations to feed a **qradar** referencer sets using OpenCTI knowledge.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0
- QRadar >= 7.5.0

### Configuration

| Parameter                               | Docker envvar                           | Mandatory | Description                                                                                   |
|-----------------------------------------|-----------------------------------------|-----------|-----------------------------------------------------------------------------------------------|
| `opencti_url`                           | `OPENCTI_URL`                           | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                         | `OPENCTI_TOKEN`                         | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                          | `CONNECTOR_ID`                          | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_name`                        | `CONNECTOR_NAME`                        | Yes       | The name of the qradar instance, to identify it if you have multiple qradar connectors.       |
| `connector_scope`                       | `CONNECTOR_SCOPE`                       | Yes       | Must be `qradar`, not used in this connector.                                                 |
| `connector_confidence_level`            | `CONNECTOR_CONFIDENCE_LEVEL`            | Yes       | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`                   | `CONNECTOR_LOG_LEVEL`                   | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_consumer_count`              | `CONNECTOR_CONSUMER_COUNT`              | No        | Number of consumer/worker that will push data to qradar.                                      |
| `connector_live_stream_start_timestamp` | `CONNECTOR_LIVE_STREAM_START_TIMESTAMP` | No        | Start timestamp used on connector first start.                                                |
| `qradar_url`                            | `QRADAR_URL`                            | Yes       | The qradar instances REST API URLs as array                                                   |
| `qradar_ssl_verify`                     | `QRADAR_SSL_VERIFY`                     | Yes       | Enable the SSL certificate check for all instances (default: `true`)                          |
| `qradar_token`                          | `QRADAR_TOKEN`                          | Yes       | The qradar login users as array (same order as URLs)                                          |
| `qradar_reference_name`                 | `QRADAR_REFERENCE_NAME`                 | Yes       | The name of the reference set base name                                                       |