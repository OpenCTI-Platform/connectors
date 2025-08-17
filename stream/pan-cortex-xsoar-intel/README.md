# OpenCTI PAN Cortex XSOAR intel

This connector allows organizations to push indicators to PAN Cortex XSOAR.

## Installation

### Configuration

| Parameter                               | Docker envvar                           | Mandatory | Description                                                                                   |
|-----------------------------------------|-----------------------------------------| --------- |-----------------------------------------------------------------------------------------------|
| `opencti_url`                           | `OPENCTI_URL`                           | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                         | `OPENCTI_TOKEN`                         | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                          | `CONNECTOR_ID`                          | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_name`                        | `CONNECTOR_NAME`                        | Yes       | The name of the XSOAR instance, to identify it if you have multiple XSOAR connectors.         |
| `connector_scope`                       | `CONNECTOR_SCOPE`                       | Yes       | Must be `xsoar`, not used in this connector.                                                  |
| `connector_confidence_level`            | `CONNECTOR_CONFIDENCE_LEVEL`            | Yes       | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`                   | `CONNECTOR_LOG_LEVEL`                   | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_live_stream_id`              | `CONNECTOR_LIVE_STREAM_ID`              | Yes       | The Live Stream ID of the stream created in the OpenCTI interface.                            |
| `connector_live_stream_start_timestamp` | `CONNECTOR_LIVE_STREAM_START_TIMESTAMP` | No        | Start timestamp used on connector first start.                                                |
| `xsoar_url`                             | `XSOAR_URL`                             | Yes       | The XSOAR API URL (generally prefixed with "api-" in PAN cloud)                               |
| `xsoar_key_id`                          | `XSOAR_KEY_ID`                          | Yes       | The XSOAR key ID                                                                              |
| `xsoar_key`                             | `XSOAR_KEY`                             | Yes       | The XSOAR key                                                                                 |
| `metrics_enable`                        | `METRICS_ENABLE`                        | No        | Whether or not Prometheus metrics should be enabled.                                          |
| `metrics_addr`                          | `METRICS_ADDR`                          | No        | Bind IP address to use for metrics endpoint.                                                  |
| `metrics_port`                          | `METRICS_PORT`                          | No        | Port to use for metrics endpoint.                                                             |