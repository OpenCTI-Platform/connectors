# OpenCTI Stream Exporter Connector

This connector listen to a stream and send the messages to a bucket in Minio. This connector is to be used with the [stream-importer](../../external-import/stream-importer/) connector to synchronize two OpenCTI instances that don't have direct access with each other. The events of the live-stream can be exporter on minio and then re-imported from minio using the stream-importer connector.

## Installation

### Requirements

- OpenCTI Platform >= 6.3.4

### Configuration

| Parameter                               | Docker envvar                           | Mandatory | Description                                                                                   |
|-----------------------------------------|-----------------------------------------|-----------|-----------------------------------------------------------------------------------------------|
| `opencti_url`                           | `OPENCTI_URL`                           | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                         | `OPENCTI_TOKEN`                         | Yes       | The token configured in the OpenCTI platform parameters file.                                 |
| `connector_id`                          | `CONNECTOR_ID`                          | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_name`                        | `CONNECTOR_NAME`                        | Yes       | Connector name.                                                                               |
| `connector_scope`                       | `CONNECTOR_SCOPE`                       | Yes       | Must be `stream-exporter`, not used in this connector.                                        |
| `connector_confidence_level`            | `CONNECTOR_CONFIDENCE_LEVEL`            | Yes       | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`                   | `CONNECTOR_LOG_LEVEL`                   | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_consumer_count`              | `CONNECTOR_CONSUMER_COUNT`              | No        | Number of consumer/worker that will push data.                                                |
| `connector_live_stream_start_timestamp` | `CONNECTOR_LIVE_STREAM_START_TIMESTAMP` | No        | Start timestamp used on connector first start, default is empty (all data).                   |
| `minio_endpoint`                        | `MINIO_ENDPOINT`                        | Yes       | The minio endpoint to save the messages.                                                      |
| `minio_port`                            | `MINIO_PORT`                            | Yes       | The minio port.                                                                               |
| `minio_bucket`                          | `MINIO_BUCKET`                          | Yes       | The minio bucket to save the messages, created if it does not exist.                          |
| `minio_folder`                          | `MINIO_FOLDER`                          | Yes       | The minio folder to save the messages.                                                        |
| `minio_access_key`                      | `MINIO_ACCESS_KEY`                      | Yes       | The minio access key.                                                                         |
| `minio_secret_key`                      | `MINIO_SECRET_KEY`                      | Yes       | The minio secret key.                                                                         |
| `minio_secure`                          | `MINIO_SECURE`                          | No        | Whether to use SSL of not, default False.                                                     |
| `minio_cert_check`                      | `MINIO_CERT_CHECK`                      | No        | Whether to check certificate.                                                                 |
| `write_every_sec`                       | `WRITE_EVERY_SEC`                       | No        | Time in seconds between two writes on minio                                                   |

## State

Since we are bulking events before writing them on minio, we need to keep track of another state for the `start_from` value. This value is a `msg.id` from the SSE client and is changed when the `ListenStream` passes the event to the callback of the connector. However, if the connector crashed, the state `start_from` will have been updated with `msg.id` that have not been saved on minio. For this, we have another state `last_written_msg_id` that is updated once the data are written on minio. When the connector starts, it set the `start_from` with the `last_written_msg_id` value if any.
