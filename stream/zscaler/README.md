# OpenCTI Zscaler Connector

This connector enables organizations to integrate **OpenCTI** intelligence into their **Zscaler** environment.

## Installation

### Requirements

- OpenCTI Platform >= 6.0.0

### Configuration

| Parameter                               | Docker Env Variable                             | Mandatory  | Description                                                                                     |
|-----------------------------------------|-------------------------------------------------|------------|------------------------------------------------------------------------------------------------ |
| `OPENCTI_URL`                           | `OPENCTI_URL`                                   | Yes        | The URL of the OpenCTI platform.                                                                |
| `OPENCTI_TOKEN`                         | `OPENCTI_TOKEN`                                 | Yes        | The API token of the OpenCTI platform.                                                          |
| `CONNECTOR_ID`                          | `CONNECTOR_ID`                                  | Yes        | A unique `UUIDv4` for this connector.                                                           |
| `CONNECTOR_TYPE`                        | `CONNECTOR_TYPE`                                | Yes        | The type of the connector. Must be `STREAM`.                                                    |
| `CONNECTOR_NAME`                        | `CONNECTOR_NAME`                                | Yes        | A name for the connector, e.g., `ZscalerConnector`.                                             |
| `CONNECTOR_SCOPE`                       | `CONNECTOR_SCOPE`                               | Yes        | The data scope for the connector. Use `domain-name` for this connector.                         |
| `CONNECTOR_LOG_LEVEL`                   | `CONNECTOR_LOG_LEVEL`                           | No         | The log level for this connector (`debug`, `info`, `warn`, or `error`).                         |
| `CONNECTOR_LIVE_STREAM_ID`              | `CONNECTOR_LIVE_STREAM_ID`                      | Yes        | The Live Stream ID of the OpenCTI stream.                                                       |
| `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`           | Yes        | Whether the connector should listen for deleted items (`true` or `false`).                      |
| `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES`         |Yes (Default)| Whether the connector should avoid dependency processing (`true` or `false`).                  |
| `CONNECTOR_DURATION_PERIOD`             | `CONNECTOR_DURATION_PERIOD`                     |Yes (Default)| The interval at which the connector will process data, e.g., `PT5M` (5 minutes).               |
| `ZSCALER_API_BASE_URL`                  | `ZSCALER_API_BASE_URL`                          | Yes        | The base URL of the Zscaler API.                                                                |
| `ZSCALER_API_KEY`                       | `ZSCALER_API_KEY`                               | Yes        | The API key for Zscaler authentication.                                                         |
| `ZSCALER_USERNAME`                      | `ZSCALER_USERNAME`                              | Yes        | The username for Zscaler authentication.                                                        |
| `ZSCALER_PASSWORD`                      | `ZSCALER_PASSWORD`                              | Yes        | The password for Zscaler authentication.                                                        |


### Usage

- This connector will connect to the Zscaler API using the specified credentials (`zscaler_username`, `zscaler_password`, and `zscaler_api_key`).
- To use the connector, create an API token in Zscaler with appropriate permissions to access the necessary data.


### Configuration Example

Here's an example Docker-compose.yml configuration for this connector, which you can adapt based on your environment:

Docker-compose.yml
{
  "opencti_url": "https://your-opencti-instance.com",
  "opencti_token": "YOUR_OPENCTI_TOKEN",
  "connector_id": "YOUR_CONNECTOR_UUID",
  "connector_name": "Zscaler Connector",
  "connector_scope": "zscaler",
  "connector_confidence_level": 3,
  "connector_log_level": "info",
  "connector_consumer_count": 1,
  "connector_live_stream_id": "YOUR_LIVE_STREAM_ID",
  "connector_live_stream_start_timestamp": "2022-01-01T00:00:00Z",
  "zscaler_url": "https://zsapi.zscalertwo.net/api",
  "zscaler_username": "YOUR_ZSCALER_USERNAME",
  "zscaler_password": "YOUR_ZSCALER_PASSWORD",
  "zscaler_api_key": "YOUR_ZSCALER_API_KEY",
  "zscaler_ssl_verify": true,
}
