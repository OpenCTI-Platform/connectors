# Comlaude Connector for OpenCTI

| Status            | Date       | Comment |
| ----------------- |------------| ------- |
| Filigran Verified | 2025-04-17 |    -    |

The Comlaude Connector is designed to integrate with the [Comlaude API](https://api.comlaude.com/docs) to leverage the `Domain Search Endpoint`. This endpoint provides a comprehensive list of all domains within a specified group, along with detailed information for each domain.

## Key Features:
- **Domain Retrieval**: Fetches domain details from a specific group in the Comlaude system.
- **OpenCTI Integration**: Imports the retrieved domains into OpenCTI.
- **CTI Allowlists Support**: Enhances the capabilities of Cyber Threat Intelligence (CTI) allowlists by integrating domain details.

By integrating Comlaude's domain information with OpenCTI, the connector aids in a more robust and informed CTI strategy.

### Requirements

- OpenCTI Platform >= 6.6.17
- Username, Password, and API Key for Comlaude

### Configuration

| Parameter                      | Docker envvar                   | Mandatory | Description                                                                                                                                         |
| ------------------------------ | ------------------------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                  | `OPENCTI_URL`                   | Yes       | The URL of the OpenCTI platform.                                                                                                                    |
| `opencti_token`                | `OPENCTI_TOKEN`                 | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                                         |
| `connector_id`                 | `CONNECTOR_ID`                  | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                  |
| `connector_name`               | `CONNECTOR_NAME`                | Yes       | The name of this connector.                                                                                                                         |
| `connector_scope`              | `CONNECTOR_SCOPE`               | Yes       | Supported scope: MIME Type or Stix Object.                                                                                                          |
| `connector_log_level`          | `CONNECTOR_LOG_LEVEL`           | Yes       | The log level for this connector (e.g., `debug`, `info`, `warn`, or `error`).                                                                       |
| `connector_run_and_terminate`  | `CONNECTOR_RUN_AND_TERMINATE`   | Yes       | Terminate container after successful execution.                                                                                                   |
| `connector_duration_period`    | `CONNECTOR_DURATION_PERIOD`     | Yes       | Execution period of the connector in ISO8601 duration format (e.g., `PT2H` for a 2-hour period).                                                     |
| `connector_queue_threshold`    | `CONNECTOR_QUEUE_THRESHOLD`     | Optional  | Optional queue threshold (default: 500MB).                                                                                                          |
| `comlaude_username`            | `COMLAUDE_USERNAME`             | Yes       | Username for the account with API access in Comlaude.                                                                                               |
| `comlaude_password`            | `COMLAUDE_PASSWORD`             | Yes       | Password for the account with API access in Comlaude.                                                                                               |
| `comlaude_api_key`             | `COMLAUDE_API_KEY`              | Yes       | API Key for the account with API access in Comlaude.                                                                                                |
| `comlaude_group_id`            | `COMLAUDE_GROUP_ID`             | Yes       | Group ID for the Comlaude API.                                                                                                                      |
| `comlaude_start_time`          | `COMLAUDE_START_TIME`           | Yes       | Earliest entry to retrieve (e.g., `1970-01-01T00:00:00Z`).                                                                                          |
| `comlaude_labels`              | `COMLAUDE_LABELS`               | Yes       | Labels to apply to Stix Objects (e.g., `comlaude,safelist`).                                                                                        |
| `comlaude_score`               | `COMLAUDE_SCORE`                | Yes       | Default score value to be assigned to domains.                                                                                                    |
