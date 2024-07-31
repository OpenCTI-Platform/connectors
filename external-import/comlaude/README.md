# Comlaude Connector for OpenCTI

The Comlaude Connector is designed to integrate with the [Comlaude API](https://api.comlaude.com/docs) to leverage the `Domain Search Endpoint`. This endpoint provides a comprehensive list of all domains within a specified group, along with detailed information for each domain.

## Key Features:
- **Domain Retrieval**: Fetches domain details from a specific group in the Comlaude system.
- **OpenCTI Integration**: Imports the retrieved domains into OpenCTI.
- **CTI Allowlists Support**: Enhances the capabilities of Cyber Threat Intelligence (CTI) allowlists by integrating domain details.

By integrating Comlaude's domain information with OpenCTI, the connector aids in a more robust and informed CTI strategy.

### Requirements

- OpenCTI Platform >= 6.2.9
- Username, Password, and API Key for Comlaude

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | Option `Template`                                                                                                                                          |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope: Template Scope (MIME Type or Stix Object)                                                                                                 |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `connector_run_and_terminate`        | `CONNECTOR_RUN_AND_TERMINATE`       | Yes          | Terminate container after successful execution.                                                                                                            |
| `config_update_existing_data`        | `CONFIG_UPDATE_EXISTING_DATA`       | Yes          | whether to updated data in the database.                                                                                                                   |
| `config_interval`                    | `CONFIG_INTERVAL`                   | Yes          | Interval to run connector in hours.                                                                                                                        |
| `config_username`                    | `COMLAUDE_USERNAME`                 | Yes          | Username for account that has API access in Comlaude.                                                                                                      |
| `comlaude_password`                  | `COMLAUDE_PASSWORD`                 | Yes          | Password for account that has API access in Comlaude.                                                                                                      |
| `comlaude_api_key`                   | `COMLAUDE_API_KEY`                  | Yes          | API Key for account that has API access in Comlaude.                                                                                                       |
| `comlaude_group_id`                  | `COMLAUDE_GROUP_ID`                 | Yes          | Group ID for API in Comlaude.                                                                                                                              |
| `comlaude_start_time`                | `COMLAUDE_START_TIME`               | Yes          | Earliest entry to retrieve (e.g., 1970-01-01T00:00:00Z).                                                                                                   |
| `comlaude_labels`                    | `COMLAUDE_LABELS`                   | Yes          | Labels to apply to Stix Objects (e.g., comlaude,safelist).                                                                                                 |

