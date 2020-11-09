# OpenCTI Splunk Connector 
An OpenCTI connector that imports events from [Splunk Enterprise](https://www.splunk.com/en_us/software/splunk-enterprise.html)

This connector takes all STIX2 events stored in an index and imports them to OpenCTI. 
For more information about Splunk indexes check [here](https://docs.splunk.com/Documentation/Splunk/8.1.0/Indexer/Setupmultipleindexes)

## Configuration

| Parameter                       | Docker envvar                    | Description                                                                                            |
|---------------------------------|----------------------------------|--------------------------------------------------------------------------------------------------------|
| `opencti_url`                   | `OPENCTI_URL`                    | The URL of the OpenCTI platform.                                                                       |
| `opencti_token`                 | `OPENCTI_TOKEN`                  | The default admin token configured in the OpenCTI platform parameters file.                            |
| `connector_id`                  | `CONNECTOR_ID`                   | A valid arbitrary `UUIDv4` that must be unique for this connector.                                     |
| `connector-type`                | `CONNECTOR_TYPE`                 | Must be `EXTERNAL_IMPORT` (this is the connector type).                                                |
| `connector_name`                | `CONNECTOR_NAME`                 | The name of the Splunk instance, to identify it if you have multiple connectors.                       |
| `connector_scope`               | `CONNECTOR_SCOPE`                | Must be `splunk`, not used in this connector.                                                          | 
| `connector_confidence_level`    | `CONNECTOR_CONFIDENCE_LEVEL`     | The default confidence level for created relationships (a number between 1 and 4).                     |
| `connector_update_existing_data`| `CONNECTOR_UPDATE_EXISTING_DATA` | If an entity already exists, update its attributes with information provided by this connector.        |
| `connector_log_level`           | `CONNECTOR_LOG_LEVEL`            | The log level for this connector, could be debug, info, warn or error (less verbose).                  |
| `config_interval`               | `CONFIG_INTERVAL`                | Check for new event to import every n days.                                                            |
| `splunk_host`                   | `SPLUNK_HOST`                    | Must be `host.docker.internal` if using Splunk Web.                                                    | 
| `splunk_port`                   | `SPLUNK_PORT`                    | Splunk management port, by default is `8089`.                                                          |
| `splunk_username`               | `SPLUNK_USERNAME`                | Username used for Splunk Web login.                                                                    |
| `splunk_connector_password`     | `SPLUNK_CONNECTOR_PASSWORD`      | Password used for Splunk Web login.                                                                    |
| `splunk_indexes`                | `SPLUNK_INDEXES`                 | List of indexes to import. Must be separated by `,` <br> e.g. `SPLUNK_INDEXES=index1,index2,index3`    |

