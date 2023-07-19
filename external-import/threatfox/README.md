# Threat Fox Import Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

This connector imports data from the [Threat Fox Recent Feed](https://threatfox.abuse.ch/)

The connector adds data for the following OpenCTI observable/indicator types:
* file-md5
* file-sha1
* file-sha256
* ipv4-addr
* domain-name
* url

The connectors adds the following Entities:
* Malware
## Installation

### Requirements

- OpenCTI Platform >= 5.9.4

### Configuration

| Parameter              | Docker envvar        | Mandatory    | Description                                                                 |
|------------------------|----------------------| ------------ |-----------------------------------------------------------------------------|
| `opencti_url`          | `OPENCTI_URL`        | Yes          | The URL of the OpenCTI platform.                                            |
| `opencti_token`        | `OPENCTI_TOKEN`      | Yes          | The default admin token configured in the OpenCTI platform parameters file. |
| `connector_id`         | `CONNECTOR_ID`       | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.          |
| `connector_type`       | `CONNECTOR_TYPE`     | Yes          | Must be `EXTERNAL_IMPORT` (this is the connector type).                     |
| `connector_name`       | `CONNECTOR_NAME`     | Yes          | Option `ZeroFox`                                                            |
| `connector_scope`      | `CONNECTOR_SCOPE`    | Yes          | Supported scope: Template Scope (MIME Type or Stix Object)                  |
| `confidence_level`     | `CONNECTOR_CONFIDENCE_LEVEL`   | Yes          | Set the confidence level for this data                                      |
| `update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA`   | Yes          | Update data alrerady in the platform based on the Threat Fox data pull      |
| `log_level`            | `CONNECTOR_LOG_LEVEL`   | Yes          | Log output for the connector                                                
| `csv_url`             | `THREATFOX_CSV_URL`   | Yes          | |
| `import_offline`             | `THREATFOX_IMPORT_OFFLINE`   | Yes          |                                                                             |
| `create_indicators`             | `THREATFOX_CREATE_INDICATORS`   | Yes          |                                                                             |
| `threats_from_labels`             | `THREATFOX_THREATS_FROM_LABELS`   | Yes          |                                                                             | 
| `interval`             | `THREATFOX_INTERVAL`   | Yes          |                                                                             |

