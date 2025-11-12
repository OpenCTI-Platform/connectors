# OpenCTI LIA File Feed

The connector ingests indicators of compromise (IOCs) from the Loader Insight Agency (LIA) File Feed, establishing
relationships between IOCs to provide context such as the loader family responsible for downloading a payload and the
URL from which it was downloaded. If known, the payload is tagged with a detection, offering insights into which malware
loader delivers specific malware.

**NOTE**: Requires a LIA File Feed subscription and can be acquired at https://loaderinsight.agency.

## Installation

### Requirements

- OpenCTI Platform >= 6.3.6

### Configuration

| Parameter                    | Docker envvar         | Mandatory | Description                                                                                   |
|------------------------------|-----------------------|-----------|-----------------------------------------------------------------------------------------------|
| `opencti_url`                | `OPENCTI_URL`         | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`              | `OPENCTI_TOKEN`       | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`               | `CONNECTOR_ID`        | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_name`             | `CONNECTOR_NAME`      | Yes       |                                                                                               |
| `connector_scope`            | `CONNECTOR_SCOPE`     | Yes       |                                                                                               |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL` | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_duration_period`  | `LIA_DURATION_PERIOD` | Yes       | Interval between collection requests                                                          |
| `lia_file_feed_api_base_url` | `LIA_BASE_API_URL`    | Yes       | The LIA API URL                                                                               |
| `lia_file_feed_api_key`      | `LIA_API_KEY`         | Yes       | Your LIA API KEY                                                                              |

### Debugging ###

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

### Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->

