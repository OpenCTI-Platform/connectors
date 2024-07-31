# Malcore Import Connector

This connector imports data from [Malcore](https://malcore.io/)

The connector creates the following OpenCTI entity types:

- Observable File (md5, sha1, and sha256),
- Indicator StixFile (sha256),
- Malware.

## Installation

### Requirements

- OpenCTI Platform >= 6.2.9

### Configuration

| Parameter             | Docker envvar         | Mandatory | Description                                                                                                                           |
|-----------------------|-----------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`         | `OPENCTI_URL`         | Yes       | The URL of the OpenCTI platform.                                                                                                      |
| `opencti_token`       | `OPENCTI_TOKEN`       | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                           |
| `connector_id`        | `CONNECTOR_ID`        | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                    |
| `connector_name`      | `CONNECTOR_NAME`      | Yes       | Option `Malcore`                                                                                                                      |
| `connector_scope`     | `CONNECTOR_SCOPE`     | Yes       | Supported scope: Template Scope (MIME Type or Stix Object)                                                                            |
| `connector_log_level` | `CONNECTOR_LOG_LEVEL` | Yes       | Log output for the connector. Defaults to `INFO`                                                                                      |
| `malcore_api_url`     | `MALCORE_API_URL`     | Yes       | Malcore API URL                                                                                                                       |
| `malcore_api_key`     | `MALCORE_API_KEY`     | Yes       | Malcore API Key                                                                                                                       |
| `malcore_score`       | `MALCORE_SCORE`       | Yes       | Parameter not used at this moment, but could be used as a default indicator/observable score at a later date                          |
| `malcore_limit`       | `MALCORE_LIMIT`       | Yes       | Parameter not used at this moment, but could be used as a limit on the number of entities to be retrieved per request at a later date |
| `malcore_interval`    | `MALCORE_INTERVAL`    | Yes       | Interval between two executions, in hours (must be > 1)                                                                               |

