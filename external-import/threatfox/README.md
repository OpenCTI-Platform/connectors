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

- file-md5
- file-sha1
- file-sha256
- ipv4-addr
- domain-name
- url

The connector adds the following Entities:

- Malware

## Installation

### Requirements

- OpenCTI Platform >= 6.2.9

### Configuration

| Parameter              | Docker envvar                    | Mandatory | Description                                                                                                             |
| ---------------------- | -------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`          | `OPENCTI_URL`                    | Yes       | The URL of the OpenCTI platform.                                                                                        |
| `opencti_token`        | `OPENCTI_TOKEN`                  | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                             |
| `connector_id`         | `CONNECTOR_ID`                   | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                      |
| `connector_name`       | `CONNECTOR_NAME`                 | Yes       | Option `ZeroFox`                                                                                                        |
| `connector_scope`      | `CONNECTOR_SCOPE`                | Yes       | Supported scope: Template Scope (MIME Type or Stix Object)                                                              |
| `confidence_level`     | `CONNECTOR_CONFIDENCE_LEVEL`     | Yes       | Set the confidence level for this data                                                                                  |
| `update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | No        | Update data alrerady in the platform based on the Threat Fox data pull                                                  |
| `log_level`            | `CONNECTOR_LOG_LEVEL`            | No        | Log output for the connector. Defaults to `INFO`                                                                                            |
| `csv_url`              | `THREATFOX_CSV_URL`              | No        | Defaults to `https://threatfox.abuse.ch/export/csv/recent/`                                                                                                                        |
| `import_offline`       | `THREATFOX_IMPORT_OFFLINE`       | No        | Create records for indicators that are offline. Defaults to `True`                                                                                                                        |
| `create_indicators`    | `THREATFOX_CREATE_INDICATORS`    | No        | Create indicators in addition to observables. Defaults to `True`                                                                                                                        |
| `interval`             | `THREATFOX_INTERVAL`             | No        | Run interval. Defaults to `3`                                                                                                                        |
| `ioc_types`            | `THREATFOX_IOC_TYPES`            | No        | List of IOC types to retrieve, available parameter: `all_types, ip:port, domain, url, md5_hash, sha1_hash, sha256_hash` |
