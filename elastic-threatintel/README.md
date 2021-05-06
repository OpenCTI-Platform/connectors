# Elastic Threat Intel Connector

TODO: Update this documentation on how to build and configure

This connector allows organizations to feed their Elastic platform using OpenCTI knowledge.

This connector uses the OpenCTI *events stream*, so it consumes knowledge in real time and, depending on the settings, creates detection and hunting threat intel documents that can be used with Indicator Match rules in the Elastic Security application.

## Quick Start

## Installation

### Requirements

- OpenCTI Platform >= 4.5.0
- Elastic platform >= 7.12.0

### Configuration

Detailed configuration can be managed via the configuration file. The script looks for `config.yml` in the current directory, but a different path can be given on the command line.

| YAML Parameter                    | Environment Var              | Mandatory | Description                                                                                                                                                              |
|-----------------------------------|------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti.token`                   | `OPENCTI_TOKEN`              | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                                                              |
| `opencti.url`                     | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                                                                                                                                         |
| `opencti.ssl_verify`              | `OPENCTI_SSL_VERIFY`         | No        | Set to `False` to disable TLS certificate validation. Defaults to `True`                                                                                                 |
| `connector.confidence_level`      | `CONNECTOR_CONFIDENCE_LEVEL` | Yes       | The default confidence level for created sightings (a number between 1 and 4).                                                                                           |
| `connector.id`                    | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                       |
| `connector.log_level`             | `CONNECTOR_LOG_LEVEL`        | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                            |
| `connector.name`                  | `CONNECTOR_NAME`             | Yes       | The name of the Elastic instance, to identify it if you have multiple Elastic instances connectors.                                                                      |
| `connector.scope`                 | `CONNECTOR_SCOPE`            | Yes       | Must be `elastic`, not used in this connector.                                                                                                                           |
| `connector.type`                  | `CONNECTOR_TYPE`             | Yes       | Must be `STREAM` (this is the connector type).                                                                                                                           |
| `cloud.auth`                      | `CLOUD_AUTH`                 | No        | Auth info for cloud instance of Elasticsearch Cloud                                                                                                                      |
| `cloud.id`                        | `CLOUD_ID`                   | No        | Cloud ID for cloud instance of Elasticsearch                                                                                                                             |
| `output.elasticsearch.api_key`    | `ELASTICSEARCH_APIKEY`       | No        | The Elasticsearch ApiKey (recommended authentication, see [apikey docs](https://www.elastic.co/guide/en/elasticsearch/reference/master/security-api-create-api-key.html) |
| `output.elasticsearch.hosts`      | `ELASTICSEARCH_HOSTS`        | No        | The Elasticsearch instance URL.                                                                                                                                          |
| `output.elasticsearch.password`   | `ELASTICSEARCH_PASSWORD`     | No        | The Elasticsearch password (ApiKey is recommended).                                                                                                                      |
| `output.elasticsearch.username`   | `ELASTICSEARCH_USERNAME`     | No        | The Elasticsearch login user (ApiKey is recommended).                                                                                                                    |
| `output.elasticsearch.ssl_verify` | `ELASTICSEARCH_SSL_VERIFY`   | No        | Set to `False` to disable TLS certificate validation. Defaults to `True`                                                                                                 |
| `elastic_import_from_date`        | `ELASTIC_IMPORT_FROM_DATE`   | No        | At the very first run, ignore all knowledge events before this date. Defaults to `now()` minus one minute.                                                               |
| `elastic.import_label`            | `ELASTIC_IMPORT_LABEL`       | Yes       | If this label is added or present to the indicator, the entity will be imported in Elasticsearch. Defaults to `*`, which imports everything.                             |
|                                   | `CONNECTOR_JSON_CONFIG`      | No        | (Optional) environment variable allowing full configuration via a single environment variable using JSON. Helpful for some container deployment scenarios.               |
