# Elastic Threat Intel Connector

This connector allows organizations to feed their Elastic platform using OpenCTI knowledge.

This connector uses the OpenCTI *events stream*, so it consumes knowledge in real time and, depending on the settings, creates detection and hunting threat intel documents that can be used with Indicator Match rules in the Elastic Security application.

## Installation

### Requirements

- OpenCTI Platform >= 4.3.0
- Elastic platform >= 7.11.0

### Configuration

**NOTES**
- Either `elasticsearch_url` or `elastic_cloud_id` are required. These are mutually exclusive options.
- Authentication is required if your cluster requires it. Supply either `elastic_login` and `elastic_password` or `elastic_apikey`.

| Parameter                    | Container envvar             | Mandatory | Description                                                                                                                                                              |
|------------------------------|------------------------------|-----------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                                                                                                                                         |
| `opencti_token`              | `OPENCTI_TOKEN`              | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                                                              |
| `connector_id`               | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                       |
| `connector_type`             | `CONNECTOR_TYPE`             | Yes       | Must be `STREAM` (this is the connector type).                                                                                                                           |
| `connector_name`             | `CONNECTOR_NAME`             | Yes       | The name of the Elastic instance, to identify it if you have multiple Elastic instances connectors.                                                                      |
| `connector_scope`            | `CONNECTOR_SCOPE`            | Yes       | Must be `elastic`, not used in this connector.                                                                                                                           |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | Yes       | The default confidence level for created sightings (a number between 1 and 4).                                                                                           |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`        | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                            |
| `elasticsearch_url`          | `ELASTICSEARCH_URL`          | No        | The Elasticsearch instance URL.                                                                                                                                          |
| `elastic_cloud_id`           | `ELASTIC_CLOUD_ID`           | No        | Cloud ID for cloud instance of Elasticsearch                                                                                                                             |
| `elastic_ssl_verify`         | `ELASTIC_SSL_VERIFY`         | Yes       | Enable the SSL certificate check (default: `true`)                                                                                                                       |
| `elastic_login`              | `ELASTIC_LOGIN`              | No        | The Elasticsearch login user (ApiKey is recommended).                                                                                                                    |
| `elastic_password`           | `ELASTIC_PASSWORD`           | No        | The Elasticsearch password (ApiKey is recommended).                                                                                                                      |
| `elastic_apikey`             | `ELASTIC_APIKEY`             | No        | The Elasticsearch ApiKey (recommended authentication, see [apikey docs](https://www.elastic.co/guide/en/elasticsearch/reference/master/security-api-create-api-key.html) |
| `elastic_observable_types`   | `ELASTIC_OBSERVABLE_TYPES`   | Yes       | A list of observable types separated by `,`, could be `ipv4-addr`, `ipv6-addr`, `domain-name`, `x-opencti-hostname`, `file` or `process` (can be empty).                 |
| `elastic_import_label`       | `ELASTIC_IMPORT_LABEL`       | Yes       | If this label is added or present, the entity will be imported in Elasticsearch, can be '*' to import everything.                                                        |
| `elastic_import_from_date`   | `ELASTIC_IMPORT_FROM_DATE`   | No        | At the very first run, ignore all knowledge event before this date.                                                                                                      |
