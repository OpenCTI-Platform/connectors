# OpenCTI Splunk connector

This connector allows organizations to feed a **Splunk** KV Store using OpenCTI knowledge.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0

### Configuration

| Parameter                               | Docker envvar                           | Mandatory | Description                                                                                   |
| --------------------------------------- | --------------------------------------- | --------- | --------------------------------------------------------------------------------------------- |
| `opencti_url`                           | `OPENCTI_URL`                           | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                         | `OPENCTI_TOKEN`                         | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                          | `CONNECTOR_ID`                          | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_type`                        | `CONNECTOR_TYPE`                        | Yes       | Must be `STREAM` (this is the connector type).                                                |
| `connector_name`                        | `CONNECTOR_NAME`                        | Yes       | The name of the Splunk instance, to identify it if you have multiple Splunk connectors.       |
| `connector_scope`                       | `CONNECTOR_SCOPE`                       | Yes       | Must be `splunk`, not used in this connector.                                                 |
| `connector_confidence_level`            | `CONNECTOR_CONFIDENCE_LEVEL`            | Yes       | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`                   | `CONNECTOR_LOG_LEVEL`                   | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_consumer_count`              | `CONNECTOR_CONSUMER_COUNT`              | No        | Number of consumer/worker that will push data to Splunk.                                      |
| `connector_live_stream_start_timestamp` | `CONNECTOR_LIVE_STREAM_START_TIMESTAMP` | No        | Start timestamp used on connector first start.                                                |
| `splunk_url`                            | `SPLUNK_URL`                            | Yes       | The Splunk instances REST API URLs as array                                                   |
| `splunk_login`                          | `SPLUNK_LOGIN`                          | Yes       | The Splunk login users as array (same order as URLs)                                          |
| `splunk_password`                       | `SPLUNK_PASSWORD`                       | Yes       | The Splunk passwords as array (same order as URLs)                                            |
| `splunk_owner`                          | `SPLUNK_OWNER`                          | Yes       | The Splunk KV store owners as array (same order as URLs)                                      |
| `splunk_ssl_verify`                     | `SPLUNK_SSL_VERIFY`                     | Yes       | Enable the SSL certificate check for all instances (default: `true`)                          |
| `splunk_app`                            | `SPLUNK_APP`                            | Yes       | The app of the KV Store for all instances.                                                    |
| `splunk_kv_store_name`                  | `SPLUNK_KV_STORE_NAME`                  | Yes       | The name of the KV Store for all instances.                                                   |
| `splunk_ignore_types`                   | `SPLUNK_IGNORE_TYPES`                   | Yes       | The list of entity types to ignore.                                                           |
| `metrics_enable`                        | `METRICS_ENABLE`                        | No        | Whether or not Prometheus metrics should be enabled.                                          |
| `metrics_addr`                          | `METRICS_ADDR`                          | No        | Bind IP address to use for metrics endpoint.                                                  |
| `metrics_port`                          | `METRICS_PORT`                          | No        | Port to use for metrics endpoint.                                                             |

### Usage

- This connector will connect your Splunk API as the user specified in field splunk_owner (recommended value is `nobody` which is the default for splunk to create a kvstore)
- You have to create a token in Splunk (beware of expiration time): Settings > Users and Authentication > Tokens
- You may have to whitelist your connector EGRESS IP address to hit the API endpoint: Settings > Server Settings > IP allow list > Search head API Access (tab)
- As a splunk_url, it is recommended to use your search head instance, so that the created kvstore is replicated across your other splunk instances. Note that any kvstore created on "non-search head" won't be replicated nor visible on the search head.
- The connector will create a kvstore named as per splunk_kv_store_name field value. Note that no other existing object in your splunk instance can have the same name.
- Once the kvstore is created, you want to create some lookup definitions for CRUD operations against your kvstore: Settings > Knowledge > Lookups > Lookup definitions > Add new
  - As an example of lookup definition, you may want to extract the following supported fields:

| type        | supported fields                                                                         |
| ----------- | ---------------------------------------------------------------------------------------- |
| domain-name | `_key,type,value,created_at,updated_at,score,labels,created_by`                          |
| url         | `_key,type,value,created_at,updated_at,score,labels,created_by`                          |
| ipv4-addr   | `_key,type,value,created_at,updated_at,score,labels,created_by`                          |
| url         | `_key,type,value,created_at,updated_at,score,labels,created_by`                          |
| file        | `_key,type,hashes,created_at,updated_at,score,labels,created_by`                         |
| indicator   | `_key,type,pattern,created_at,updated_at,score,labels,splunk_queries.queries,created_by` |
| ...         | ...etc...                                                                                |
