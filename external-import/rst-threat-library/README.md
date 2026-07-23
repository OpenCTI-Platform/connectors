# OpenCTI RST Threat Library Connector

Ingests intrusion sets, malware, tools, and campaigns from the **RST Cloud Threat Library REST API** (`https://api.rstcloud.net/v1`) into OpenCTI, and keeps them in sync as upstream objects change.

## Introduction

The connector polls `GET /threat-objects/<type>` for each configured type and upserts the results into OpenCTI keyed on `standard_id`.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12 with a working worker
- Python >= 3.11 (for manual deployment)
- An RST Cloud Threat Library API key
- Docker / Docker Compose

### Configuration variables

Configuration is set either in `docker-compose.yml` (Docker) or in `config.yml` (manual deployment). See `config.yml.sample` for a full annotated example. Field descriptions and examples are also defined on the Pydantic models in `src/connector/settings.py` and mirrored in `__metadata__/connector_config_schema.json`.

#### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Example                 | Description                                      |
| ------------- | ---------- | --------------------------- | --------- | ----------------------- | ------------------------------------------------ |
| OpenCTI URL   | `url`      | `OPENCTI_URL`               | Yes       | `http://localhost:8080` | URL of the OpenCTI platform.                     |
| OpenCTI Token | `token`    | `OPENCTI_TOKEN`             | Yes       | `ChangeMe`              | Admin / API token used to bootstrap the connector. |

#### Base connector environment variables

| Parameter                      | config.yml                                   | Docker environment variable                              | Default             | Mandatory | Example                                      | Description                                                                 |
| ------------------------------ | -------------------------------------------- | -------------------------------------------------------- | ------------------- | --------- | -------------------------------------------- | --------------------------------------------------------------------------- |
| Connector ID                   | `id`                                         | `CONNECTOR_ID`                                           | /                   | Yes       | `b7f9a6b4-6b2a-4c3f-9f7b-8b5e5b6f2d1a`       | Unique UUID v4 for this connector instance.                                 |
| Connector Type                 | `type`                                       | `CONNECTOR_TYPE`                                         | `EXTERNAL_IMPORT`   | Yes       | `EXTERNAL_IMPORT`                            | Must be `EXTERNAL_IMPORT`.                                                  |
| Connector Name                 | `name`                                       | `CONNECTOR_NAME`                                         | `RST Threat Library`| Yes       | `RST Threat Library`                         | Display name in OpenCTI.                                                    |
| Connector Scope                | `scope`                                      | `CONNECTOR_SCOPE`                                        | /                   | Yes       | `intrusion-set,malware,tool,campaign`        | STIX domain types emitted.                                                  |
| Log Level                      | `log_level`                                  | `CONNECTOR_LOG_LEVEL`                                    | `error`             | No        | `info`                                       | `debug`, `info`, `warn`, or `error`.                                        |
| Duration Period                | `duration_period`                            | `CONNECTOR_DURATION_PERIOD`                              | `PT1H`              | No        | `PT1H`                                       | ISO-8601 interval between runs.                                                         |
| Queue Threshold                | `queue_threshold`                            | `CONNECTOR_QUEUE_THRESHOLD`                              | `500`               | No        | `500`                                        | Max RabbitMQ queue size (MB) before pausing ingestion.                      |
| Update Existing Data           | `update_existing_data`                       | `CONNECTOR_UPDATE_EXISTING_DATA`                       | `true`              | No        | `true`                                       | Upsert existing STIX objects when `true`.                                   |
| Auto-create Service Account    | `auto_create_service_account`                | `CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT`                  | `false`             | No        | `true`                                       | Create a Connectors-group service account on first start.                   |
| Service Account Confidence     | `auto_create_service_account_confidence_level` | `CONNECTOR_AUTO_CREATE_SERVICE_ACCOUNT_CONFIDENCE_LEVEL` | `50`                | No        | `50`                                         | Max confidence for the auto-created service account.                        |

#### Connector extra parameters

| Parameter                         | config.yml                          | Docker environment variable                          | Default                                      | Mandatory | Example                                      | Description                                                                 |
| --------------------------------- | ----------------------------------- | ---------------------------------------------------- | -------------------------------------------- | --------- | -------------------------------------------- | --------------------------------------------------------------------------- |
| API base URL                      | `baseurl`                           | `RST_THREAT_LIBRARY_BASEURL`                         | `https://api.rstcloud.net/v1`                | Yes       | `https://api.rstcloud.net/v1`                | RST Cloud API root.                                                         |
| API key                           | `apikey`                            | `RST_THREAT_LIBRARY_APIKEY`                          | /                                            | Yes       | `ChangeMe`                                   | RST Cloud Threat Library API key.                                           |
| Auth header name                  | `auth_header`                       | `RST_THREAT_LIBRARY_AUTH_HEADER`                     | `x-api-key`                                  | No        | `x-api-key`                                  | HTTP header carrying the API key.                                           |
| HTTP proxy                        | `proxy`                             | `RST_THREAT_LIBRARY_PROXY`                           | *(empty)*                                    | No        | `http://proxy.example.com:8080`              | Forward HTTP proxy URL. Empty = direct egress.                              |
| Verify TLS                        | `ssl_verify`                        | `RST_THREAT_LIBRARY_SSL_VERIFY`                      | `true`                                       | No        | `true`                                       | Verify TLS certificates.                                                    |
| Connect timeout                   | `contimeout`                        | `RST_THREAT_LIBRARY_CONTIMEOUT`                      | `30`                                         | No        | `30`                                         | HTTP connect timeout in seconds.                                            |
| Read timeout                      | `readtimeout`                       | `RST_THREAT_LIBRARY_READTIMEOUT`                     | `120`                                        | No        | `600`                                        | HTTP read timeout in seconds.                                               |
| HTTP fetch retries                | `retry`                             | `RST_THREAT_LIBRARY_RETRY`                           | `2`                                          | No        | `10`                                         | Per-request retry count.                                                    |
| OpenCTI push max retries          | `max_retries`                       | `RST_THREAT_LIBRARY_MAX_RETRIES`                     | `3`                                          | No        | `3`                                          | Retries when pushing to OpenCTI.                                            |
| OpenCTI push retry delay          | `retry_delay`                       | `RST_THREAT_LIBRARY_RETRY_DELAY`                     | `10`                                         | No        | `10`                                         | Initial retry delay in seconds.                                             |
| OpenCTI push backoff multiplier   | `retry_backoff_multiplier`          | `RST_THREAT_LIBRARY_RETRY_BACKOFF_MULTIPLIER`        | `2.0`                                        | No        | `2.0`                                        | Exponential backoff multiplier.                                             |
| OpenCTI push mode                 | `opencti_push_mode`                 | `RST_THREAT_LIBRARY_OPENCTI_PUSH_MODE`               | `bundle`                                     | No        | `bundle`                                     | `bundle` (worker) or `api` (GraphQL import).                                |
| Object types to pull              | `object_types`                      | `RST_THREAT_LIBRARY_OBJECT_TYPES`                    | `intrusion-sets,malware,tools,campaigns`     | No        | `intrusion-sets,malware,tools,campaigns`     | Comma-separated paths under `/threat-objects/`.                             |
| Sort field                        | `order_by`                          | `RST_THREAT_LIBRARY_ORDER_BY`                        | `modified`                                   | No        | `modified`                                   | Use `modified` for incremental sync.                                        |
| Sort direction                    | `order_mode`                        | `RST_THREAT_LIBRARY_ORDER_MODE`                      | `desc`                                       | No        | `desc`                                       | `asc` or `desc`.                                                            |
| Page size                         | `page_size`                         | `RST_THREAT_LIBRARY_PAGE_SIZE`                       | `100`                                        | No        | `20`                                         | `limit` per request.                                                        |
| Intrusion-set merge/split         | `merge_split`                       | `RST_THREAT_LIBRARY_MERGE_SPLIT`                     | `false`                                      | No        | `false`                                      | Reconcile intrusion-set alias merge/split.                                  |
| Respect local user edits          | `respect_user_edits`                | `RST_THREAT_LIBRARY_RESPECT_USER_EDITS`              | `false`                                      | No        | `false`                                      | Preserve higher-confidence OpenCTI edits.                                   |
| Intrusion-set import confidence   | `intrusion_set_default_confidence`  | `RST_THREAT_LIBRARY_INTRUSION_SET_DEFAULT_CONFIDENCE`| *(unset)*                                    | No        | `80`                                         | When set (0–100), replaces upstream confidence on intrusion sets.           |
| Sync labels on import             | `sync_labels`                       | `RST_THREAT_LIBRARY_SYNC_LABELS`                     | `RST Threat Library`                         | No        | `RST Threat Library`                         | Labels merged on import; scopes merge/split.                                |
| Reconcile exclude labels          | `reconcile_exclude_labels`          | `RST_THREAT_LIBRARY_RECONCILE_EXCLUDE_LABELS`        | *(empty)*                                    | No        | `MITRE,manual`                               | Labels excluded from merge/split fusion.                                    |
| Reconcile createdBy allowlist     | `reconcile_allow_created_by`        | `RST_THREAT_LIBRARY_RECONCILE_ALLOW_CREATED_BY`      | *(empty)*                                    | No        | `identity--…`                                | If set, fuse only entities with these `createdBy` IDs.                      |
| Initial backfill cutoff           | `import_from_date`                  | `RST_THREAT_LIBRARY_IMPORT_FROM_DATE`                | *(empty)*                                    | No        | `2024-01-01`                                 | `YYYY-MM-DD`. Empty = full history on first run.                            |

### Recommended values (RST API reliability)

For deep pagination (especially `tools`), these reduce `504 Gateway Timeout` and `IncompleteRead` errors:

```env
RST_THREAT_LIBRARY_PAGE_SIZE=20
RST_THREAT_LIBRARY_READTIMEOUT=600
RST_THREAT_LIBRARY_RETRY=10
```
