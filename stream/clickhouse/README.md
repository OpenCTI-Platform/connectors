# OpenCTI ClickHouse Connector

The ClickHouse connector is a **stream** connector that mirrors OpenCTI knowledge
into a [ClickHouse](https://clickhouse.com) database in real time. It listens to
an OpenCTI live stream and writes every create, update and delete event to a
ClickHouse table, making threat intelligence available for high-performance
correlation, hunting and dashboards next to your detection telemetry.

Table of Contents

- [OpenCTI ClickHouse Connector](#opencti-clickhouse-connector)
  - [Introduction](#introduction)
  - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Behavior](#behavior)
  - [Data model](#data-model)

## Introduction

[ClickHouse](https://clickhouse.com) is an open-source column-oriented database
designed for real-time analytics on large volumes of data. This connector keeps a
ClickHouse table continuously synchronised with the OpenCTI live stream, which is
particularly useful when ClickHouse is used as the analytics backend of a
detection pipeline (for example alongside Corelight NDR and a RedPanda streaming
bus).

## Requirements

- OpenCTI Platform >= 7.260722.0
- A reachable ClickHouse server with its HTTP interface enabled (default port 8123)
- A ClickHouse user allowed to create databases/tables and insert rows

## Configuration variables

Configuration parameters can be provided in either `config.yml` (see
`config.yml.sample`), `docker-compose.yml` (environment variables) or directly as
environment variables.

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | `token`    | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml                  | Docker environment variable           | Default      | Mandatory | Description                                               |
| --------------- | --------------------------- | ------------------------------------- | ------------ | --------- | -------------------------------------------------------- |
| Connector ID    | `id`                        | `CONNECTOR_ID`                        | /            | Yes       | A unique `UUIDv4` identifier for this connector instance. |
| Connector Name  | `name`                      | `CONNECTOR_NAME`                      | `ClickHouse` | No        | Name of the connector.                                   |
| Connector Scope | `scope`                     | `CONNECTOR_SCOPE`                     | `clickhouse` | No        | The scope of the connector.                              |
| Log Level       | `log_level`                 | `CONNECTOR_LOG_LEVEL`                 | `error`      | No        | Logs verbosity (`debug`, `info`, `warn`, `error`).       |
| Live Stream ID  | `live_stream_id`            | `CONNECTOR_LIVE_STREAM_ID`            | /            | Yes       | ID of the live stream created in the OpenCTI UI.         |
| Listen Delete   | `live_stream_listen_delete` | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` | `true`       | No        | Whether to listen to delete events on the live stream.  |
| No Dependencies | `live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `true`   | No        | Whether to ignore dependencies when processing events.  |

### Connector extra parameters environment variables

| Parameter    | config.yml     | Docker environment variable | Default          | Mandatory | Description                                                       |
| ------------ | -------------- | --------------------------- | ---------------- | --------- | ---------------------------------------------------------------- |
| Base URL     | `base_url`     | `CLICKHOUSE_BASE_URL`       | /                | Yes       | Base URL of the ClickHouse HTTP interface.                       |
| Username     | `username`     | `CLICKHOUSE_USERNAME`       | `default`        | No        | ClickHouse user name.                                            |
| Password     | `password`     | `CLICKHOUSE_PASSWORD`       | `""`             | No        | ClickHouse user password.                                        |
| Database     | `database`     | `CLICKHOUSE_DATABASE`       | `default`        | No        | ClickHouse database to write to.                                 |
| Table        | `table`        | `CLICKHOUSE_TABLE`          | `opencti_stream` | No        | Destination table for the stream events.                        |
| Create table | `create_table` | `CLICKHOUSE_CREATE_TABLE`   | `true`           | No        | Create the database and table automatically on startup.         |
| SSL verify   | `ssl_verify`   | `CLICKHOUSE_SSL_VERIFY`     | `true`           | No        | Whether to verify the SSL certificate of the HTTP interface.    |

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-clickhouse:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configurations, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Create a `config.yml` file at the connector root from `config.yml.sample` and fill in the values, then:

```shell
pip install -r src/requirements.txt
python src/main.py
```

## Behavior

On startup the connector creates the destination database and table (unless
`create_table` is disabled). It then listens to the OpenCTI live stream and, for
each event, inserts a row into ClickHouse via the HTTP interface.

## Data model

The destination table is created with the following schema:

```sql
CREATE TABLE IF NOT EXISTS <database>.<table> (
    id String,
    entity_type String,
    operation String,
    data String,
    event_date DateTime DEFAULT now()
) ENGINE = MergeTree ORDER BY (event_date, id)
```

- `id`: the STIX id of the entity carried by the event.
- `entity_type`: the STIX type (for example `indicator`, `malware`).
- `operation`: the stream operation (`create`, `update`, `delete`).
- `data`: the full STIX payload as a JSON string.
- `event_date`: the OpenCTI event time, derived from the live-stream event id (it falls back to the connector receipt time when the id is unavailable). The connector always writes this value explicitly; the `DEFAULT now()` in the schema is only a fallback for rows inserted outside the connector.
