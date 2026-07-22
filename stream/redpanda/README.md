# OpenCTI Redpanda Connector

The Redpanda connector is a **stream** connector that publishes OpenCTI knowledge
to a [Redpanda](https://www.redpanda.com) topic in real time. It listens to an
OpenCTI live stream and produces every create, update and delete event to a
Kafka-compatible topic through the Redpanda HTTP Proxy (Pandaproxy), so downstream
consumers can react to threat intelligence changes.

Table of Contents

- [OpenCTI Redpanda Connector](#opencti-redpanda-connector)
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

## Introduction

[Redpanda](https://www.redpanda.com) is a Kafka-compatible streaming data
platform. It ships with an HTTP Proxy (Pandaproxy) that allows producing records
over HTTP, which this connector uses to publish OpenCTI events without requiring a
native Kafka client.

## Requirements

- OpenCTI Platform >= 7.260722.0
- A reachable Redpanda HTTP Proxy (Pandaproxy), default port 8082
- A topic to publish to (created beforehand or with auto-topic-creation enabled)

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

| Parameter       | config.yml                  | Docker environment variable           | Default    | Mandatory | Description                                               |
| --------------- | --------------------------- | ------------------------------------- | ---------- | --------- | -------------------------------------------------------- |
| Connector ID    | `id`                        | `CONNECTOR_ID`                        | /          | Yes       | A unique `UUIDv4` identifier for this connector instance. |
| Connector Name  | `name`                      | `CONNECTOR_NAME`                      | `Redpanda` | No        | Name of the connector.                                   |
| Connector Scope | `scope`                     | `CONNECTOR_SCOPE`                     | `redpanda` | No        | The scope of the connector.                              |
| Log Level       | `log_level`                 | `CONNECTOR_LOG_LEVEL`                 | `error`    | No        | Logs verbosity (`debug`, `info`, `warn`, `error`).       |
| Live Stream ID  | `live_stream_id`            | `CONNECTOR_LIVE_STREAM_ID`            | /          | Yes       | ID of the live stream created in the OpenCTI UI.         |
| Listen Delete   | `live_stream_listen_delete` | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` | `true`     | No        | Whether to listen to delete events on the live stream.  |
| No Dependencies | `live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `true` | No        | Whether to ignore dependencies when processing events.  |

### Connector extra parameters environment variables

| Parameter      | config.yml       | Docker environment variable | Default   | Mandatory | Description                                                |
| -------------- | ---------------- | --------------------------- | --------- | --------- | --------------------------------------------------------- |
| HTTP Proxy URL | `http_proxy_url` | `REDPANDA_HTTP_PROXY_URL`   | /         | Yes       | Base URL of the Redpanda HTTP Proxy (Pandaproxy).         |
| Topic          | `topic`          | `REDPANDA_TOPIC`            | `opencti` | No        | Topic that receives the OpenCTI stream events.            |
| Username       | `username`       | `REDPANDA_USERNAME`         | /         | No        | Optional user name for HTTP basic authentication.         |
| Password       | `password`       | `REDPANDA_PASSWORD`         | /         | No        | Optional password for HTTP basic authentication.          |
| SSL verify     | `ssl_verify`     | `REDPANDA_SSL_VERIFY`       | `true`    | No        | Whether to verify the SSL certificate of the proxy.       |

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-redpanda:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configurations, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Create a `src/config.yml` file from the root `config.yml.sample` and fill in the
values, then:

```shell
cd src
pip install -r requirements.txt
python main.py
```

## Behavior

For each event received on the OpenCTI live stream, the connector produces a
record to the configured Redpanda topic through the HTTP Proxy
(`POST /topics/{topic}`). The record key is the STIX id of the entity and the
record value contains the stream operation and the full STIX payload.
