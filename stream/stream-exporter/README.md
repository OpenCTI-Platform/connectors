# OpenCTI Stream Exporter Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

The Stream Exporter connector exports OpenCTI live stream events to an S3-compatible bucket (RustFS, AWS S3, ...) for asynchronous synchronization between OpenCTI instances.

## Table of Contents

- [OpenCTI Stream Exporter Connector](#opencti-stream-exporter-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

This connector listens to an OpenCTI live stream and exports events to an S3-compatible bucket. It is designed to work with the [stream-importer](../../external-import/stream-importer/) connector for synchronizing OpenCTI instances that don't have direct network access to each other.

Key features:
- Export live stream events to an S3 bucket
- Bulk writing for performance optimization
- State management for reliable synchronization
- Configurable write intervals
- Support for SSL and certificate verification

## Installation

### Requirements

- OpenCTI Platform >= 6.3.4
- S3-compatible object storage (RustFS, AWS S3, ...)
- Network access to the S3 endpoint

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter                      | config.yml                | Docker environment variable             | Default         | Mandatory | Description                                                                    |
|--------------------------------|---------------------------|-----------------------------------------|-----------------|-----------|--------------------------------------------------------------------------------|
| Connector ID                   | id                        | `CONNECTOR_ID`                          |                 | Yes       | A unique `UUIDv4` identifier for this connector instance.                      |
| Connector Name                 | name                      | `CONNECTOR_NAME`                        |                 | Yes       | Name of the connector.                                                         |
| Connector Scope                | scope                     | `CONNECTOR_SCOPE`                       | stream-exporter | Yes       | The scope of the connector.                                                    |
| Live Stream Start Timestamp    | live_stream_start_timestamp| `CONNECTOR_LIVE_STREAM_START_TIMESTAMP`|                 | No        | Start timestamp on first start (default: all data).                            |
| Consumer Count                 | consumer_count            | `CONNECTOR_CONSUMER_COUNT`              | 10              | No        | Number of consumer/worker threads.                                             |
| Log Level                      | log_level                 | `CONNECTOR_LOG_LEVEL`                   | info            | No        | Determines the verbosity of the logs.                                          |

### Connector extra parameters environment variables

| Parameter      | config.yml                    | Docker environment variable     | Default | Mandatory | Description                             |
|----------------|-------------------------------|---------------------------------|---------|-----------|-----------------------------------------|
| S3 Endpoint    | stream_exporter.s3_endpoint   | `STREAM_EXPORTER_S3_ENDPOINT`   |         | Yes       | S3 server endpoint.                     |
| S3 Port        | stream_exporter.s3_port       | `STREAM_EXPORTER_S3_PORT`       |         | Yes       | S3 server port.                         |
| S3 Bucket      | stream_exporter.s3_bucket     | `STREAM_EXPORTER_S3_BUCKET`     |         | Yes       | S3 bucket name (created if not exists). |
| S3 Folder      | stream_exporter.s3_folder     | `STREAM_EXPORTER_S3_FOLDER`     |         | Yes       | Folder within bucket for messages.      |
| S3 Access Key  | stream_exporter.s3_access_key | `STREAM_EXPORTER_S3_ACCESS_KEY` |         | Yes       | S3 access key.                          |
| S3 Secret Key  | stream_exporter.s3_secret_key | `STREAM_EXPORTER_S3_SECRET_KEY` |         | Yes       | S3 secret key.                          |
| S3 Secure      | stream_exporter.s3_secure     | `STREAM_EXPORTER_S3_SECURE`     | false   | No        | Whether to use SSL.                     |
| S3 Cert Check  | stream_exporter.s3_cert_check | `STREAM_EXPORTER_S3_CERT_CHECK` | true    | No        | Whether to verify SSL certificate.      |
| Write Interval | write.every_sec               | `WRITE_EVERY_SEC`               | 900     | No        | Seconds between S3 writes.              |

The names carry the connector's section because pycti already reads `S3_*` and the `s3` section of `config.yml` for `CONNECTOR_SEND_TO_S3`, which this connector does not use.

The new names are read from version 7.26XXXX.0 of the connector. The former names, `MINIO_*` variables and the `minio` section of `config.yml`, are read too, with a deprecation warning in the logs. Earlier images read only the former names: keep them as long as you may run or go back to such an image. An environment variable wins over `config.yml`, whatever its name. Within the environment, or within `config.yml`, the new name wins over the former one. A variable set to an empty value counts as set and hides the other names: a text setting then takes its default, an empty port stops the connector at startup.

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-stream-exporter:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-stream-exporter:
    image: opencti/connector-stream-exporter:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Stream Exporter
      - CONNECTOR_SCOPE=stream-exporter
      - CONNECTOR_LOG_LEVEL=info
      - STREAM_EXPORTER_S3_ENDPOINT=s3.example.com
      - STREAM_EXPORTER_S3_PORT=9000
      - STREAM_EXPORTER_S3_BUCKET=opencti-export
      - STREAM_EXPORTER_S3_FOLDER=stream
      - STREAM_EXPORTER_S3_ACCESS_KEY=ChangeMe
      - STREAM_EXPORTER_S3_SECRET_KEY=ChangeMe
      - STREAM_EXPORTER_S3_SECURE=true
      - WRITE_EVERY_SEC=60
    restart: always
```

Start the connector:

```bash
docker compose up -d
```

### Manual Deployment

1. Create `config.yml` based on `config.yml.sample`.

2. Install dependencies:

```bash
pip3 install -r requirements.txt
```

3. Start the connector from the `src` directory:

```bash
python3 main.py
```

## Usage

1. Set up an S3-compatible storage
2. Create a Live Stream in OpenCTI (Data Management -> Data Sharing -> Live Streams)
3. Configure the stream with appropriate filters
4. Start the connector
5. Configure [stream-importer](../../external-import/stream-importer/) on the target OpenCTI instance

## Behavior

The connector listens to OpenCTI live stream events and batches them for export to S3.

### Data Flow

```mermaid
graph LR
    subgraph OpenCTI
        direction TB
        Stream[Live Stream]
        Events[Stream Events]
    end

    subgraph Connector
        direction LR
        Listen[Event Listener]
        Buffer[Bulk Buffer]
        Write[Batch Writer]
    end

    subgraph S3[S3 storage]
        direction TB
        API[S3 API]
        Bucket[Object Storage]
    end

    Stream --> Events
    Events --> Listen
    Listen --> Buffer
    Buffer --> Write
    Write --> API
    API --> Bucket
```

### Event Processing

| Step | Description                                              |
|------|----------------------------------------------------------|
| 1    | Listen to live stream events                             |
| 2    | Buffer events in memory                                  |
| 3    | Write to S3 at configured interval                       |
| 4    | Update state with last written message ID                |

### State Management

The connector maintains two state values:
- `start_from`: Updated on each received message
- `last_written_msg_id`: Updated only after successful S3 write

On restart, the connector uses `last_written_msg_id` to resume from the last successfully written position.

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

### Common Issues

| Issue                          | Solution                                              |
|--------------------------------|-------------------------------------------------------|
| Connection refused             | Verify S3 endpoint and port                           |
| Authentication failed          | Verify access key and secret key                      |
| Bucket not created             | Check S3 permissions for bucket creation              |
| SSL errors                     | Set `STREAM_EXPORTER_S3_CERT_CHECK=false` for testing |

## Additional information

- **Use Case**: Synchronize OpenCTI instances without direct network access
- **Companion Connector**: Use with [stream-importer](../../external-import/stream-importer/)
- **Write Interval**: Adjust `WRITE_EVERY_SEC` based on data volume and latency requirements
- **State Recovery**: Connector resumes from last successful write on restart
- **S3 Compatibility**: Works with any S3-compatible object storage
