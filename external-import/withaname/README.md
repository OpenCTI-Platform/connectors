# DDoSIA Connector

This connector imports DDoS targets from the DDoSIA campaign (provided by `witha.name`) into the OpenCTI platform.

## Introduction

The DDoSIA connector automatically retrieves snapshots of DDoS targets. For each snapshot, it creates:
- **Domain-Name** entities for the targeted hosts.
- **IPv4-Addr** entities for the associated IP addresses.
- **Resolves-to** relationships between the domains and the IPs.
- **Notes** attached to each domain containing the raw JSON data of the targets for traceability.

## Installation

### Docker Deployment

1. Build the Docker image:
   ```shell
   docker build . -t opencti/connector-withaname:latest
   ```

2. Use the provided `docker-compose.yml` and configure the environment variables.

3. Start the container:
   ```shell
   docker compose up -d
   ```

### Manual Deployment

1. Create a `config.yml` based on `config.yml.sample`.
2. Install the required python dependencies:
   ```shell
   pip3 install -r requirements.txt
   ```
3. Start the connector from the `src` directory:
   ```shell
   python3 main.py
   ```

## Configuration variables

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | --------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml | Docker environment variable | Default         | Mandatory | Description                                                                              |
| --------------- | ---------- | --------------------------- | --------------- | --------- | -------------------------------------------------------------------------------------------------------- |
| Connector ID    | id         | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type       | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                               |
| Connector Name  | name       | `CONNECTOR_NAME`            |                 | Yes       | Name of the connector.                                                                   |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           |                 | Yes       | The scope or type of data the connector is importing.                                |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Duration Period | duration_period | `CONNECTOR_DURATION_PERIOD` | 1h              | No        | The period of time to await between two runs of the connector.                           |

### DDoSIA specific parameters

| Parameter | config.yml | Docker environment variable | Default | Mandatory | Description |
| ---------- | ----------- | --------------------------- | --------- | --------- | ----------- |
| API Base URL | api_base_url | `DDOSIA_API_BASE_URL` | / | Yes | The base URL of the witha.name API. |
| TLP Level | tlp_level | `DDOSIA_TLP_LEVEL` | green | No | Default TLP level of the imported entities. |
| Import Start Timestamp | import_start_timestamp | `DDOSIA_IMPORT_START_TIMESTAMP` | null | No | Timestamp to start the first import. <br> - `null`: Only the most recent snapshot. <br> - `0`: All available history. <br> - `value`: All snapshots since this timestamp. |
| Create Notes | create_notes | `DDOSIA_CREATE_NOTES` | true | No | Whether to create STIX Note objects for each domain containing raw targets data. Set to `false` to disable note creation. |

## Behavior

The connector operates in a scheduled pull mode:
1. It fetches the list of available snapshots from `/api/configs`.
2. It identifies new snapshots based on the `last_cfg_ts` stored in the state.
3. For each new snapshot, it creates a dedicated OpenCTI **Work**.
4. It retrieves the targets for that snapshot via `/api/config/{cfg_id}`.
5. It transforms the data into STIX 2.1 objects and sends them as a bundle.
6. It updates the state only after the successful import of the snapshot.

## Debugging

The connector can be debugged by setting the `CONNECTOR_LOG_LEVEL` to `debug`.
Logging messages are available via the standard output and can be viewed in the Docker logs.
