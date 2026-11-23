# WithaName Connector

This connector imports DDoS targets from the DDoSIA campaign (provided by `witha.name`) into the OpenCTI platform.

## Introduction

The WithaName connector automatically retrieves snapshots of DDoS targets. For each snapshot, it creates:
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

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

Only `OPENCTI_URL` and `OPENCTI_TOKEN` are required. Set `CONNECTOR_ID` to a unique UUIDv4 for each deployment; every other variable has a default.

`WITHANAME_IMPORT_START_TIMESTAMP` sets where the first import starts:

- unset (default): only the most recent snapshot.
- `0`: all available history.
- a Unix timestamp: all snapshots since this timestamp.

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
