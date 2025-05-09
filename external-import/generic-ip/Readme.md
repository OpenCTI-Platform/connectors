# OpenCTI Generic Threat Intelligence Connectors

## Description
The **Generic Threat Intelligence (TI) connectors** allow importing feeds containing **IP addresses, URLs, domains, and SHA-1 hashes**.  
Each connector is an independent Python process that interacts with **OpenCTI** and **RabbitMQ** to ingest and enrich cyber threat data.

These connectors parse the provided feeds, validate the indicators, transform them into **STIX observables**, and send them to **OpenCTI**.

## Installation
The connectors can be executed:
- **Manually** using a Python script after configuring the `config.yml` file
- **Within a Docker container** using the corresponding images

We provide an example **`docker-compose.yml` file**, which can be used independently or integrated into **OpenCTI’s global docker-compose setup**.

⚠️ **Note**: If running the connector independently, ensure that the **RabbitMQ port** matches the one configured in OpenCTI.

## Requirements
- **OpenCTI** (≥ 5.12.32)
- **Subscription to a TI feed** (depending on the data source)

## Configuration
The connectors can be configured with the following variables:

| Parameter                   | Docker Env Variable         | Required | Description |
|-----------------------------|----------------------------|----------|-------------|
| `opencti_url`               | `OPENCTI_URL`              | ✅ Yes   | The URL of the OpenCTI platform (avoid trailing `/`). Example: `http://opencti:8080` |
| `opencti_token`             | `OPENCTI_TOKEN`            | ✅ Yes   | OpenCTI authentication token |
| `connector_id`              | `CONNECTOR_ID`             | ✅ Yes   | Unique UUID for the connector |
| `connector_name`            | `CONNECTOR_NAME`           | ✅ Yes   | Connector name as displayed in OpenCTI |
| `connector_scope`           | `CONNECTOR_SCOPE`          | ✅ Yes   | Supported data format (e.g., `text/csv`) |
| `connector_log_level`       | `CONNECTOR_LOG_LEVEL`      | ✅ Yes   | Log level (`debug`, `info`, `warn`, `error`) |
| `interval`                  | `CONNECTOR_RUN_EVERY`      | ✅ Yes   | Execution frequency (`30s`, `1d`, etc.) |
| `target_url`                | `TARGET_URL`               | ✅ Yes   | URL of the threat intelligence feed |
| `score`                     | `SCORE`                    | ✅ Yes   | Threat score assigned to indicators |
| `org_name`                  | `ORG_NAME`                 | ✅ Yes   | Name of the organization providing the data |
| `connector_identity_name`   | `CONNECTOR_IDENTITY_NAME`  | ✅ Yes   | Identity of the TI provider |
| `connector_identity_description` | `CONNECTOR_IDENTITY_DESCRIPTION` | ✅ Yes | Description of the connector |

## Running with Docker
Here is an example **Docker Compose** configuration for the `generic-ip` connector:

```yaml
version: '3'
services:
  connector-generic-ip:
    build:
      context: external-import/generic-ip
    container_name: connector-generic-ip
    restart: always
    environment:
      - OPENCTI_URL=${OPENCTI_URL}
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_GENERIC_IP_ID}
      - CONNECTOR_NAME=generic-ip
      - TARGET_URL=${TARGET_URL}
      - SCORE=50
      - INTERVAL=1d
      - ORG_NAME=Threat_Provider
      - CONNECTOR_IDENTITY_NAME=ThreatFeeds
      - CONNECTOR_IDENTITY_DESCRIPTION="This connector imports a CSV feed containing malicious IPs, validates them, and integrates them as STIX indicators."
    depends_on:
      opencti:
        condition: service_healthy
