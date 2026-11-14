# OpenCTI DECTRAX External Import Connector

Table of Contents

- [OpenCTI DECTRAX External Import Connector](#opencti-dectrax-external-import-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration Variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Behavior and Data Model](#behavior-and-data-model)
  - [MITRE ATT&CK Mapping](#mitre-attck-mapping)
  - [Debugging](#debugging)

## Introduction

[DECTRAX](https://dectrax.io) is an autonomous cyber deception and automated threat interdiction platform. This connector continuously ingests verified attacker telemetry, active decoy sensor engagements, and External Dynamic Lists (EDL) from DECTRAX into OpenCTI as standards-compliant STIX 2.1 bundles.

Because deception sensors have zero legitimate operational traffic, interactions with DECTRAX decoy assets represent high-fidelity malicious reconnaissance, credential brute force, and lateral movement.

## Installation

### Requirements

- OpenCTI Platform >= 6.0.0
- Python 3.10+ (for manual deployment)
- Network connectivity to DECTRAX API endpoint (or EDL feed)

## Configuration Variables

The connector supports configuration via `config.yml` or standard environment variables.

### OpenCTI Configuration

| Parameter | Docker Env Var | Default | Description |
|---|---|---|---|
| `opencti.url` | `OPENCTI_URL` | - | OpenCTI server URL (e.g. `http://localhost:8080`) |
| `opencti.token` | `OPENCTI_TOKEN` | - | OpenCTI user API token |

### Connector Configuration

| Parameter | Docker Env Var | Default | Description |
|---|---|---|---|
| `connector.id` | `CONNECTOR_ID` | `dectrax-external-import-connector` | Unique UUIDv4 identifier for connector |
| `connector.name` | `CONNECTOR_NAME` | `DECTRAX Autonomous Deception` | Display name in OpenCTI Data > Connectors |
| `connector.scope` | `CONNECTOR_SCOPE` | `dectrax,ipv4-addr,indicator` | Supported entity scopes |
| `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `info` | Logging verbosity (`debug`, `info`, `warn`, `error`) |
| `connector.duration_period` | `CONNECTOR_DURATION_PERIOD` | `PT1H` | ISO 8601 execution interval |

### DECTRAX Configuration

| Parameter | Docker Env Var | Default | Description |
|---|---|---|---|
| `dectrax.api_url` | `DECTRAX_API_URL` | `http://localhost:8000` | Base URL of DECTRAX instance |
| `dectrax.api_key` | `DECTRAX_API_KEY` | - | Optional bearer token for DECTRAX API |
| `dectrax.edl_endpoint` | `DECTRAX_EDL_ENDPOINT` | `/api/v1/edl/firewall.txt` | Path to interdiction blocklist EDL |
| `dectrax.telemetry_endpoint` | `DECTRAX_TELEMETRY_ENDPOINT` | `/api/v1/telemetry/threats` | Path to structured threat telemetry |
| `dectrax.tlp_level` | `DECTRAX_TLP_LEVEL` | `clear` | STIX TLP marking (`clear`, `white`, `green`, `amber`, `red`) |
| `dectrax.confidence_level` | `DECTRAX_CONFIDENCE_LEVEL` | `90` | Confidence score for generated STIX indicators (0-100) |
| `dectrax.create_indicators` | `DECTRAX_CREATE_INDICATORS` | `true` | Create STIX Indicator objects |
| `dectrax.create_observables` | `DECTRAX_CREATE_OBSERVABLES` | `true` | Create STIX Cyber Observables (`IPv4Address`) |

## Deployment

### Docker Deployment

Build and run using Docker Compose:

```bash
docker compose up -d
```

Or build manually:

```bash
docker build -t opencti/connector-dectrax:latest .
docker run -d --name connector-dectrax \
  -e OPENCTI_URL="http://opencti:8080" \
  -e OPENCTI_TOKEN="YOUR_OPENCTI_TOKEN" \
  -e CONNECTOR_ID="4dfb62c9-6cb8-48b5-90df-520e2ef5b901" \
  -e DECTRAX_API_URL="http://dectrax:8000" \
  opencti/connector-dectrax:latest
```

### Manual Deployment

```bash
cd external-import/dectrax
pip install -r requirements.txt
cp config.yml.sample src/config.yml
# Edit src/config.yml with your credentials
python3 src/main.py
```

## Behavior and Data Model

When the connector executes:
1. It queries the DECTRAX telemetry and interdiction EDL endpoints.
2. For each attacker interaction with high-interaction decoys, it constructs:
   - **STIX Identity**: Represents the author organization (`DECTRAX Autonomous Deception Platform`).
   - **STIX IPv4-Addr**: Cyber observable for the adversarial host.
   - **STIX Indicator**: Detection pattern `[ipv4-addr:value = '...']` with confidence 90+.
   - **STIX AttackPattern**: Mapped MITRE ATT&CK techniques based on the decoy protocol engaged.
   - **STIX Relationships**: `indicates` relationship linking Indicator to AttackPattern, and `related-to` linking Indicator to Author Identity.
3. The STIX 2.1 bundle is validated and transmitted to OpenCTI via RabbitMQ ingestion queues.
4. The connector persists state (`last_sync`, record counts) to ensure idempotent runs.

## MITRE ATT&CK Mapping

| Decoy Service / Port | Target Protocol | Mapped MITRE Technique | Technique ID |
|---|---|---|---|
| RDP (3389) | Remote Desktop Protocol | Remote Services: Remote Desktop Protocol | `T1021.001` |
| RDP Brute Force | Remote Desktop Protocol | Brute Force | `T1110` |
| LDAP (389) | Active Directory Directory Service | Permission Groups Discovery: Domain Groups | `T1069.002` |
| LDAP Honeytoken | Active Directory Directory Service | Valid Accounts | `T1078` |
| Modbus (502) | ICS / Operational Technology | Unauthorized Command Message | `T0855` |
| Decoy Sweep | Network Reconnaissance | Network Service Discovery | `T1046` |

## Debugging

Enable verbose logging by setting:
```yaml
connector:
  log_level: 'debug'
```
or via environment:
```bash
CONNECTOR_LOG_LEVEL=debug
```
