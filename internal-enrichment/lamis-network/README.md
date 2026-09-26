# OpenCTI Lamis Network IP Intelligence & Fraud Scoring Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | 2026-09 | Initial Release |

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration](#configuration)
  - [OpenCTI Configuration](#opencti-configuration)
  - [Base Connector Configuration](#base-connector-configuration)
  - [Lamis Network Configuration](#lamis-network-configuration)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Behavior](#behavior)
  - [Data Flow](#data-flow)
  - [STIX 2.1 Mapping](#stix-21-mapping)
  - [TLP & Privacy](#tlp--privacy)
  - [Error Handling](#error-handling)
- [Community Program](#community-program)

---

## Introduction

[Lamis Network](https://lamisnetwork.com) is an IP intelligence and fraud risk scoring provider hosted in Austria (EU).

This internal-enrichment connector automatically enriches `IPv4-Addr` and `IPv6-Addr` observables in OpenCTI with:
- **Fraud Risk Score (0–100)**: Real-time probability scoring written to observable's `x_opencti_score`.
- **Autonomous System (ASN)**: Links `AutonomousSystem` SCO with a `belongs-to` relationship.
- **Geolocation**: Creates `Location` SDOs (`Country`, `City`) with `located-at` relationships.
- **Infrastructure Classification**: Attaches STIX labels (`datacenter`, `vpn`, `tor-exit-node`, `public-proxy`).
- **Suspicious Flagging**: Attaches `suspicious` label when risk score meets or exceeds the configurable threshold.
- **External References**: Records the Lamis Network source and evaluated IP.

---

## Installation

### Requirements

- OpenCTI Platform >= 5.12.0
- Valid Lamis Network API Key ([Community Program](https://lamisnetwork.com/community.html) or Commercial)
- Network connectivity from the connector to `https://api.lamisnetwork.com`

---

## Configuration

Configuration can be provided via environment variables or `config.yml`.

### OpenCTI Configuration

| Parameter | Docker Env Var | Description | Required |
|---|---|---|---|
| `opencti.url` | `OPENCTI_URL` | URL of the OpenCTI platform | Yes |
| `opencti.token` | `OPENCTI_TOKEN` | Connector user API token | Yes |

### Base Connector Configuration

| Parameter | Docker Env Var | Default | Description |
|---|---|---|---|
| `connector.id` | `CONNECTOR_ID` | | Unique UUID v4 for the connector |
| `connector.name` | `CONNECTOR_NAME` | `Lamis Network IP Intelligence` | Display name of the connector |
| `connector.scope` | `CONNECTOR_SCOPE` | `IPv4-Addr,IPv6-Addr` | Supported observable types |
| `connector.auto` | `CONNECTOR_AUTO` | `false` | Enable automatic enrichment on observable creation (default: `false` for quota-based APIs) |
| `connector.confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | `50` | Confidence level (0-100) |
| `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `info` | Log verbosity (`debug`, `info`, `warn`, `error`) |

### Lamis Network Configuration

| Parameter | Docker Env Var | Default | Description |
|---|---|---|---|
| `lamis_network.api_key` | `LAMIS_NETWORK_API_KEY` | | Lamis Network API key |
| `lamis_network.api_url` | `LAMIS_NETWORK_API_URL` | `https://api.lamisnetwork.com` | Base API endpoint |
| `lamis_network.timeout` | `LAMIS_NETWORK_TIMEOUT` | `10` | HTTP request timeout in seconds |
| `lamis_network.suspicious_threshold` | `LAMIS_NETWORK_SUSPICIOUS_THRESHOLD` | `75` | Minimum fraud score to tag with `suspicious` label |
| `lamis_network.create_indicator` | `LAMIS_NETWORK_CREATE_INDICATOR` | `true` | Generate STIX Indicator linked via `based-on` |
| `lamis_network.add_relationships` | `LAMIS_NETWORK_ADD_RELATIONSHIPS` | `true` | Create ASN (`belongs-to`) and Location (`located-at`) entities |
| `lamis_network.default_tlp` | `LAMIS_NETWORK_DEFAULT_TLP` | `TLP:CLEAR` | Default TLP marking for emitted STIX objects |
| `lamis_network.max_tlp` | `LAMIS_NETWORK_MAX_TLP` | `TLP:AMBER` | Maximum TLP allowed for enrichment (skips if exceeded) |

---

## Deployment

### Docker Deployment

Build the image from this connector directory before starting Compose:

```bash
docker build -t lamis-network-opencti:local .
```

```yaml
services:
  connector-lamis-network:
    image: lamis-network-opencti:local
    build:
      context: .
      dockerfile: Dockerfile
    environment:
      - OPENCTI_URL=http://localhost:8080
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Lamis Network IP Intelligence
      - CONNECTOR_SCOPE=IPv4-Addr,IPv6-Addr
      - CONNECTOR_AUTO=false
      - CONNECTOR_CONFIDENCE_LEVEL=50
      - CONNECTOR_LOG_LEVEL=info
      - LAMIS_NETWORK_API_KEY=ChangeMe
      - LAMIS_NETWORK_API_URL=https://api.lamisnetwork.com
      - LAMIS_NETWORK_TIMEOUT=10
      - LAMIS_NETWORK_SUSPICIOUS_THRESHOLD=75
      - LAMIS_NETWORK_CREATE_INDICATOR=true
      - LAMIS_NETWORK_ADD_RELATIONSHIPS=true
      - LAMIS_NETWORK_DEFAULT_TLP=TLP:CLEAR
      - LAMIS_NETWORK_MAX_TLP=TLP:AMBER
    restart: always
```

### Manual Deployment

```bash
cd internal-enrichment/lamis-network/src
pip install -r requirements.txt
cp ../config.yml.sample config.yml
# Edit config.yml with your OpenCTI and Lamis Network parameters
python main.py
```

---

## Behavior

### Data Flow

```
OpenCTI Observable (IPv4 / IPv6)
       │
       ▼
TLP Check (<= max_tlp?) ─── No ──► Skip (no external request)
       │
      Yes
       │
       ▼
Query Lamis Network API (/v1/ip/{ip})
       │
       ├─► Update Observable (score, labels, source reference) in STIX bundle
       ├─► Create AutonomousSystem SCO ──(belongs-to)──► Observable
       ├─► Create Country & City Location SDOs ──(located-at)──► Observable
       └─► Create Indicator (labels, description) ──(based-on)──► Observable
```

### STIX 2.1 Mapping

| Lamis Network Field | STIX 2.1 Entity | Relationship | Details |
|---|---|---|---|
| `fraud_score` | Cyber-Observable Property | - | Populates `x_opencti_score` (0–100) |
| `asn` | `AutonomousSystem` (SCO) | `belongs-to` | ASN number and organization name |
| `geo.country` | `Location` (SDO, Country) | `located-at` | Country code and country name |
| `geo.city` | `Location` (SDO, City) | `located-at` | City name anchored to country |
| Classifications | Observable and optional `Indicator` (SDO) | `based-on` when enabled | Labels: `datacenter`, `vpn`, `tor-exit-node`, `public-proxy`, `suspicious` |
| Source URL | `External-Reference` | - | Attached to Observable and optional Indicator; points to the Lamis Network homepage |

### TLP & Privacy

The connector enforces strict TLP validation **before** dispatching the observable's IP address to the external API:
- Every TLP marking is checked. If any is greater than `LAMIS_NETWORK_MAX_TLP` (e.g. `TLP:RED` against `TLP:AMBER`) or cannot be identified, enrichment is skipped before the external request.
- Emitted STIX entities inherit the source observable's markings, preventing unintended data exposure within OpenCTI.

### Error Handling

Network timeouts, rate limits (HTTP 429), authentication errors (HTTP 401/403), malformed JSON, and incomplete scores leave the observable unchanged. Enrichment is built and serialized before the STIX bundle is sent. The connector authenticates to Lamis Network with `Authorization: Bearer <API key>`.

---

## Community Program

Lamis Network offers **50,000 free queries per month** per approved key for eligible open-source projects, researchers, and CSIRT/CERT evaluation:
- [Lamis Network Community Program](https://lamisnetwork.com/community.html)
- [Official Website](https://lamisnetwork.com)
