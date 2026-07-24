# 🔗 OpenCTI ThreatMatch Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

The **ThreatMatch Connector** imports ThreatMatch intelligence (alerts, profiles, IOCs, reports) into OpenCTI. It
authenticates to the ThreatMatch Developer Platform, fetches items since the last successful run (or a configured
relative start date on first run), and maps them to STIX 2.1 objects and relationships in OpenCTI.

---

## 📖 Table of Contents

- [🧩 Introduction](#-introduction)
- [⚙️ Requirements](#-requirements)
- [🔧 Configuration](#-configuration)
- [🚀 Deployment](#-deployment)
    - [Docker](#docker)
    - [Manual (venv)](#manual-venv)
- [📌 Usage](#-usage)
- [⚙️ Connector behavior](#-connector-behavior)
- [🛟 Troubleshooting](#-troubleshooting)

---

## 🧩 Introduction

This connector periodically pulls ThreatMatch data and ingest it into OpenCTI. You can enable/disable specific
datasets (profiles, alerts, IOCs) and set a default TLP for items missing markings.

---

## ⚙️ Requirements

- Network egress to the ThreatMatch API (`THREATMATCH_URL`)
- ThreatMatch **Client Credentials** (client id/secret)

---

## 🔧 Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

---

## 🚀 Deployment

### Docker

```bash
# Build
docker build -t opencti/connector-threatmatch:latest .

# Or pull (when published)
# docker pull opencti/connector-threatmatch:latest
```

### Manual (venv)

```bash
python3 -m venv venv
source venv/bin/activate

# Minimal runtime deps
pip install -r src/requirements.txt
# For tests
# pip install -r tests/test-requirements.txt

# Provide configuration via config.yml or environment
python3 src/main.py
```

Configuration lookup order:

1. `config.yml`
3. Environment variables
4. Built‑in defaults

---

## 📌 Usage

On each run (or according to `CONNECTOR_DURATION_PERIOD`):

- Authenticate to the ThreatMatch API using client credentials.
- Determine the **import window**:
    - First run: from `THREATMATCH_IMPORT_FROM_DATE` (relative duration) to *now*.
    - Subsequent runs: from the **last successful run** to *now*.
- Fetch the enabled datasets (profiles, alerts, IOCs) with pagination.
- Map and upsert to OpenCTI as STIX 2.1 SDOs/SROs (e.g., `report`, `indicator`, `malware`, `intrusion-set`,
  `relationship`).
- Apply TLP markings (defaulting to `THREATMATCH_TLP_LEVEL` when missing).

---

## ⚙️ Connector behavior

- **Idempotent upserts**: objects are deduplicated by external references and natural keys where possible.
- **Stateful**: the connector stores the last run timestamp and resumes from there.
- **No destructive actions**: it does not delete/update items outside its scope.
- **Error handling**: on 401 responses, the connector **refreshes the token and retries once**; other HTTP errors are
  logged and surfaced.

---

## 🛟 Troubleshooting

- **401 Unauthorized**: Verify client id/secret and that the token endpoint is reachable from the connector container.
- **import_from_date**: Having a relative date too far in the past (e.g., `P365D`) will lead to performance issues
  due to large data volumes. Use a more recent date if possible (e.g., `P30D`).

---
