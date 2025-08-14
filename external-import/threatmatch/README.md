# 🔗 OpenCTI ThreatMatch Connector

The **ThreatMatch Connector** imports ThreatMatch intelligence (alerts, profiles, IOCs, reports) into OpenCTI. It
authenticates to the ThreatMatch Developer Platform, fetches items since the last successful run (or a configured
relative start date on first run), and maps them to STIX 2.1 objects and relationships in OpenCTI.

---

## 📖 Table of Contents

- [🧩 Introduction](#-introduction)
- [⚙️ Requirements](#-requirements)
- [🔧 Configuration](#-configuration)
    - [OpenCTI configuration](#opencti-configuration)
    - [Base connector configuration](#base-connector-configuration)
    - [ThreatMatch configuration](#threatmatch-configuration)
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

## 🔧 Configuration

Configuration can be provided via a `config.yml` file, or **environment variables**.

### OpenCTI configuration

| Parameter     | `config.yml` | Environment variable | Required | Description                                 |
|---------------|--------------|----------------------|----------|---------------------------------------------|
| OpenCTI URL   | `url`        | `OPENCTI_URL`        | ✅        | Base URL of your OpenCTI instance.          |
| OpenCTI Token | `token`      | `OPENCTI_TOKEN`      | ✅        | Platform token (typically the admin token). |

### Base connector configuration

| Parameter                 | `config.yml`      | Environment variable        | Required | Default     | Description                                         |
|---------------------------|-------------------|-----------------------------|----------|-------------|-----------------------------------------------------|
| Connector ID              | `id`              | `CONNECTOR_ID`              | ✅        | ❌           | Unique `UUIDv4` for this connector instance.        |
| Connector Name            | `name`            | `CONNECTOR_NAME`            | ❌        | ThreatMatch | Display name of the connector.                      |
| Connector Scope           | `scope`           | `CONNECTOR_SCOPE`           | ❌        | threatmatch | Scope/type handled by this connector.               |
| Connector Log Level       | `log_level`       | `CONNECTOR_LOG_LEVEL`       | ❌        | error       | One of `debug`, `info`, `warn`, `error`.            |
| Connector Duration Period | `duration_period` | `CONNECTOR_DURATION_PERIOD` | ❌        | `P1D`       | Polling frequency (ISO‑8601 duration, e.g., `P1D`). |

### ThreatMatch configuration

| Parameter                       | `config.yml`                                | Environment variable                         | Required | Default / Example            | Description                                                                                           |
|---------------------------------|---------------------------------------------|----------------------------------------------|----------|------------------------------|-------------------------------------------------------------------------------------------------------|
| ThreatMatch Client ID           | `threatmatch.client_id`                     | `THREATMATCH_CLIENT_ID`                      | ✅        |                              | OAuth2 client id (Client Credentials).                                                                |
| ThreatMatch Client Secret       | `threatmatch.client_secret`                 | `THREATMATCH_CLIENT_SECRET`                  | ✅        |                              | OAuth2 client secret.                                                                                 |
| ThreatMatch URL                 | `threatmatch.url`                           | `THREATMATCH_URL`                            | ❌        | `https://eu.threatmatch.com` | Base URL of the ThreatMatch API.                                                                      |
| Relative Import Start Date      | `threatmatch.import_from_date`              | `THREATMATCH_IMPORT_FROM_DATE`               | ❌        | `P30D`                       | **Relative** ISO‑8601 duration (e.g., `P30D`) to set the first import window. Used only on first run. |
| Import Profiles                 | `threatmatch.import_profiles`               | `THREATMATCH_IMPORT_PROFILES`                | ❌        | `true`                       | Import ThreatMatch *profiles* dataset.                                                                |
| Import Alerts                   | `threatmatch.import_alerts`                 | `THREATMATCH_IMPORT_ALERTS`                  | ❌        | `true`                       | Import ThreatMatch *alerts* dataset.                                                                  |
| Import IOCs                     | `threatmatch.import_iocs`                   | `THREATMATCH_IMPORT_IOCS`                    | ❌        | `true`                       | Import ThreatMatch *IOCs* dataset.                                                                    |
| Default TLP                     | `threatmatch.tlp_level`                     | `THREATMATCH_TLP_LEVEL`                      | ❌        | `amber`                      | TLP if missing on source objects. One of `clear`, `white`, `green`, `amber`, `amber+strict`, `red`.   |
| Threat actors as intrusion sets | `threatmatch.threat_actor_as_intrusion_set` | `THREATMATCH_THREAT_ACTOR_AS_INSTRUSION_SET` | ❌        | `true`                       | Map ThreatMatch `threat-actor` to STIX `intrusion-set`.                                               |

> **Note**: Set `CONNECTOR_LOG_LEVEL=debug` to see detailed fetch/mapping logs during troubleshooting.

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
