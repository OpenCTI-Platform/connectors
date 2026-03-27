# OpenCTI PRODAFT USTA External Import Connector

This connector imports threat intelligence data from the [USTA](https://usta.prodaft.com) Threat Stream API by [Prodaft](https://prodaft.com) into [OpenCTI](https://www.opencti.io/).

## Table of Contents

- [Overview](#overview)
- [Data Imported](#data-imported)
- [STIX Mapping](#stix-mapping)
- [Requirements](#requirements)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Testing](#testing)
- [Architecture](#architecture)
- [Finding Data in OpenCTI](#finding-data-in-opencti)

---

## Overview

The USTA connector is an **External Import** connector that periodically fetches IOCs and ticket data from six USTA Threat Stream v4 API endpoints and converts them into STIX 2.1 bundles for ingestion into OpenCTI.

**Key features:**

- Imports **malicious URLs**, **phishing sites**, **malware hashes**, **compromised credentials**, **credit card fraud tickets**, and **Deep Sight intelligence tickets**
- Per-feed cursor-based incremental import (never re-imports data)
- Graceful degradation — if one feed fails, the others continue
- Deterministic STIX IDs for proper deduplication
- Automatic batch splitting for large datasets
- Rate limiting and exponential-backoff retry
- Full `schedule_process()` integration (OpenCTI ≥ 6.6.4)
- Raw passwords are **not** stored by default (opt-in via `USTA_STORE_CREDENTIAL_PASSWORD=true`); card numbers are masked to BIN + last 4

---

## Data Imported

| USTA Endpoint | Data Type | STIX Objects Created |
|---|---|---|
| `/ioc/malicious-urls` | C2 infrastructure, RAT callbacks | IPv4-Addr, Domain-Name, URL, Indicator, Malware |
| `/ioc/phishing-sites` | Credential harvesting domains | URL, Domain-Name, Indicator |
| `/ioc/malware-hashes` | Known malware samples | File (StixFile), Indicator, Malware |
| `.../compromised-credentials-tickets` | Stolen credentials | Incident, User-Account, URL, Domain-Name, IPv4-Addr, Malware, Note |
| `.../credit-card-tickets` | Compromised payment cards | Incident, Identity, Note |
| `.../deep-sight-tickets` | Threat reports, leaks, APT activity | Report, ThreatActor, Identity, Relationship |

---

## STIX Mapping

### IOC Feeds (Malicious URLs, Phishing Sites, Malware Hashes)

```
Indicator ──based-on──▸ Observable (IPv4 / Domain / URL / File)
    │
    └──indicates──▸ Malware (from API "tags" field)
```

### Compromised Credentials

```
Incident ──related-to──▸ User-Account (compromised login)
    │    ──related-to──▸ URL (target login page)
    │    ──related-to──▸ Domain-Name (extracted from URL)
    │    ──related-to──▸ IPv4-Addr (victim machine IP)
    │    ──uses────────▸ Malware (stealer family from victim_detail)
    │
    └── Note (victim telemetry: OS, CPU, infection date)

User-Account ──related-to──▸ URL (target login page)
```

### Credit Card Fraud Tickets

```
Incident ──targets──▸ Identity (affected company)
    │
    └── Note (masked card: BIN + last 4, expiry)
```

### Deep Sight Intelligence Tickets

```
Report ──contains──▸ ThreatActor (per threat actor entry)
       │           ▸ Identity    (per targeted organization)
       │           ▸ Relationship (ThreatActor ──targets──▸ Identity)
       │
       └── (optional PDF attachment via x_opencti_files)
```

**Author:** `Identity` SDO — "USTA" (organization)
**Markings:** Configurable TLP level (default: TLP:RED)
**Confidence:** Configurable (default: 99)

---

## Requirements

- OpenCTI Platform ≥ **6.6.4**
- Python ≥ **3.12** (for local development)
- A valid **USTA API Bearer Token** (obtain from USTA platform)

---

## Configuration

| Parameter                             | Environment Variable | Required | Default | Description |
|---------------------------------------|---|---|---|---|
| `opencti.url`                         | `OPENCTI_URL` | **Yes** | — | OpenCTI platform URL |
| `opencti.token`                       | `OPENCTI_TOKEN` | **Yes** | — | OpenCTI API token |
| `connector.id`                        | `CONNECTOR_ID` | **Yes** | — | Unique UUIDv4 for this connector |
| `connector.name`                      | `CONNECTOR_NAME` | No | `USTA` | Display name |
| `connector.duration_period`           | `CONNECTOR_DURATION_PERIOD` | No | `PT30M` | Interval between runs (ISO 8601) |
| `usta.api_key`                        | `USTA_API_KEY` | **Yes** | — | USTA API bearer token |
| `usta.api_base_url`                   | `USTA_API_BASE_URL` | No | `https://usta.prodaft.com` | API base URL |
| `usta.import_start_date`              | `USTA_IMPORT_START_DATE` | No | `P90D` | How far back on first run |
| `usta.page_size`                      | `USTA_PAGE_SIZE` | No | `100` | Records per API page |
| `usta.import_malicious_urls`          | `USTA_IMPORT_MALICIOUS_URLS` | No | `true` | Enable malicious URL feed |
| `usta.import_phishing_sites`          | `USTA_IMPORT_PHISHING_SITES` | No | `true` | Enable phishing sites feed |
| `usta.import_malware_hashes`          | `USTA_IMPORT_MALWARE_HASHES` | No | `true` | Enable malware hashes feed |
| `usta.import_compromised_credentials` | `USTA_IMPORT_COMPROMISED_CREDENTIALS` | No | `true` | Enable compromised credentials feed |
| `usta.import_credit_cards`            | `USTA_IMPORT_CREDIT_CARDS` | No | `true` | Enable credit card fraud feed |
| `usta.import_deep_sight_tickets`      | `USTA_IMPORT_DEEP_SIGHT_TICKETS` | No | `true` | Enable Deep Sight intelligence tickets feed |
| `usta.store_credential_password`      | `USTA_STORE_CREDENTIAL_PASSWORD` | No | `false` | Store raw password in User-Account STIX object (disabled by default) |
| `usta.tlp_level`                      | `USTA_TLP_LEVEL` | No | `red` | TLP marking for all objects |
| `usta.confidence_level`               | `USTA_CONFIDENCE_LEVEL` | No | `99` | Confidence score (0–100) |

---

## Deployment

### Docker (Recommended)

Set the required env variables in `docker-compose.yml`, then run.

```bash
# Build and run
docker compose up --build
```

### Standalone Python

```bash
cd src
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
# ..Set required env vars here..
python main.py
```

---

## Testing

Tests use `pytest` with `pytest-cov` for 95%+ code coverage.

```bash
# From the project root:
pip install -r src/requirements.txt -r tests/test-requirements.txt
pytest --cov --cov-report=term-missing
```

`tests/conftest.py` injects `src/` into `sys.path` so that `pytest` can resolve `from connector import ...` and `from usta_client import ...` correctly regardless of the working directory.

---

## Architecture

```
usta/
├── __metadata__
|   ├── connector_manifest.json
|   └── logo.png
├── src/
|   ├── requirements.txt
│   ├── main.py                          # Entry point
│   ├── connector/
│   │   ├── __init__.py
│   │   ├── connector.py                 # Import orchestration (state, work, batching)
│   │   ├── converter_to_stix.py         # STIX 2.1 conversion for all 6 data families
│   │   ├── settings.py                  # Pydantic configuration models
│   │   └── utils.py                     # Shared utility functions
│   └── usta_client/
│       ├── __init__.py
│       └── api_client.py                # USTA API client (rate-limited, retried)
├── tests/
│   ├── conftest.py                      # Shared fixtures
│   ├── test_main.py                     # Import smoke tests
│   ├── test_connector/
│   │   ├── test_connector.py            # Orchestrator tests
│   │   ├── test_converter_to_stix.py    # Converter tests
│   │   ├── test_settings.py             # Configuration tests
│   │   └── test_utils.py                # Utility tests
│   └── test_client/
│       └── test_api_client.py           # API client tests
├── entrypoint.sh                        # Docker entrypoint
├── Dockerfile
├── pytest.ini 
└── docker-compose.yml
```

### State Management

| State Key | Purpose |
|---|---|
| `last_run_start` | Timestamp of the last run |
| `last_run_with_data` | Timestamp of last run that ingested data |
| `malicious_urls_last_created` | Cursor for malicious URLs feed |
| `phishing_sites_last_created` | Cursor for phishing sites feed |
| `malware_hashes_last_created` | Cursor for malware hashes feed |
| `compromised_creds_last_created` | Cursor for compromised credentials feed |
| `credit_cards_last_created` | Cursor for credit card tickets feed |
| `deep_sight_last_created` | Cursor for Deep Sight intelligence tickets feed |

---

## Finding Data in OpenCTI

### Compromised Accounts / Credentials

Compromised credentials are imported as an **Incident** with related STIX objects.

1. **Observations → Observables**: Filter by type `User Account`. Each compromised login appears as a `User-Account` SCO with the `account_login` field set to the stolen username/email.

2. **Events → Incidents**: An Incident SDO is created per credential record, linked to the User-Account, URL, and IP observables via `related-to` relationships.

3. **Analysis → Notes**: Victim telemetry (OS, IP, computer name, infection date, stealer family) is attached as Notes linked to the Incident and User-Account.

4. **Threats → Malware**: Stealer families (e.g., "StealC", "Vidar") are created as Malware SDOs and linked via `related-to` relationships.

### Malicious URLs / Phishing Sites

**Analysis → Indicators**: Filter labels by `malicious-activity` or `phishing`.

### Malware Hashes

**Analysis → Indicators**: Filter by main observable type `StixFile`.
**Observations → Observables**: Filter by type `File` to see the hash observables directly.

### Credit Card Fraud

**Events → Incidents**: Each compromised card appears as an Incident with masked card details in the description. The company is linked via a `targets` relationship.

### Deep Sight Intelligence Tickets

**Analyses → Reports**: Each Deep Sight ticket is imported as a Report SDO. Threat actors and targeted organizations are linked via `targets` relationships and appear under **Threats → Threat Actors** and **Entities → Organizations** respectively.

---

## License

Apache 2.0
