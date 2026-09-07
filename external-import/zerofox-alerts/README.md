# ZeroFox Alerts Connector

This connector imports ZeroFox operational alerts into OpenCTI as **STIX Incidents**.

## Overview

The ZeroFox Alerts connector ingests alerts from the ZeroFox `/alerts/` API endpoint, which includes impersonation attempts, phishing, malware detections, domain squatting, and other digital risk protection alerts.

This connector is **complementary** to the existing `external-import/zerofox` connector which consumes curated CTI feeds (`/cti/*`) and produces Indicators/Observables.

## STIX Object Mapping

Each ZeroFox alert produces:

| ZeroFox Object | STIX Object | Relationship |
|---|---|---|
| Alert | `Incident` | — |
| Entity / Asset | `Identity` (victim) | Incident `targets` Identity |
| Perpetrator | `Threat Actor` | Incident `attributed-to` Threat Actor |
| offending_content_url | `URL` Observable | Incident `related-to` URL |
| metadata.occurrences[].term | `Domain-Name` Observable | Incident `related-to` Domain-Name |
| perpetrator.url | `URL` Observable | Incident `related-to` URL |

## Field Mapping

### Alert → Incident

| ZeroFox Field | OpenCTI Field |
|---|---|
| `alert_type` | `incident_type` |
| `severity` (1-4) | severity (low/medium/high/critical) |
| `timestamp` | `created` |
| `content_created_at` | `first_seen` |
| `rule_name` | `name` |
| `network` | label `zerofox:network:<value>` |
| `notes` | `description` |
| `escalated` | label `zerofox:escalated` + force severity critical |
| `tags` | `labels` |
| `metadata.justification` | label `zerofox:justification:<value>` |

### Metadata (stringified JSON — parsed automatically)

- `justification` → label
- `alert_reasons[].value.text_content` → enriches description
- `occurrences[].term` → Domain-Name observables
- `content_raw_data.details` → enriches description

## Authentication

This connector uses **Personal Access Token (PAT)** authentication (Mechanism B):

```
Authorization: Token <YOUR_PAT>
```

Generate a PAT from the ZeroFox admin UI. No token refresh is required.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Compose

```bash
docker-compose up -d
```

### Local Development

```bash
cp .env.sample .env
# Edit .env with your credentials
pip install -r requirements.txt
cd src && python main.py
```

## Architecture

```
src/
├── main.py                          # Entry point
└── zerofox_alerts/
    ├── __init__.py
    ├── settings.py                  # Pydantic settings (SDK BaseConnectorSettings)
    ├── client_api.py                # API client (SDK BaseClientApi)
    ├── models.py                    # Pydantic models for API responses
    └── zerofox_alert_processor.py   # Data processor & STIX conversion (SDK BaseDataProcessor)
```

## References

- [ZeroFox API Docs - Alerts](https://api.zerofox.com/1.0/docs/#operation--alerts--get)
- [ZeroFox Platform](https://cloud.zerofox.com/alerts)
- [OpenCTI Incident definition](https://docs.opencti.io/latest/usage/exploring-events/#incidents)
