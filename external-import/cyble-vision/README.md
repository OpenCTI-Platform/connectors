# OpenCTI Cyble Vision Connector

Table of Contents

- [OpenCTI Cyble Vision Connector](#opencti-cyble-vision-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
    - [Alert mapping](#alert-mapping)
    - [Research documents](#research-documents)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

[Cyble Vision](https://cyble.com) is a threat intelligence and digital risk protection platform. It raises alerts
when an organization's domains, IPs, brands, people or credentials appear in places they should not: stealer logs,
data breaches, phishing domains, exposed code and cloud storage, dark web markets, ransomware leak sites, and so on.

This connector imports those alerts into OpenCTI as STIX 2.1 objects, together with Cyble's research advisories,
newsfeed articles and newsflash spot reports. Every imported object carries the Cyble author, a configurable TLP
marking and an external reference that links back to the alert in Cyble Vision.

To push analyst triage in OpenCTI (Incident status and severity) back to Cyble Vision, deploy the companion
[Cyble Vision Writeback](../../stream/cyble-vision-writeback) stream connector alongside this one.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- A Cyble Vision API token with access to the Alerts API (and the engine API if research documents are enabled)

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build the Docker image from the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-cyble-vision:latest
```

Set the variables in `docker-compose.yml` (at least `OPENCTI_URL`, `OPENCTI_TOKEN` and `CYBLE_VISION_API_TOKEN`),
add the service to the OpenCTI `docker-compose.yml` and start it:

```shell
docker compose up -d
```

### Manual Deployment

Copy `config.yml.sample` to `src/config.yml` and fill in the values, then install the dependencies and run the
connector:

```shell
pip3 install -r src/requirements.txt
cd src
python3 main.py
```

## Usage

After the connector starts it runs immediately, then every `CONNECTOR_DURATION_PERIOD` (one hour by default). To force
an immediate run, go to **Data management → Ingestion → Connectors**, open the connector and click the refresh button
to reset its state. The next run then reimports from `CYBLE_VISION_IMPORT_SINCE`.

## Behavior

On each run the connector:

1. Lists the Vision alert services the API token is entitled to (`GET /y/services`), optionally narrowed with
   `CYBLE_VISION_ALERT_SERVICES`.
2. Pages through new alerts for each service in `created_at` order, skipping statuses listed in
   `CYBLE_VISION_EXCLUDE_STATUSES` (`FALSE_POSITIVE` by default).
3. Converts each alert to STIX and sends one bundle per service.
4. Saves a per-service `created_at` checkpoint, so later runs are incremental and a failing service does not rewind
   or skip the others.
5. If enabled, imports research advisories, newsfeed articles and newsflash reports from the Cyble engine API as
   Reports.

All STIX identifiers are deterministic. Re-importing an alert, or importing it again after its status changed in
Vision, updates the existing OpenCTI objects instead of creating duplicates.

### Alert mapping

Every alert produces an **Incident** (type `alert`, with Vision severity, labels `cyble` and `cyble:<service>`, and a
deep link to Vision) and a **Note** holding the alert details. Depending on the service, the connector adds:

| Vision services | Additional objects |
|---|---|
| `stealer_logs`, `leaked_credentials`, `compromised_files`, `compromised_endpoints_cookies`, `compromised_cards`, `darkweb_data_breaches` | Domain-Name, Url, User-Account, Malware (stealer family, when known) |
| `phishing`, `suspicious_domains`, `ip_risk_score`, `botnet`, `malicious_ads`, `iocs` | Domain-Name / IPv4-Addr observables with an Indicator |
| `assets`, `subdomains`, `domain_expiry`, `domain_watchlist`, `new_port`, `web_applications` | Domain-Name / IPv4-Addr observables of the monitored attack surface |
| `ssl_expiry` | Domain-Name and X509-Certificate |
| `new_vulnerability`, `product_vulnerability`, `vulnerability` | Vulnerability (CVE), affected IPv4-Addr |
| `ransomware_updates`, `darkweb_ransomware` | Intrusion-Set for the ransomware group |
| `github`, `postman`, `cloud_storage`, `pastebin`, `telegram_mentions`, `social_media_monitoring`, `darkweb_marketplaces`, `hacktivism`, `i2p`, `tor_links`, `physical_threats`, `ot_ics` and other exposure services | Url of the exposure, Intrusion-Set / IPv4-Addr where the alert names an actor or address |
| Any other service | Incident and Note only |

Related objects are linked to the alert Incident with `related-to` relationships.

Observables that belong to the customer (monitored assets, certificates, subdomains) never get an Indicator: an
Indicator would push the customer's own infrastructure into detection tooling as malicious.

When `CYBLE_VISION_ENABLE_ADVISORIES`, `CYBLE_VISION_ENABLE_NEWSFEED` or `CYBLE_VISION_ENABLE_NEWSFLASH` is enabled,
the matching document alert services (`advisory`, `news_feed`, `flash_report`) are skipped in the alert import so the
same content is not imported twice.

### Research documents

| Source | OpenCTI object |
|---|---|
| Research advisories | Report (type `threat-report`) |
| Newsfeed articles | Report (type `intelligence-summary`) with the original article as an external reference |
| Newsflash spot reports | Report (type `spotrep`) |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for detailed logs. Each Vision page fetched is logged with its service, offset and
size, and alerts that fail to convert are logged at `warning` level with their ID and service, then skipped.

## Additional information

- Contact: [support@cyble.com](mailto:support@cyble.com)
- Product: [Cyble Vision](https://cyble.com)
