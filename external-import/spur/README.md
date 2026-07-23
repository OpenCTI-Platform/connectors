# OpenCTI Spur External Import Connector

[Spur](https://spur.us) provides anonymous infrastructure intelligence - identifying VPN exit nodes, residential proxies, and other anonymization infrastructure at scale. This connector downloads Spur's bulk IP feeds daily and imports them into OpenCTI as STIX 2.1 observables, enriching your existing data.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
  - [OpenCTI environment variables](#opencti-environment-variables)
  - [Base connector environment variables](#base-connector-environment-variables)
  - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Behavior](#behavior)
- [Debugging](#debugging)
- [Additional information](#additional-information)

## Introduction

This connector imports Spur's anonymous and residential proxy feeds into OpenCTI. Each IP in the feed is converted to a STIX 2.1 `IPv4Address` or `IPv6Address` observable with:

- A computed threat score based on the number of Spur risk flags
- Labels derived from Spur risk categories (e.g. `tunnel`, `login-bruteforce`, `ad-fraud`), infrastructure type, and tunnel operator names
- A description containing ASN, organization, geolocation, detected services, tunnel details, and client statistics
- Optional related AutonomousSystem and Location objects with `belongs-to` / `located-at` relationships
- Optional Indicator objects (STIX pattern `[ipv4-addr:value = '...']`) with `based-on` relationships, created only for IPs that carry risk or tunnel flags

This connector will upsert anonymizer/proxy context into existing observables or indicators. 

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 6.8.12
- [`pycti`](https://pypi.org/project/pycti/) compatible your OpenCTI server version
- A Spur account with feed access - this connector downloads gzipped NDJSON files, it doesn't call the per-IP Context API
- A Spur API key

## Configuration variables

### OpenCTI environment variables

| Parameter     | config.yml | Docker env var  | Mandatory | Description                           |
|---------------|------------|-----------------|-----------|---------------------------------------|
| OpenCTI URL   | `url`      | `OPENCTI_URL`   | Yes       | URL of the OpenCTI platform.          |
| OpenCTI Token | `token`    | `OPENCTI_TOKEN` | Yes       | Admin token for the OpenCTI platform. |

### Base connector environment variables

| Parameter | config.yml | Docker env var | Default | Mandatory | Description |
| --- | --- | --- | --- | --- | --- |
| Connector ID | `id` | `CONNECTOR_ID` | — | Yes | A unique UUIDv4 identifier for this connector instance. |
| Connector Type | `type` | `CONNECTOR_TYPE` | `EXTERNAL_IMPORT` | Yes | Must be `EXTERNAL_IMPORT`. |
| Connector Name | `name` | `CONNECTOR_NAME` | `Spur` | No | Display name in the OpenCTI UI. |
| Connector Scope | `scope` | `CONNECTOR_SCOPE` | — | Yes | Scope of imported data (e.g. `IPv4-Addr,IPv6-Addr`). |
| Log Level | `log_level` | `CONNECTOR_LOG_LEVEL` | `info` | No | Verbosity: `debug`, `info`, `warn`, or `error`. |
| Duration Period | `duration_period` | `CONNECTOR_DURATION_PERIOD` | `PT24H` | No | How often the feed runs (ISO-8601 duration). Default is 24 hours. |

### Connector extra parameters environment variables

| Parameter | config.yml | Docker env var | Default | Mandatory | Description |
| --- | --- | --- | --- | --- | --- |
| API Key | `spur.api_key` | `SPUR_API_KEY` | — | Yes | Your Spur API token. Must have feed download access. |
| Feed URLs | `spur.feed_urls` | `SPUR_FEED_URLS` | See note | No | Comma-separated Spur feed URLs. Defaults to anonymous and residential feeds. Adjust to match your license. |
| TLP Level | `spur.tlp_level` | `SPUR_TLP_LEVEL` | `amber` | No | TLP marking on all imported objects. Options: `clear`, `white`, `green`, `amber`, `amber+strict`, `red`. |
| Create Indicators | `spur.create_indicators` | `SPUR_CREATE_INDICATORS` | `true` | No | Create STIX Indicators for flagged IPs. Only created for IPs with risks or tunnel data. |
| Create ASNs | `spur.create_asns` | `SPUR_CREATE_ASNS` | `true` | No | Create `AutonomousSystem` objects with `belongs-to` relationships. |
| Create Locations | `spur.create_locations` | `SPUR_CREATE_LOCATIONS` | `true` | No | Create `Location` objects with `located-at` relationships. |
| Default Score | `spur.default_score` | `SPUR_DEFAULT_SCORE` | `70` | No | Base OpenCTI score (0–100). Each risk flag adds 5 points, capped at 100. |
| Batch Size | `spur.batch_size` | `SPUR_BATCH_SIZE` | `5000` | No | IP records per STIX bundle sent to OpenCTI. Reduce if you encounter memory pressure. |

Default feed URLs:

```text
https://feeds.spur.us/v2/anonymous/feed.json.gz
https://feeds.spur.us/v2/residential/feed.json.gz
```

## Deployment

### Docker Deployment

Set the `pycti` version in `src/requirements.txt` to match your OpenCTI server version before building:

```text
pycti==<your-opencti-version>
```

Build the image:

```shell
docker build . -t opencti/connector-spur:latest
```

Copy `docker-compose.yml`, fill in the environment variables, and start:

```shell
docker compose up -d
```

### Manual Deployment

Create `config.yml` from `config.yml.sample` and fill in all `ChangeMe` values.

Install dependencies in a virtual environment:

```shell
cd src
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
```

Start the connector:

```shell
python3 main.py
```

## Behavior

### Feed download and scheduling

The connector runs on the configured interval (default: 24 hours). Each run downloads all configured feed URLs sequentially. Spur feeds are updated daily by approximately 05:00 UTC. Before deploying the connector, set `CONNECTOR_DURATION_PERIOD=PT24H` and start the container around 06:00 UTC to consistently pick up fresh data.

Each feed is a gzip-compressed NDJSON file. The connector streams and decompresses in chunks, processing records line by line without loading the entire feed into memory. Records are sent to OpenCTI in batches (default 5000 IPs per bundle).

### STIX objects created per IP

| STIX Object                    | Condition                                                  | Relationship to IP |
|--------------------------------|------------------------------------------------------------|--------------------|
| `IPv4Address` or `IPv6Address` | Always                                                     | —                  |
| `AutonomousSystem`             | `create_asns=true` and ASN data present                    | `belongs-to`       |
| `Location`                     | `create_locations=true` and location data present          | `located-at`       |
| `Indicator`                    | `create_indicators=true` and risks or tunnels present      | `based-on`         |

### Enrichment via upsert

STIX SCO IDs for IP addresses are deterministic UUIDs based solely on the IP value. Any observable already in OpenCTI from another source shares the same STIX ID. When the Spur feed runs, OpenCTI merges the Spur score, labels, and description into the existing observable. IPs not present in the Spur feed are unaffected.

### Score calculation

```text
score = min(100, default_score + (number_of_risks × 5))
```

An IP with no risks at the default score of 70 stays at 70. An IP with `TUNNEL` and `LOGIN_BRUTEFORCE` scores 80.

### Labels

Labels are normalized to lowercase with underscores replaced by hyphens:

- Spur `risks` values: `tunnel`, `login-bruteforce`, `ad-fraud`, `callback-proxy`, `geo-mismatch`, `web-scraping`
- `infrastructure` type: `datacenter`, `mobile`, `satellite`, `in-flight-wifi`, `google`
- Tunnel `type`: `vpn`, `tor`
- Tunnel `operator` names, e.g. `protonvpn`, `mullvad`, `nordvpn`

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for verbose output including per-batch progress and skipped records.

Common issues:

| Symptom | Likely cause |
| --- | --- |
| HTTP 401 / 403 on feed download | `SPUR_API_KEY` invalid or feed not included in your Spur subscription |
| Connector fails to start | `OPENCTI_URL` unreachable or `OPENCTI_TOKEN` invalid |
| Duplicate observables | pycti version mismatch between connector and OpenCTI server |
| No new data after re-run | Feed not yet updated by Spur (published ~05:00 UTC daily) |

## Additional information

### pycti version alignment

The `pycti` client library version must be compatible your OpenCTI server version. Update `src/requirements.txt` and rebuild the image when upgrading OpenCTI.

### Feed access vs. Context API

This connector uses Spur's bulk feed API (gzipped NDJSON download), not the per-IP Context API. Ensure your Spur license covers feed access for the URLs you configure.

### Large feed volumes

Spur feeds contain over 90 million Context API records. The initial import may take significant time. Subsequent daily runs re-import the full feed; Spur feeds are complete daily snapshots, not incremental diffs.
