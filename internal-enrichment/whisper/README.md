# OpenCTI Whisper Connector

The Whisper connector enriches `IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, and
`Autonomous-System` observables with relationship context from the
[Whisper](https://whisper.security) graph — the internet's largest
infrastructure graph (7.39 billion nodes, 39 billion edges) spanning DNS,
BGP, WHOIS, GeoIP, web links, email infrastructure, and threat intelligence.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
  - [OpenCTI environment variables](#opencti-environment-variables)
  - [Base connector environment variables](#base-connector-environment-variables)
  - [Whisper connector environment variables](#whisper-connector-environment-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
  - [Supported observables](#supported-observables)
  - [Domain-Name enrichment](#domain-name-enrichment)
  - [IP / ASN enrichment](#ip--asn-enrichment)
  - [Notes](#notes)
- [Debugging](#debugging)
- [Additional information](#additional-information)

## Introduction

When an analyst (or a playbook) requests enrichment of a supported observable,
OpenCTI dispatches the request to this connector over RabbitMQ. The connector
runs bounded one-hop queries against the Whisper graph API, translates the
result into a STIX 2.1 bundle, and ships it back to OpenCTI. All STIX IDs are
deterministic, so re-enrichment is idempotent and never duplicates objects.

## Installation

### Requirements

- OpenCTI Platform >= 7.260604.0
- A Whisper API key (`WHISPER_API_KEY`) and graph API URL (`WHISPER_API_URL`).

## Configuration variables

Configuration is provided via environment variables (Docker) or a `config.yml`
file (manual deployment). See [`src/config.yml.sample`](src/config.yml.sample).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml | Docker environment variable | Default                                        | Mandatory | Description                                                         |
|-----------------|------------|-----------------------------|------------------------------------------------|-----------|---------------------------------------------------------------------|
| Connector ID    | id         | `CONNECTOR_ID`              |                                                | Yes       | A unique `UUIDv4` identifier for this connector instance.           |
| Connector Name  | name       | `CONNECTOR_NAME`            | Whisper                                        | No        | Name of the connector.                                              |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           | IPv4-Addr,IPv6-Addr,Domain-Name,Autonomous-System | No     | The observable types the connector will enrich.                    |
| Connector Type  | type       | `CONNECTOR_TYPE`            | INTERNAL_ENRICHMENT                            | Yes       | Should always be `INTERNAL_ENRICHMENT` for this connector.          |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | error                                          | No        | Verbosity of the logs: `debug`, `info`, `warn`, or `error`.        |
| Auto Mode       | auto       | `CONNECTOR_AUTO`            | false                                          | No        | Enables or disables automatic enrichment of observables.           |

### Whisper connector environment variables

| Parameter | config.yml       | Docker environment variable | Default                          | Mandatory | Description                                                              |
|-----------|------------------|-----------------------------|----------------------------------|-----------|--------------------------------------------------------------------------|
| API URL   | whisper.api_url  | `WHISPER_API_URL`           |                                  | Yes       | Base URL of the Whisper graph API, e.g. `https://graph.whisper.security` (the connector POSTs to `/api/query`). |
| API Key   | whisper.api_key  | `WHISPER_API_KEY`           |                                  | Yes       | Whisper API key, sent as the `X-API-Key` header.                         |
| Max TLP   | whisper.max_tlp  | `WHISPER_MAX_TLP`           | TLP:AMBER+STRICT                 | No        | Maximum TLP of an observable the connector will enrich.                  |

## Deployment

### Docker Deployment

Build the image and run it with the environment variables above:

```shell
docker build . -t opencti/connector-whisper:latest
```

Or use the provided [`docker-compose.yml`](docker-compose.yml): set the
variables and run `docker compose up -d`.

### Manual Deployment

```shell
cd src
pip3 install -r requirements.txt
cp config.yml.sample config.yml   # then edit config.yml
python3 main.py
```

## Usage

After the connector is registered, enrich a supported observable from the
OpenCTI UI (**Enrichment** → **Whisper**) or wire it into a playbook. The
connector is `playbook_compatible`: out-of-scope observables arriving through a
playbook chain are passed through unchanged.

## Behavior

### Supported observables

`IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Autonomous-System`. Unsupported types
return a clear status and do not raise.

### Domain-Name enrichment

Domain enrichment is deterministic and category-targeted (not a single broad
one-hop query). Each category produces relationships with a stable, readable
`description`:

| Category | Output |
|----------|--------|
| A / AAAA | `resolves-to` → `IPv4-Addr` / `IPv6-Addr` (`a-record` / `aaaa-record`) |
| CNAME | `related-to` → `Domain-Name` (`cname`) |
| NS / MX | `related-to` → `Domain-Name` (`name-server` / `mx-server`) |
| Registrar / Previous registrar / Registered org | `related-to` → `Identity` (`registrar` / `previous-registrar` / `registered-by`) |
| WHOIS email | `related-to` → `Email-Addr` (`whois-email`) |
| Capped pivots | `nameserver-for-domain`, `mail-server-for-domain`, `subdomain`, `cname-pointing-to-seed`, inbound/outbound web links — each capped, with an overflow Note |

### IP / ASN enrichment

IPv4/IPv6/ASN seeds use a bounded one-hop query plus supplementary passes for
the announcing ASN / prefix / BGP context and threat-feed evidence.

### Notes

Data without a clean STIX SCO is summarized in analyst-visible Notes attached
to the seed: **Whisper SPF policy**, **Whisper WHOIS phone contacts**,
**Whisper threat feed evidence** (with the caveat that the score is supporting
evidence, not an authoritative verdict), **Whisper domain variants**
(registered lookalikes, with method + confidence), capped-pivot overflow
summaries, **Whisper network context** (IP), and dropped non-RFC-1035 DNS
records.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for verbose logging. On startup the connector
waits quietly for the OpenCTI API if it isn't ready yet (logging a one-line
retry message rather than crash-looping); tune via `OPENCTI_STARTUP_MAX_RETRIES`
and `OPENCTI_STARTUP_RETRY_DELAY`.

## Additional information

Whisper API access requires a key; request one at
[whisper.security](https://whisper.security). The connector code is Apache-2.0
licensed and the upstream source of value is the Whisper graph behind the API.