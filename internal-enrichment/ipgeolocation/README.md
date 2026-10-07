# OpenCTI IPGeolocation.io Connector

| Status    | Date | Comment |
|-----------|------|---------|
| Community | -    | -       |

The IPGeolocation.io connector enriches IPv4 and IPv6 observables with IP intelligence from [IPGeolocation.io](https://ipgeolocation.io): geolocation, autonomous system, company, threat intelligence and abuse contact.

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
- [Usage](#usage)
- [Behavior](#behavior)
- [Debugging](#debugging)
- [Additional information](#additional-information)

## Introduction

For each observable, the connector makes one request to the IPGeolocation.io [IP Location API](https://ipgeolocation.io/documentation/ip-location-api.html) and sends back:

- the observable with a score, labels (`vpn`, `tor`, `known-attacker`, `risk:high`, ...) and a link to its IPGeolocation.io page
- its country and city, autonomous system, operating organization, cloud provider and hostname, with relationships
- an indicator when the risk score reaches a threshold
- a note with the full enrichment report, including the abuse contact

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- An IPGeolocation.io API key ([sign up](https://app.ipgeolocation.io/signup)). Free plans return location and ASN; the threat intelligence, abuse contact and hostname modules need a [paid plan](https://ipgeolocation.io/pricing.html).

## Configuration variables

Configuration comes from environment variables or from `config.yml` (see `config.yml.sample`).

### OpenCTI environment variables

| Parameter     | config.yml      | Docker environment variable | Mandatory | Description                                          |
|---------------|-----------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | `opencti.url`   | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | `opencti.token` | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml            | Docker environment variable | Default               | Mandatory | Description                                                                 |
|-----------------|-----------------------|-----------------------------|-----------------------|-----------|-----------------------------------------------------------------------------|
| Connector ID    | `connector.id`        | `CONNECTOR_ID`              |                       | Yes       | A unique `UUIDv4` identifier for this connector instance.                   |
| Connector Name  | `connector.name`      | `CONNECTOR_NAME`            | `IPGeolocation.io`    | No        | Name of the connector.                                                      |
| Connector Scope | `connector.scope`     | `CONNECTOR_SCOPE`           | `IPv4-Addr,IPv6-Addr` | No        | The observable types the connector enriches.                                |
| Log Level       | `connector.log_level` | `CONNECTOR_LOG_LEVEL`       | `error`               | No        | `debug`, `info`, `warn` or `error`.                                         |
| Auto            | `connector.auto`      | `CONNECTOR_AUTO`            | `false`               | No        | Enrich new observables automatically. Every lookup spends API credits.      |

### Connector extra parameters environment variables

| Parameter            | config.yml                           | Docker environment variable            | Default                         | Mandatory | Description                                                                                       |
|----------------------|--------------------------------------|----------------------------------------|---------------------------------|-----------|---------------------------------------------------------------------------------------------------|
| API key              | `ipgeolocation.api_key`              | `IPGEOLOCATION_API_KEY`                |                                 | Yes       | IPGeolocation.io API key.                                                                         |
| API base URL         | `ipgeolocation.api_base_url`         | `IPGEOLOCATION_API_BASE_URL`           | `https://api.ipgeolocation.io`  | No        | IPGeolocation.io API base URL.                                                                    |
| Timeout              | `ipgeolocation.timeout`              | `IPGEOLOCATION_TIMEOUT`                | `30`                            | No        | HTTP request timeout in seconds.                                                                  |
| Include security     | `ipgeolocation.include_security`     | `IPGEOLOCATION_INCLUDE_SECURITY`       | `true`                          | No        | Request the threat score and VPN, proxy, Tor, relay, bot, spam and attacker flags (paid plans, 2 extra credits). |
| Include abuse        | `ipgeolocation.include_abuse`        | `IPGEOLOCATION_INCLUDE_ABUSE`          | `true`                          | No        | Request the abuse contact (paid plans, 1 extra credit).                                           |
| Include hostname     | `ipgeolocation.include_hostname`     | `IPGEOLOCATION_INCLUDE_HOSTNAME`       | `true`                          | No        | Request the hostname (paid plans, no extra credit).                                               |
| Max TLP level        | `ipgeolocation.max_tlp_level`        | `IPGEOLOCATION_MAX_TLP_LEVEL`          | `amber+strict`                  | No        | Highest TLP of the observables sent to IPGeolocation.io: `clear`, `white`, `green`, `amber`, `amber+strict` or `red`. |
| TLP level            | `ipgeolocation.tlp_level`            | `IPGEOLOCATION_TLP_LEVEL`              | `clear`                         | No        | TLP marking of the objects the connector creates.                                                 |
| Create labels        | `ipgeolocation.create_labels`        | `IPGEOLOCATION_CREATE_LABELS`          | `true`                          | No        | Add labels to the observable.                                                                     |
| Create relationships | `ipgeolocation.create_relationships` | `IPGEOLOCATION_CREATE_RELATIONSHIPS`   | `true`                          | No        | Link the observable to its country, city, autonomous system, organizations and hostname.          |
| Create indicator     | `ipgeolocation.create_indicator`     | `IPGEOLOCATION_CREATE_INDICATOR`       | `true`                          | No        | Create an indicator when the risk score reaches the threshold.                                    |
| Indicator threshold  | `ipgeolocation.indicator_threshold`  | `IPGEOLOCATION_INDICATOR_THRESHOLD`    | `50`                            | No        | Risk score (0-100) from which an indicator is created.                                            |
| Create note          | `ipgeolocation.create_note`          | `IPGEOLOCATION_CREATE_NOTE`            | `true`                          | No        | Attach a note with the full enrichment report.                                                    |

## Deployment

### Docker Deployment

Build the image:

```shell
docker build . -t opencti/connector-ipgeolocation:latest
```

Set the environment variables in `docker-compose.yml`, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Create `config.yml` from `config.yml.sample`, then install the dependencies and start the connector:

```shell
cd src
pip3 install -r requirements.txt
python3 main.py
```

## Usage

In OpenCTI, open an IPv4 or IPv6 observable, click the enrichment button and choose IPGeolocation.io. With `CONNECTOR_AUTO=true`, new observables are enriched as they are created. The connector also works as a playbook step.

## Behavior

### Objects created

| IPGeolocation.io data             | OpenCTI                                                                    |
|-----------------------------------|----------------------------------------------------------------------------|
| Country, city                     | Country and City locations; observable `located-at` both, city `located-at` country |
| Autonomous system                 | Autonomous System; observable `belongs-to` it                              |
| ASN organization or company       | Organization; autonomous system `related-to` it                            |
| Cloud provider                    | Organization; observable `related-to` it                                   |
| Hostname                          | Hostname; hostname `resolves-to` the observable                            |
| Threat score and security flags   | Observable score and labels; an Indicator `based-on` the observable from the threshold |
| Everything, including abuse contact | Note attached to the observable                                          |

All new objects carry the IPGeolocation.io author and the configured TLP marking, and use the deterministic IDs of the connectors SDK, so enriching the same observable again updates the same entities. The observable keeps its own markings and author.

### Risk score

The score set on the observable starts from the IPGeolocation.io threat score (0-100) and adds a weight for each security flag: Tor exit +15, known attacker +15, spam +10, bot +10, residential proxy +8, VPN +5, proxy +5, relay +3, anonymous +3 (when no other anonymity flag is set), cloud provider +2. The result is capped at 100 and mapped to a risk level used in the `risk:` label: low (0-20), medium (21-50), high (51-80), critical (81-100).

Without the security module (free plan, or `include_security=false`), the connector sets no score, no risk label and no indicator, and the note says the threat intelligence was not part of the lookup.

### Credits

A lookup costs 1 credit, plus 2 with the security module and 1 with the abuse module. When the plan does not include those modules, the connector falls back to the base lookup by itself.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for detailed logs. API errors (invalid key, used-up quota, private address) are reported in the connector's work in OpenCTI with the message returned by IPGeolocation.io; the API key never appears in logs or messages.

## Additional information

- Observables with a TLP above `max_tlp_level` are never sent to IPGeolocation.io.
- Private and reserved addresses (such as `10.0.0.1`) are skipped without calling the API.
- Support: support@ipgeolocation.io
