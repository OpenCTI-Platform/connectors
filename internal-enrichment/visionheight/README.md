# OpenCTI Internal Enrichment VisionHeight Connector

The VisionHeight enrichment connector queries our API to enrich IPv4 and Domain observables in OpenCTI with risk scores, threat labels, infrastructure context (ASN, country, hosted services, vulnerabilities), and DNS/certificate/WHOIS data. HIGH-risk observables (score 100) are automatically promoted to Indicators.

Table of Contents

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
- [Usage](#usage)
- [Behavior](#behavior)
- [Debugging](#debugging)
- [Additional information](#additional-information)

## Introduction

The connector behaves as follows for each enrichment:

- The observable's `score` and `labels` are updated based on the VisionHeight risk verdict and tags.
- Related entities are created and linked: Autonomous System (for IPs), Country, Vulnerabilities (CVEs), resolved IP observables (for domains), X.509 Certificates (for domains), and a context Note (WHOIS, open ports, and blocklist hits for IPs; WHOIS for domains).
- HIGH-risk observables (score 100) are promoted to Indicators with a `based-on` relationship.
- Every enriched object is stamped with a `VisionHeight` Identity (`created_by_ref`) and an `external_reference` pointing back to the VisionHeight UI.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 7.260224.0
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors/tree/master/connectors-sdk) library matching your OpenCTI version
- A VisionHeight API key

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter       | config.yml | Docker environment variable | Default                  | Mandatory | Description                                                                          |
| --------------- | ---------- | --------------------------- | ------------------------ | --------- | ------------------------------------------------------------------------------------ |
| Connector ID    | id         | `CONNECTOR_ID`              | /                        | Yes       | A unique `UUIDv4` identifier for this connector instance.                            |
| Connector Type  | type       | `CONNECTOR_TYPE`            | `INTERNAL_ENRICHMENT`    | Yes       | The connector type. Defaults to `INTERNAL_ENRICHMENT`.                    |
| Connector Name  | name       | `CONNECTOR_NAME`            | `VisionHeight`           | Yes       | Name of the connector as shown in OpenCTI.                                           |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           | `IPv4-Addr,Domain-Name`  | Yes       | The observable types this connector enriches.                        |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | `info`                   | Yes       | Verbosity of logs. Options: `debug`, `info`, `warn`, or `error`.                     |
| Connector Auto  | auto       | `CONNECTOR_AUTO`            | `false`                  | No        | If `true`, every newly created IP/domain in OpenCTI is automatically enriched.       |

### Connector extra parameters environment variables

Below are the VisionHeight-specific parameters:

| Parameter          | config.yml       | Docker environment variable     | Default                          | Mandatory | Description                                                                                                       |
| ------------------ | ---------------- | ------------------------------- | -------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------- |
| API Base URL       | `api_base_url`   | `VISIONHEIGHT_API_BASE_URL`     | `https://api.visionheight.com`   | No        | VisionHeight API base URL. Override for staging or white-label endpoints.                                         |
| API Key            | `api_key`        | `VISIONHEIGHT_API_KEY`          | /                                | Yes       | VisionHeight API key, sent as the `x-api-key` header on every request.                                            |
| Max TLP Level      | `max_tlp_level`  | `VISIONHEIGHT_MAX_TLP_LEVEL`    | `amber+strict`                   | No        | Maximum TLP level the connector will enrich. Observables with a marking above this cause the enrichment to abort with an error logged. One of `clear`, `green`, `amber`, `amber+strict`, `red`. |

## Deployment

### Docker Deployment

Build the Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-visionheight:latest
```

Set the environment variables in `docker-compose.yml` for your environment, then start the connector:

```shell
docker compose up -d
```

### Manual Deployment

Create a `config.yml` based on `config.yml.sample` and replace the `ChangeMe` placeholders with your values.

Install Python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then start the connector from the `src` directory:

```shell
python3 main.py
```

## Usage

Once the connector is registered with the platform, IPv4 and Domain observables can be enriched in three ways:

1. **Manually** - In the OpenCTI UI, navigate to an IP or Domain observable and click the enrichment button. Select `VisionHeight` from the list of available enrichers.
2. **Automatically on creation** - Set `CONNECTOR_AUTO=true` to enrich every newly created IP or Domain observable. Note that this can consume API quota quickly on busy platforms.
3. **Via playbooks** - Add the connector as a step in an OpenCTI playbook. The connector preserves the bundle being passed through and adds enrichment objects to it.

## Behavior

For each enrichment job, the connector calls the VisionHeight API once (`GET /ip/{ip}` or `GET /domain/{domain}`), maps the response to STIX 2.1 objects, and returns a bundle to OpenCTI.

### IPv4 observables

| VisionHeight field                                              | STIX target                                          |
| --------------------------------------------------------------- | ---------------------------------------------------- |
| `risk.latest_risk == HIGH`                                      | `score` on the IPv4-Addr set to 100                  |
| `risk.latest_risk == SUSPICIOUS`                                | `score` on the IPv4-Addr set to 50                   |
| `tags[]` contains `halo` (and risk is not HIGH/SUSPICIOUS)      | `score` on the IPv4-Addr set to 0                    |
| `tags[]` ∪ `risk.details[].tag`                                 | `labels` on the IPv4-Addr (deduplicated)             |
| `ip_attributes` boolean flags                                   | `labels` on the IPv4-Addr (e.g. `tor-exit-node`, `datacenter`, `mobile`, `satellite`, `icloud-private-relay`, `anonymizer`, `commercial-vpn`, `residential-proxy`) |
| `infrastructure.asn` + `infrastructure.isp`                     | New `Autonomous-System` + `belongs-to` relationship  |
| `location.country_code`                                         | New `Location` (Country) + `located-at` relationship |
| `vulnerabilities.cve[]`                                         | New `Vulnerability` per CVE + `related-to` relationship |
| `whois.registrant_name` / `abuse_email`, open ports, blocklist `last_seen` | A context `Note` linked to the IP             |
| HIGH risk (score 100)                                            | New `Indicator` + `based-on` relationship            |

### Domain observables

| VisionHeight field                                                            | STIX target                                              |
| ----------------------------------------------------------------------------- | -------------------------------------------------------- |
| `risk.score == HIGH`                                                          | `score` on the Domain-Name set to 100                    |
| `risk.score == SUSPICIOUS`                                                    | `score` on the Domain-Name set to 50                     |
| `tags[]` contains `halo` (and risk is not HIGH/SUSPICIOUS)                    | `score` on the Domain-Name set to 0                      |
| `tags[]`                                                                      | `labels` on the Domain-Name                              |
| `dns.a_records[].ip`                                                          | New `IPv4-Addr` per record + `resolves-to` relationship  |
| `ssl_certs[]` (sha1, issuer, subject, validity)                               | New `X509-Certificate` per cert + `related-to` relationship |
| `whois[0]` (registrar, created/expires, age, name_servers)                    | A WHOIS context `Note` linked to the domain              |
| HIGH risk (score 100)                                                          | New `Indicator` + `based-on` relationship                |

> **Note:** The IP and Domain endpoints intentionally use different field names: IPs use `risk.latest_risk`, domains use `risk.score`. Both carry the same `UNRATED / SUSPICIOUS / HIGH` values.

Every enrichment also adds:

- A `VisionHeight` `Identity` object (deterministic ID; deduplicates across runs). Every new STIX object created by the connector is stamped with `created_by_ref = VisionHeight`.
- An `external_references` entry on the enriched observable pointing to the VisionHeight UI (`https://app.visionheight.com/ip/{ip}` for IPs, `https://app.visionheight.com/domain/{domain}` for domains).

The connector mutates the original observable in place: the score is replaced with the current VisionHeight risk verdict, while labels and external references are appended to existing values (OpenCTI's bundle merge dedupes repeats). Related STIX objects are added to the bundle.

## Debugging

The connector can be debugged by setting the appropriate log level via `CONNECTOR_LOG_LEVEL` (`debug`, `info`, `warn`, or `error`).

Internally, all log messages use structured logging via `self.helper.connector_logger.{level}(message, context_dict)`. Context fields included on every enrichment include the observable type, value, and (on errors) the API status code and response body.

## Additional information

- The VisionHeight API returns HTTP 400 for invalid input (bogons, malformed IPs/domains). Be aware that, depending on the customer's plan, these requests may count against API quota.
- On non-2xx API responses, the connector logs the error and returns the original bundle unchanged so playbook chains are preserved.
- The `max_tlp_level` setting hard-limits which observables the connector will process; observables with a marking above this level cause the enrichment to abort with an error logged.