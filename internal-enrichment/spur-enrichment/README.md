# OpenCTI Spur Enrichment Connector

Table of Contents

- [OpenCTI Spur Enrichment Connector](#opencti-spur-enrichment-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

[Spur](https://spur.us) specializes in IP intelligence: it tells whether an IP address belongs to a VPN, a
proxy, a Tor node or another anonymization service, and describes the clients behind it.

This connector enriches `IPv4-Addr` and `IPv6-Addr` observables on demand with the
[Spur Context API](https://docs.spur.us/context-api/endpoints). It complements the
[Spur external-import connector](../../external-import/spur), which imports the full daily Spur Feeds and
requires a Feeds subscription.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- A Spur API token with access to the Context API

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

```shell
docker build . -t opencti/connector-spur-enrichment:latest
```

Set the environment variables in `docker-compose.yml` (at least `OPENCTI_URL`, `OPENCTI_TOKEN` and `SPUR_API_KEY`),
then start the container:

```shell
docker compose up -d
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample` and replace the `ChangeMe` values.

Install the required Python dependencies (preferably in a virtual environment):

```shell
pip3 install -r src/requirements.txt
```

Then, start the connector from the `src` directory:

```shell
python3 main.py
```

## Usage

Open an IPv4 or IPv6 observable in OpenCTI and click on the enrichment button, then select this connector.
The connector can also be used in playbooks.

Each enrichment consumes one query of the Spur Context API quota, so `CONNECTOR_AUTO` defaults to `false`.
With `SPUR_FETCH_TAG_METADATA=true`, each distinct service seen on the IP costs one more query, cached for 24 hours
(see [Service metadata](#service-metadata)).

## Behavior

The connector makes a single call to `GET /v2/context/{ip}` per enrichment and creates the following objects:

| Spur field | OpenCTI |
| ---------- | ------- |
| `tunnels[].type`, `tunnels[].anonymous` | Labels on the IP: `spur-tunnel-type:vpn`, `spur-tunnel-anonymous:true` |
| `risks` | Labels on the IP: `spur-risk:geo_mismatch`... |
| `services` | Labels on the IP: `spur-service:openvpn`... |
| `infrastructure` | Label on the IP: `spur-infrastructure:datacenter` |
| `client.behaviors` | Labels on the IP: `spur-behavior:tor_proxy_user`... |
| `client.types` | Labels on the IP: `spur-client-type:mobile`... |
| `ai.types` | Labels on the IP: `spur-ai-type:crawler`... |
| `risks` | Score on the IP when it has offensive risks (`AD_FRAUD`, `CALLBACK_PROXY`, `LOGIN_BRUTEFORCE`, `WEB_SCRAPING`): `SPUR_DEFAULT_SCORE + 5 x number of offensive risks`, capped at 100. Other IPs keep their current score, so a consumer VPN exit is not flagged as malicious. |
| `ip` | External reference to the Spur page of the IP (`https://spur.us/context/{ip}`) |
| `tunnels[].operator` | Anonymization `Infrastructure` that `consists-of` the IP. Labelled `spur-infra:anonymous` when the tunnel is anonymous, with the IP `services` in its description. |
| `tunnels[].entries`, `tunnels[].exits` | IP observables that the tunnel `Infrastructure` `consists-of`, the relationship description giving the role (`Entry node`, `Exit node`). At most 50 nodes per tunnel, no score and no label. |
| `client.proxies` | Anonymization `Infrastructure` `related-to` the IP: the clients behind the IP use this proxy, but the IP is not necessarily part of it |
| `ai.operator` | `Infrastructure` that `consists-of` the IP |
| `as.number`, `as.organization` | `Autonomous-System`, the IP `belongs-to` it |
| `location.city`, `location.state`, `location.country` | `City`, `Administrative-Area` and `Country`: the IP is `located-at` the most precise one, and each location is `located-at` the next less precise one. Anycast IPs (`Anycast` city and state, `ZZ` country) get no location. |
| `organization`, `client.count`, `client.countries`, `client.spread`, `client.concentration` | `Note` attached to the IP |

Infrastructures are named after the Spur service tag (e.g. `PROTON_VPN`), so the same service always gives the same
infrastructure. Service tags are not labels: they are an open catalog of thousands of values.

### Service metadata

With `SPUR_FETCH_TAG_METADATA=true`, the connector also calls `GET /v2/metadata/tags/{tag}` for each service seen on
the IP (tunnel operators, client proxies, AI operator) and describes their infrastructures with it:

| Tag metadata field | OpenCTI |
| ------------------ | ------- |
| `aliasOf` | The infrastructure is named after the canonical tag, the tag seen on the IP becomes an alias |
| `name`, `aliases`, `allTags` | `Infrastructure` aliases (e.g. `Proton VPN`) |
| `categories` | Labels on the infrastructure: `spur-category:commercial_vpn`... |
| `isAnonymous`, `isNoLog` | Labels on the infrastructure: `spur-infra:anonymous`, `spur-infra:no-log` |
| `description` and the other properties (`protocols`, `platforms`, `targetingTypes`, `isCallbackProxy`, `isEnterprise`, `isInactive`, `maxAgeDays`, `resoldBy`, `resells`...) | `Infrastructure` description |
| `website` | External reference on the infrastructure |
| `metrics` | `Note` attached to the infrastructure (distinct IPs, ASNs, countries, churn rate...) |

Responses are cached for 24 hours, including unknown tags (HTTP 404, which still costs a query). A service whose
metadata cannot be fetched keeps the infrastructure built from the IP context only, and the enrichment goes on.

The new objects are created by the `Spur` organization and marked with `SPUR_TLP_LEVEL`. The author and the markings
of the enriched IP are left unchanged.

The connector skips (without calling Spur):

- an entity whose TLP is above `CONNECTOR_MAX_TLP`,
- a network (CIDR value with more than one address): Spur only accepts a single IP.

When Spur rejects the IP (HTTP 400, e.g. a private or reserved address), nothing is created.

## Debugging

The connector can be debugged by setting the appropriate log level (`CONNECTOR_LOG_LEVEL=debug`).

## Additional information

- The Spur labels and the score can also be set by the Spur external-import connector, which uses unprefixed labels.
- Without service metadata, the infrastructure description lists the services of the last enriched IP of this
  service: it is replaced at each enrichment.
- Labels are only added, never removed: an IP keeps its Spur labels after Spur stops reporting them.
- The service metrics change often: each new set of metrics gives a new note on the infrastructure, and the older ones
  remain.
