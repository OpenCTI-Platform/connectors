# OpenCTI Shodan Hunt Connector

The Shodan hunt connector executes the infrastructure hunts of OpenCTI on [Shodan](https://www.shodan.io/): it
searches the fingerprints of adversary infrastructure (JARM, certificates, HTTP title, ASN) in the Shodan banners and
creates the infrastructure it finds in OpenCTI. It is a connector of type `INTERNAL_HUNT` registered for the `shodan`
hunt platform.

## Before you start

| | |
|---|---|
| Credential | A Shodan API key of a plan with query credits. |
| Console | Shodan, **Account** (`https://account.shodan.io/`). |
| Network | `https://api.shodan.io` reachable from the connector. |

Step by step:

1. In your Shodan account, check that the plan has query credits left for the month.
2. Copy the API key of the account into `SHODAN_HUNT_API_KEY`.

Least-privilege permissions:

| Permission | Why |
|---|---|
| API key of a plan with query credits | Search the banners on JARM, certificate fingerprint, subject and issuer, HTTP title and ASN. |

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
SHODAN_HUNT_API_KEY=ChangeMe
```

A hunt run refused by Shodan names the setting to fix or the missing permission in plain words. The API key travels
in the query string of every request, so the connector removes it from the network errors it logs and reports.

Table of Contents

- [OpenCTI Shodan Hunt Connector](#opencti-shodan-hunt-connector)
  - [Before you start](#before-you-start)
  - [Introduction](#introduction)
  - [Installation](#installation)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
  - [Usage](#usage)
  - [Query language](#query-language)
  - [Behavior](#behavior)
  - [Quotas and limits](#quotas-and-limits)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

An infrastructure hunt tracks the servers of a threat: its hypothesis is that the threat still operates
infrastructure with known fingerprints (the JARM of its team servers, the default certificate of its framework, the
title of its phishing kit...). For every hunt run dispatched by OpenCTI (one hunt, one time window), the connector:

1. plans one Shodan search per fingerprint of the rule of the hunt;
2. runs them within the run timeout and result limit and merges the services of every host found;
3. sends to OpenCTI an infrastructure consisting of the public IPv4 addresses, domain names and X.509 certificates
   found, each with a detection indicator, related to the threats the hunt targets;
4. reports the run (hosts found, the queries run, a redacted evidence sample).

The same fingerprint rule runs on the other infrastructure hunt connectors (Censys Platform, Silent Push,
urlscan.io, Team Cymru Scout): each searches the fingerprint kinds its service indexes.

## Installation

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261014.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API and stops with an explicit message
  otherwise.
- A Shodan account as described in [Before you start](#before-you-start).

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Shodan Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `shodan` | No | Hunt platform slug, keep `shodan`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | `1` | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create; it creates `IPv4-Addr` and `Domain-Name` when listed. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| API key | `shodan_hunt.api_key` | `SHODAN_HUNT_API_KEY` | | Yes | Shodan API key of a plan with query credits. |
| API URL | `shodan_hunt.api_url` | `SHODAN_HUNT_API_URL` | `https://api.shodan.io` | No | URL of the Shodan API. |
| Certificates | `shodan_hunt.create_certificates` | `SHODAN_HUNT_CREATE_CERTIFICATES` | `true` | No | Create the X.509 certificates found, with their indicators. |

## Deployment

Build the image with the provided `Dockerfile` (`docker build . -t opencti/connector-shodan-hunt:latest`), replace
the `ChangeMe` values of `docker-compose.yml` and start it with `docker compose up -d`. For a manual deployment,
create a `config.yml` from `config.yml.sample`, install `src/requirements.txt` in a virtual environment and run
`python3 main.py` from the `src` directory.

## Usage

At startup the connector registers the `shodan` hunt platform in OpenCTI with the `fingerprint` language. The
platform has no Security Platform: what the connector finds is threat infrastructure, not activity in your
environment. Infrastructure hunts then run on it from OpenCTI, and their runs appear in the hunt detail page. A
preview run only plans the hunt: the searches are shown in OpenCTI and Shodan is not queried.

## Query language

The connector executes native queries written for the `shodan` platform in the `fingerprint` language: a YAML (or
JSON) fingerprint rule. Sigma rules describe telemetry and are rejected.

```yaml
fingerprints:
  - kind: jarm
    value: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
  - kind: certificate_subject
    value: CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike
queries:                         # optional, raw queries by platform
  shodan: 'ssl.cert.serial:146473198 port:50050'
```

| Kind | Shodan filter |
|---|---|
| `jarm` | `ssl.jarm` |
| `certificate_sha256` | `ssl.cert.fingerprint` |
| `certificate_subject` | `ssl.cert.subject.cn` (the common name of the subject) |
| `certificate_issuer` | `ssl.cert.issuer.cn` (the common name of the issuer) |
| `http_title` | `http.title` |
| `asn` (`AS20473` or `20473`) | `asn` |

Every fingerprint is one search, and the raw query of `queries.shodan` is one more. Other fingerprint kinds (Shodan
hashes HTML bodies with MurmurHash3, not SHA-256) are not searched; a rule with none of the kinds above and no raw
query for `shodan` fails with an explicit reason.

## Behavior

1. The searches run one after the other within the run timeout, paced to 1 request per second. Shodan searches the
   latest banner of every service: only the hosts it last scanned within the run window are kept.
2. A failing search is logged and skipped; the run fails only when every search fails. A timeout fails the run.
3. The searches share the run `max_results`: each reads at most an equal share of what is left. The services of a
   host are merged by IP address; the run is reported as truncated when Shodan holds more matches than were read,
   when the budget is spent before every search ran, or when a search failed while another answered.
4. Hosts matching a benign pattern of the hunt are suppressed.
5. With hits, the connector sends one `infrastructure` named after the hunt and its OpenCTI id, with a STIX id
   seeded from the hunt id, so every run grows the same infrastructure; the public IPv4 addresses, domain names and
   certificates found (`consists-of`), each with an indicator (`based-on`); `related-to` and `indicates`
   relationships to the threats the hunt targets; and one observed-data per observable, stamped with the hunt run.
   Every object inherits the markings and the author of the hunt and has a deterministic identifier.
6. The run is reported with the number of hosts, the requests sent (`queries_count`) and an evidence sample of the
   fingerprints matched (values hashed and truncated).

## Quotas and limits

Quotas of the platform, from its vendor documentation:

| Quota | Value | Source |
|---|---|---|
| Query credits | 1 credit per search with a filter, plus 1 per page of 100 banners past the first. | [Shodan credits](https://help.shodan.io/the-basics/credit-types-explained) |
| Monthly credits | 100 (Membership), 10,000 (Freelancer), 200,000 (Small Business), unlimited (Corporate). | [Shodan pricing](https://developer.shodan.io/pricing) |
| Request rate | 1 request per second on every plan. | [Shodan pricing](https://developer.shodan.io/pricing) |
| Filters | `vuln` and `tag` need a higher plan (raw queries only). | [Shodan API](https://developer.shodan.io/api) |

Limits of the connector:

| Limit | Value |
|---|---|
| Records per run | `limits.max_results` of the run, shared by the searches of the run; pages hold 100 banners. |
| Run timeout | `limits.timeout_seconds` of the run: every call is bounded by the time left. |
| Concurrent runs | 1 by default (`CONNECTOR_MAX_CONCURRENT_RUNS`), each sending one request at a time, paced to 1 per second. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run; private IP addresses, IPv6 addresses and internal domains are never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception and its completion (hits, suppressed hosts, objects
sent) or failure. Search failures are logged as warnings with the Shodan error (without the API key); failed runs are
reported to OpenCTI with the error of the first failing search.

## Additional information

- Use the preview of a hunt to check the searches Shodan receives before scheduling it.
- Every fingerprint is one query credit per run: keep the fingerprints of a hunt few and specific, and schedule
  infrastructure hunts daily or weekly rather than hourly.
