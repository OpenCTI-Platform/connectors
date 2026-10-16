# OpenCTI Team Cymru Scout Hunt Connector

The Team Cymru Scout hunt connector executes the infrastructure hunts of OpenCTI on
[Team Cymru Scout](https://www.team-cymru.com/pure-signal-scout): it searches the fingerprints of adversary
infrastructure (JARM, JA4X, X.509 certificates) in the IP addresses Scout observed on the days of the run window and
creates the infrastructure it finds in OpenCTI. It is a connector of type `INTERNAL_HUNT` registered for the
`cymru-scout` hunt platform.

## Before you start

| | |
|---|---|
| Credential | A Team Cymru Scout API key with search queries left in its balance. |
| Console | Scout, **API Keys**. |
| Network | `https://scout.cymru.com` reachable from the connector. |

Step by step:

1. In Scout, create an API key and check its monthly query balance.
2. Set the key in `CYMRU_SCOUT_HUNT_API_KEY`.

Least-privilege permissions:

| Permission | Why |
|---|---|
| API key with search queries | Search the IP addresses of the last 90 days on JARM, JA4X and X.509 certificates. |

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
CYMRU_SCOUT_HUNT_API_KEY=ChangeMe
```

A hunt run refused by Scout names the setting to fix or the missing permission in plain words.

Table of Contents

- [OpenCTI Team Cymru Scout Hunt Connector](#opencti-team-cymru-scout-hunt-connector)
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
infrastructure with known fingerprints (the JARM of its team servers, the default certificate of its framework...).
For every hunt run dispatched by OpenCTI (one hunt, one time window), the connector:

1. plans one Scout search per fingerprint of the rule of the hunt;
2. runs them over the days of the run window within the run timeout and result limit, and merges the IP addresses
   found;
3. sends to OpenCTI an infrastructure consisting of the public IPv4 addresses and the domain names (passive DNS)
   found, each with a detection indicator, related to the threats the hunt targets;
4. reports the run (hosts found, the queries run, a redacted evidence sample).

The same fingerprint rule runs on the other infrastructure hunt connectors (Censys Platform, Silent Push,
urlscan.io, Shodan): each searches the fingerprint kinds its service indexes.

## Installation

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261014.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API and stops with an explicit message
  otherwise.
- A Team Cymru Scout account as described in [Before you start](#before-you-start).

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Team Cymru Scout Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `cymru-scout` | No | Hunt platform slug, keep `cymru-scout`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | `1` | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create; it creates `IPv4-Addr` and `Domain-Name` when listed. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| API key | `cymru_scout_hunt.api_key` | `CYMRU_SCOUT_HUNT_API_KEY` | | Yes | Team Cymru Scout API key. |
| API URL | `cymru_scout_hunt.api_url` | `CYMRU_SCOUT_HUNT_API_URL` | `https://scout.cymru.com/api/scout` | No | URL of the Team Cymru Scout API. |

## Deployment

Build the image with the provided `Dockerfile` (`docker build . -t opencti/connector-cymru-scout-hunt:latest`),
replace the `ChangeMe` values of `docker-compose.yml` and start it with `docker compose up -d`. For a manual
deployment, create a `config.yml` from `config.yml.sample`, install `src/requirements.txt` in a virtual environment
and run `python3 main.py` from the `src` directory.

## Usage

At startup the connector registers the `cymru-scout` hunt platform in OpenCTI with the `fingerprint` language. The
platform has no Security Platform: what the connector finds is threat infrastructure, not activity in your
environment. Infrastructure hunts then run on it from OpenCTI, and their runs appear in the hunt detail page. A
preview run only plans the hunt: the searches are shown in OpenCTI and Scout is not queried.

## Query language

The connector executes native queries written for the `cymru-scout` platform in the `fingerprint` language: a YAML
(or JSON) fingerprint rule. Sigma rules describe telemetry and are rejected.

```yaml
fingerprints:
  - kind: jarm
    value: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
  - kind: certificate_subject
    value: CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike
queries:                         # optional, raw queries by platform
  cymru-scout: 'x509.subject.cn = "Major Cobalt Strike"'
```

| Kind | Scout selector |
|---|---|
| `jarm` | `fingerprints.hash` |
| `ja4x` | `fingerprints.hash` |
| `certificate_sha256` | `x509.sha256` |
| `certificate_subject` | `x509.subject` (commas escaped) |
| `certificate_issuer` | `x509.issuer` (commas escaped) |

Every fingerprint is one search, and the raw query of `queries.cymru-scout` is one more. Other fingerprint kinds are
not searched; a rule with none of the kinds above and no raw query for `cymru-scout` fails with an explicit reason.

## Behavior

1. The searches run one after the other within the run timeout, paced to 1 request per second. Scout dates what it
   observed by the day only: every search covers the days of the run window, within the 90 days of Scout history
   and 30 days at most (the most recent ones). A window older than the history is skipped and the run is reported
   as truncated; every IP address found on the days of the window is kept, including for a window shorter than a day.
2. A failing search is logged and skipped; the run fails only when every search fails. A timeout fails the run.
3. The searches share the run `max_results`: each reads at most an equal share of what is left. IP addresses are
   merged; the run is reported as truncated when Scout holds more matches than were read, when the window was
   clipped, when the budget is spent before every search ran, or when a search failed while another answered.
4. Hosts matching a benign pattern of the hunt are suppressed.
5. With hits, the connector sends one `infrastructure` named after the hunt and its OpenCTI id, with a STIX id
   seeded from the hunt id, so every run grows the same infrastructure; the public IPv4 addresses and domain names
   found (`consists-of`), each with an indicator (`based-on`); `related-to` and `indicates` relationships to the
   threats the hunt targets; and one observed-data per observable, stamped with the hunt run. Every object inherits
   the markings and the author of the hunt and has a deterministic identifier.
6. The run is reported with the number of hosts, the requests sent (`queries_count`) and an evidence sample of the
   fingerprints matched (values hashed and truncated).

## Quotas and limits

Quotas of the platform, from its vendor documentation:

| Quota | Value | Source |
|---|---|---|
| Queries | Every search uses one query of the monthly balance of the account (`usage.query_limit` in the answers). | [Scout API](https://scout.cymru.com/docs/scout/ultimate) |
| Rate | HTTP 429 beyond 1 request per second, beyond the concurrent request limit, or once the balance is spent. | [Scout API](https://scout.cymru.com/docs/scout/ultimate) |
| History | 90 days; a search returns at most 5,000 IP addresses. | [Scout API](https://scout.cymru.com/docs/scout/ultimate) |

Limits of the connector:

| Limit | Value |
|---|---|
| Records per run | `limits.max_results` of the run, shared by the searches of the run; a search returns at most 5,000 IP addresses. |
| Run timeout | `limits.timeout_seconds` of the run: every call is bounded by the time left. |
| Concurrent runs | 1 by default (`CONNECTOR_MAX_CONCURRENT_RUNS`), each sending one request at a time, paced to 1 per second. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run; private IP addresses, IPv6 addresses and internal domains are never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception and its completion (hits, suppressed hosts, objects
sent) or failure. Search failures are logged as warnings with the Scout error, and a skipped window is logged; failed
runs are reported to OpenCTI with the error of the first failing search.

## Additional information

- Use the preview of a hunt to check the searches Scout receives before scheduling it.
- Every fingerprint is one query of the monthly balance: keep the fingerprints of a hunt few and specific, and
  schedule infrastructure hunts daily or weekly rather than hourly.
