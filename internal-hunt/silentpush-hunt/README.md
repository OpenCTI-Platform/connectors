# OpenCTI Silent Push Hunt Connector

The Silent Push hunt connector executes the infrastructure hunts of OpenCTI on
[Silent Push](https://www.silentpush.com/): it searches the fingerprints of adversary infrastructure (JARM,
certificate SHA-256, HTTP title, HTML body hash, `Server` header) in the Silent Push web scan data and creates the
infrastructure it finds in OpenCTI. It is a connector of type `INTERNAL_HUNT` registered for the `silentpush` hunt
platform.

## Before you start

| | |
|---|---|
| Credential | A Silent Push API key whose subscription includes the Explore web scan data API. |
| Console | Silent Push, **Account** > **API key**. |
| Network | `https://api.silentpush.com` reachable from the connector. |

Step by step:

1. Check with Silent Push that the subscription of the account includes the Explore web scan data API.
2. Copy the API key of the account into `SILENTPUSH_HUNT_API_KEY`.

Least-privilege permissions:

| Permission | Why |
|---|---|
| API key with the Explore web scan data API | Search the web scans (SPQL) on JARM, certificate SHA-256, HTTP title, HTML body hash and `Server` header. |

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
SILENTPUSH_HUNT_API_KEY=ChangeMe
```

A hunt run refused by Silent Push names the setting to fix or the missing permission in plain words.

Table of Contents

- [OpenCTI Silent Push Hunt Connector](#opencti-silent-push-hunt-connector)
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
infrastructure with known fingerprints (the JARM of its team servers, the title of its phishing kit...). For every
hunt run dispatched by OpenCTI (one hunt, one time window), the connector:

1. plans the SPQL query of the fingerprint rule of the hunt;
2. runs it within the run timeout and result limit and merges the hosts of the scans found;
3. sends to OpenCTI an infrastructure consisting of the public IPv4 addresses, domain names and X.509 certificates
   found, each with a detection indicator, related to the threats the hunt targets;
4. reports the run (hosts found, the queries run, a redacted evidence sample).

The same fingerprint rule runs on the other infrastructure hunt connectors (Censys Platform, urlscan.io, Team Cymru
Scout, Shodan): each searches the fingerprint kinds its service indexes.

## Installation

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261014.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API and stops with an explicit message
  otherwise.
- A Silent Push account as described in [Before you start](#before-you-start).

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Silent Push Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `silentpush` | No | Hunt platform slug, keep `silentpush`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | `2` | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create; it creates `IPv4-Addr` and `Domain-Name` when listed. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| API key | `silentpush_hunt.api_key` | `SILENTPUSH_HUNT_API_KEY` | | Yes | Silent Push API key. |
| API URL | `silentpush_hunt.api_url` | `SILENTPUSH_HUNT_API_URL` | `https://api.silentpush.com` | No | URL of the Silent Push API. |
| Certificates | `silentpush_hunt.create_certificates` | `SILENTPUSH_HUNT_CREATE_CERTIFICATES` | `true` | No | Create the X.509 certificates found, with their indicators. |

## Deployment

Build the image with the provided `Dockerfile` (`docker build . -t opencti/connector-silentpush-hunt:latest`),
replace the `ChangeMe` values of `docker-compose.yml` and start it with `docker compose up -d`. For a manual
deployment, create a `config.yml` from `config.yml.sample`, install `src/requirements.txt` in a virtual environment
and run `python3 main.py` from the `src` directory.

## Usage

At startup the connector registers the `silentpush` hunt platform in OpenCTI with the `fingerprint` language. The
platform has no Security Platform: what the connector finds is threat infrastructure, not activity in your
environment. Infrastructure hunts then run on it from OpenCTI, and their runs appear in the hunt detail page. A
preview run only plans the hunt: the query is shown in OpenCTI and Silent Push is not queried.

## Query language

The connector executes native queries written for the `silentpush` platform in the `fingerprint` language: a YAML
(or JSON) fingerprint rule. Sigma rules describe telemetry and are rejected.

```yaml
fingerprints:
  - kind: jarm
    value: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
  - kind: http_title
    value: Sign in to your account
queries:                         # optional, raw queries by platform
  silentpush: 'htmltitle = "Office 365" AND header.server = "nginx"'
```

| Kind | SPQL field |
|---|---|
| `jarm` | `jarm` |
| `certificate_sha256` | `ssl.SHA256` |
| `http_title` | `htmltitle` |
| `http_body_sha256` | `html_body_sha256` |
| `http_server` | `header.server` |

The fingerprints are joined with `OR` into one query, and the raw query of `queries.silentpush` runs as a second
query. Other fingerprint kinds are not searched; a rule with none of the kinds above and no raw query for
`silentpush` fails with an explicit reason.

## Behavior

1. The queries run one after the other within the run timeout. Silent Push searches its current scan data: only the
   hosts it last scanned within the run window are kept (a host without a scan time is kept).
2. A failing query is logged and skipped; the run fails only when every query fails. A timeout fails the run.
3. The queries share the run `max_results`: each reads at most an equal share of what is left. Hosts are merged by
   IP address; the run is reported as truncated when Silent Push holds more matches than were read, when the budget
   is spent before every query ran, or when a query failed while another answered.
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
| API calls | Counted against the subscription of the account; Silent Push emails the account when it reaches its daily limit. The limits are not published: ask Silent Push for those of your subscription. | [Silent Push API](https://help.silentpush.com/docs/get-started-with-api) |
| Concurrency and request rate | Not documented by the vendor. | - |

Limits of the connector:

| Limit | Value |
|---|---|
| Records per run | `limits.max_results` of the run, shared by the queries of the run; requests read up to 1,000 scans. |
| Run timeout | `limits.timeout_seconds` of the run: every call is bounded by the time left. |
| Concurrent runs | 2 by default (`CONNECTOR_MAX_CONCURRENT_RUNS`), each sending one request at a time, since the vendor publishes no limit. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run; private IP addresses, IPv6 addresses and internal domains are never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception and its completion (hits, suppressed hosts, objects
sent) or failure. Query failures are logged as warnings with the Silent Push error; failed runs are reported to
OpenCTI with the error of the first failing query.

## Additional information

- Use the preview of a hunt to check the query Silent Push receives before scheduling it.
- Every request counts against the subscription: schedule infrastructure hunts daily or weekly rather than hourly,
  and keep the fingerprints of a hunt specific.
