# OpenCTI Censys Platform Hunt Connector

The Censys Platform hunt connector executes the infrastructure hunts of OpenCTI on
[Censys Platform](https://censys.com/): it searches the fingerprints of adversary infrastructure (JARM, JA4X,
certificates, HTTP banners, ASN...) with the Censys global search and creates the infrastructure it finds in OpenCTI.
It is a connector of type `INTERNAL_HUNT` registered for the `censys` hunt platform.

## Before you start

| | |
|---|---|
| Credential | A Censys Platform personal access token of a user with the API Access role, and the organization ID of a paid organization. |
| Console | Censys Platform, **Account** > **Personal Access Tokens**, and **Organization** > **Settings** for the organization ID. |
| Network | `https://api.platform.censys.io` reachable from the connector. |

Step by step:

1. In the Censys Platform, make sure the user of the connector has the **API Access** role in a paid organization
   (free accounts cannot search through the API).
2. Create a personal access token for that user and set it in `CENSYS_HUNT_TOKEN`.
3. Copy the ID of the organization whose credits the searches use into `CENSYS_HUNT_ORGANIZATION_ID`.

Least-privilege permissions:

| Permission | Why |
|---|---|
| Personal access token of a user with the API Access role | Search the hosts and web properties of the global search (CenQL) on every fingerprint kind. |
| Organization ID (paid plans) | The organization whose credits the searches use. |

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
CENSYS_HUNT_TOKEN=ChangeMe
CENSYS_HUNT_ORGANIZATION_ID=ChangeMe
```

A hunt run refused by Censys names the setting to fix or the missing permission in plain words.

Table of Contents

- [OpenCTI Censys Platform Hunt Connector](#opencti-censys-platform-hunt-connector)
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

1. plans the CenQL query of the fingerprint rule of the hunt;
2. runs it within the run timeout and result limit and merges the hosts and web properties found;
3. sends to OpenCTI an infrastructure consisting of the public IPv4 addresses, domain names and X.509 certificates
   found, each with a detection indicator, related to the threats the hunt targets;
4. reports the run (hosts found, the queries run, a redacted evidence sample).

The same fingerprint rule runs on the other infrastructure hunt connectors (Silent Push, urlscan.io, Team Cymru
Scout, Shodan): each searches the fingerprint kinds its service indexes.

## Installation

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261014.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API and stops with an explicit message
  otherwise.
- A Censys Platform account as described in [Before you start](#before-you-start).

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Censys Platform Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `censys` | No | Hunt platform slug, keep `censys`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | `1` | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create; it creates `IPv4-Addr` and `Domain-Name` when listed. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| Token | `censys_hunt.token` | `CENSYS_HUNT_TOKEN` | | Yes | Personal access token of a user with the API Access role. |
| Organization | `censys_hunt.organization_id` | `CENSYS_HUNT_ORGANIZATION_ID` | | No | ID of the organization whose credits the searches use (required by the paid plans). |
| API URL | `censys_hunt.api_url` | `CENSYS_HUNT_API_URL` | `https://api.platform.censys.io` | No | URL of the Censys Platform API. |
| Certificates | `censys_hunt.create_certificates` | `CENSYS_HUNT_CREATE_CERTIFICATES` | `true` | No | Create the X.509 certificates found, with their indicators. |

## Deployment

Build the image with the provided `Dockerfile` (`docker build . -t opencti/connector-censys-hunt:latest`), replace
the `ChangeMe` values of `docker-compose.yml` and start it with `docker compose up -d`. For a manual deployment,
create a `config.yml` from `config.yml.sample`, install `src/requirements.txt` in a virtual environment and run
`python3 main.py` from the `src` directory.

## Usage

At startup the connector registers the `censys` hunt platform in OpenCTI with the `fingerprint` language. The
platform has no Security Platform: what the connector finds is threat infrastructure, not activity in your
environment. Infrastructure hunts then run on it from OpenCTI (manually, on schedule, when the threat landscape
changes or from playbooks), and their runs appear in the hunt detail page. A preview run only plans the hunt: the
query is shown in OpenCTI and Censys is not queried.

## Query language

The connector executes native queries written for the `censys` platform in the `fingerprint` language: a YAML (or
JSON) fingerprint rule. Sigma rules describe telemetry and are rejected.

```yaml
fingerprints:
  - kind: jarm
    value: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
  - kind: certificate_subject
    value: CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike
queries:                         # optional, raw queries by platform
  censys: 'host.services.endpoints.http.html_title = "Cobalt Strike"'
```

| Kind | CenQL field |
|---|---|
| `jarm` | `host.services.jarm.fingerprint` |
| `ja4x` | `host.services.cert.parsed.ja4x` |
| `ja4s` | `host.services.tls.ja4s` |
| `certificate_sha256` | `host.services.cert.fingerprint_sha256` |
| `certificate_subject` | `host.services.cert.parsed.subject_dn` |
| `certificate_issuer` | `host.services.cert.parsed.issuer_dn` |
| `http_title` | `host.services.endpoints.http.html_title` |
| `http_body_sha256` | `host.services.endpoints.http.body_hash_sha256` |
| `http_server` | `host.services.endpoints.http.headers` (`Server` key) |
| `banner_sha256` | `host.services.banner_hash_sha256` |
| `asn` (`AS20473` or `20473`) | `host.autonomous_system.asn` |

The fingerprints are joined with `or` into one query, and the raw query of `queries.censys` runs as a second query.
A rule holds at most 50 fingerprints. The run fails with an explicit reason when the rule is invalid.

## Behavior

1. The queries run one after the other within the run timeout. Censys searches its current view of the internet:
   only the hosts it last scanned within the run window are kept (a host without a scan time is kept).
2. A failing query is logged and skipped; the run fails only when every query fails. A timeout fails the run.
3. The queries share the run `max_results`: each reads at most an equal share of what is left. Hosts are merged by
   IP address (or host name for web properties without one); the run is reported as truncated when Censys holds
   more matches than were read, when the budget is spent before every query ran, or when a query failed while
   another answered (OpenCTI then never concludes benign from zero hits).
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
| Credits | 1 credit per search, plus 1 per extra page of 100 hits. | [Censys credits](https://docs.censys.com/docs/platform-credits-enterprise) |
| Concurrent requests | 1 per organization on the Free and Starter plans, 25 on the Search and Core plans (HTTP 429 beyond). | [Censys API](https://docs.censys.com/reference/get-started) |
| Request rate | 25 requests per second per IP address (HTTP 503 beyond). | [Censys API](https://docs.censys.com/reference/get-started) |
| History | 7 days on the Starter plan. | [Censys API](https://docs.censys.com/reference/get-started) |

Limits of the connector:

| Limit | Value |
|---|---|
| Records per run | `limits.max_results` of the run, shared by the queries of the run; pages hold 100 hits. |
| Run timeout | `limits.timeout_seconds` of the run: every call is bounded by the time left. |
| Concurrent runs | 1 by default (`CONNECTOR_MAX_CONCURRENT_RUNS`), each sending one request at a time; raise it only on a plan with concurrent requests to spare. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run; private IP addresses, IPv6 addresses and internal domains are never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception and its completion (hits, suppressed hosts, objects
sent) or failure. Query failures are logged as warnings with the Censys error; failed runs are reported to OpenCTI
with the error of the first failing query.

## Additional information

- Use the preview of a hunt to check the query Censys receives before scheduling it.
- Every search uses credits of the organization: schedule infrastructure hunts daily or weekly rather than hourly,
  and keep the fingerprints of a hunt specific (JARM alone matches many legitimate servers; combine it with a
  certificate or HTTP fingerprint).
