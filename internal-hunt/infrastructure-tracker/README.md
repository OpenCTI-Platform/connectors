# OpenCTI Infrastructure Tracker Connector

The infrastructure tracker executes the infrastructure hunts of OpenCTI on internet scanning data: it searches the
fingerprints of adversary infrastructure (JARM, JA4X, certificates, HTTP banners, ASN...) on
[Censys](https://censys.com/), [Silent Push](https://www.silentpush.com/), [urlscan.io](https://urlscan.io/) and
[Team Cymru Scout](https://www.team-cymru.com/scout), enriches what it finds with
[Shodan InternetDB](https://internetdb.shodan.io/), and creates the infrastructure in OpenCTI. It is a connector of
type `INTERNAL_HUNT` registered for the `internet` hunt platform.

Table of Contents

- [OpenCTI Infrastructure Tracker Connector](#opencti-infrastructure-tracker-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Source accounts](#source-accounts)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Query language](#query-language)
  - [Behavior](#behavior)
  - [Limits](#limits)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

An infrastructure hunt tracks the servers of a threat: its hypothesis is that the threat still operates
infrastructure with known fingerprints (the JARM of its team servers, the default certificate of its framework, the
title of its phishing kit...). For every hunt run dispatched by OpenCTI (one hunt, one time window), the connector:

1. plans the query of every configured source from the fingerprint rule of the hunt;
2. runs the queries within the run timeout and result limit, and merges the hosts the sources find;
3. enriches the public IP addresses found with Shodan InternetDB (host names, open ports, tags);
4. sends to OpenCTI an infrastructure consisting of the public IPv4 addresses, domain names and X.509 certificates
   found, each with a detection indicator, related to the threats the hunt targets;
5. reports the run (hosts found, distinct IP addresses and domains, the queries run, a redacted evidence sample).

## Installation

### Requirements

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261002.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API (`INTERNAL_HUNT`, `register_hunt_platform`,
  `listen_hunt`, `report_hunt_run`) and stops with an explicit message otherwise.
- An account on at least one search source (see below), reachable from the connector over HTTPS.

### Source accounts

Configure the sources you have access to; a source without a key is disabled. Each source answers with the data its
plan includes, and each search counts against the quota of your account.

| Source | Credentials | Searches |
|---|---|---|
| Censys Platform | Personal access token with access to the Global Search API, and the organization ID for organization accounts. | Hosts and web properties (CenQL) on every fingerprint kind. |
| Silent Push | API key with access to the Explore web scan data API. | Web scans (SPQL) on JARM, certificate SHA-256, HTTP title, body hash and `Server` header. |
| urlscan.io | API key with search access. | Scans of the run window on HTTP title, `Server` header, TLS issuer, body hash and ASN. |
| Team Cymru Scout | API key with search queries. | IP addresses of the last 90 days on JARM, JA4X, JA4S and certificate SHA-256. |
| Shodan InternetDB | None (free service, subject to its terms of use). | Enrichment only: host names, open ports and tags of the IP addresses found. |

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Infrastructure Tracker` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `internet` | No | Hunt platform slug, keep `internet`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create; it creates `IPv4-Addr` and `Domain-Name` when listed. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| Censys token | `infrastructure_tracker.censys_token` | `INFRASTRUCTURE_TRACKER_CENSYS_TOKEN` | | One source | Censys Platform personal access token. |
| Censys organization | `infrastructure_tracker.censys_organisation_id` | `INFRASTRUCTURE_TRACKER_CENSYS_ORGANISATION_ID` | | No | Censys organization ID (organization accounts). |
| Censys API URL | `infrastructure_tracker.censys_api_url` | `INFRASTRUCTURE_TRACKER_CENSYS_API_URL` | `https://api.platform.censys.io` | No | URL of the Censys Platform API. |
| Silent Push API key | `infrastructure_tracker.silentpush_api_key` | `INFRASTRUCTURE_TRACKER_SILENTPUSH_API_KEY` | | One source | Silent Push API key. |
| Silent Push API URL | `infrastructure_tracker.silentpush_api_url` | `INFRASTRUCTURE_TRACKER_SILENTPUSH_API_URL` | `https://api.silentpush.com` | No | URL of the Silent Push API. |
| urlscan.io API key | `infrastructure_tracker.urlscan_api_key` | `INFRASTRUCTURE_TRACKER_URLSCAN_API_KEY` | | One source | urlscan.io API key. |
| urlscan.io URL | `infrastructure_tracker.urlscan_api_url` | `INFRASTRUCTURE_TRACKER_URLSCAN_API_URL` | `https://urlscan.io` | No | URL of urlscan.io (or of an on-premise instance). |
| Scout API key | `infrastructure_tracker.cymru_scout_api_key` | `INFRASTRUCTURE_TRACKER_CYMRU_SCOUT_API_KEY` | | One source | Team Cymru Scout API key. |
| Scout API URL | `infrastructure_tracker.cymru_scout_api_url` | `INFRASTRUCTURE_TRACKER_CYMRU_SCOUT_API_URL` | `https://scout.cymru.com/api/scout` | No | URL of the Team Cymru Scout API. |
| InternetDB enrichment | `infrastructure_tracker.internetdb_enabled` | `INFRASTRUCTURE_TRACKER_INTERNETDB_ENABLED` | `true` | No | Enrich the IP addresses found with Shodan InternetDB. |
| InternetDB URL | `infrastructure_tracker.internetdb_url` | `INFRASTRUCTURE_TRACKER_INTERNETDB_URL` | `https://internetdb.shodan.io` | No | URL of Shodan InternetDB. |
| InternetDB lookups | `infrastructure_tracker.internetdb_max_lookups` | `INFRASTRUCTURE_TRACKER_INTERNETDB_MAX_LOOKUPS` | `25` | No | IP addresses enriched per run (0 to 1000; 0 disables the enrichment). |
| Certificates | `infrastructure_tracker.create_certificates` | `INFRASTRUCTURE_TRACKER_CREATE_CERTIFICATES` | `true` | No | Create the X.509 certificates found, with their indicators. |

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-infrastructure-tracker:latest
```

Replace the `ChangeMe` values of `docker-compose.yml` with your configuration, then start the container:

```shell
docker compose up -d
```

### Manual Deployment

Create a file `config.yml` based on `config.yml.sample`, replace the `ChangeMe` values, install the dependencies
(preferably in a virtual environment) and start the connector from the `src` directory:

```shell
pip3 install -r requirements.txt
python3 main.py
```

## Usage

At startup the connector registers the `internet` hunt platform in OpenCTI with the `internet` language. The internet
platform has no Security Platform: what the connector finds is threat infrastructure, not activity in your
environment. Infrastructure hunts then run on it from OpenCTI (manually, on schedule, when the threat landscape
changes or from playbooks), and their runs appear in the hunt detail page. A preview run only plans the hunt: the
queries of every source are shown in OpenCTI and no source is queried.

## Query language

The connector executes native queries written for the `internet` platform in the `internet` language: a YAML (or
JSON) fingerprint rule. Sigma rules describe telemetry and are rejected.

```yaml
fingerprints:
  - kind: jarm
    value: 07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1
  - kind: certificate_subject
    value: CN=Major Cobalt Strike, OU=AdvancedPenTesting, O=cobaltstrike
sources: [censys, cymru_scout]   # optional, default: every configured source
queries:                         # optional, raw queries in the language of a source
  urlscan: 'page.title:"Sign in" AND page.asn:AS20473'
```

| Kind | Censys | Silent Push | urlscan.io | Team Cymru Scout |
|---|---|---|---|---|
| `jarm` | `host.services.jarm.fingerprint` | `jarm` | | value search |
| `ja4x` | `host.services.cert.parsed.ja4x` | | | value search |
| `ja4s` | `host.services.tls.ja4s` | | | value search |
| `certificate_sha256` | `host.services.cert.fingerprint_sha256` | `ssl.SHA256` | | value search |
| `certificate_subject` | `host.services.cert.parsed.subject_dn` | | | |
| `certificate_issuer` | `host.services.cert.parsed.issuer_dn` | | `page.tlsIssuer` | |
| `http_title` | `host.services.endpoints.http.html_title` | `htmltitle` | `page.title` | |
| `http_body_sha256` | `host.services.endpoints.http.body_hash_sha256` | `html_body_sha256` | `hash` | |
| `http_server` | HTTP `Server` header | `header.server` | `page.server` | |
| `banner_sha256` | `host.services.banner_hash_sha256` | | | |
| `asn` (`AS20473` or `20473`) | `host.autonomous_system.asn` | | `page.asn` | |

Every source receives one query matching any of the fingerprints it supports (joined with `or`), plus its raw query
from `queries`; Team Cymru Scout receives one search per fingerprint value. A rule holds at most 50 fingerprints. The
run fails with an explicit reason when the rule is invalid, when none of its `sources` is configured, or when no
configured source supports its fingerprints.

## Behavior

1. The sources are queried one after the other, within the run timeout. Censys and Silent Push search their current
   view of the internet, and only the hosts they last scanned within the run window are kept (a host without a scan
   time is kept); urlscan.io searches the days of the run window, and only the scans within the window are kept; Team
   Cymru Scout searches the most recent 30 days of the run window within its 90 days of history (a window older than
   that is skipped).
2. A failing source is logged and skipped; the run fails only when every query fails. A source timeout fails the run.
3. The queries share the run `max_results`: each query reads at most an equal share of what is left of it, so the run
   never reads more than `max_results` records in total, whatever the number of queries. Hosts are merged by IP
   address (or host name for web properties without one); the run is reported as truncated when a source holds more
   matches than were read, or when the budget is spent before every query ran.
4. Up to `INFRASTRUCTURE_TRACKER_INTERNETDB_MAX_LOOKUPS` public IP addresses are enriched with Shodan InternetDB. The
   enrichment is best effort: an error is logged, and it stops when the run timeout is close.
5. Hosts matching a benign pattern of the hunt are suppressed.
6. With hits, the connector sends:
   - one `infrastructure` named after the hunt and the first eight characters of its OpenCTI id ("Cobalt Strike team
     servers (hunt 3f2a9c1d)"), so two hunts sharing a name never grow the same infrastructure, active between the
     first and last observation of its hosts;
   - the public IPv4 addresses, public domain names and X.509 certificates (SHA-256, subject, issuer) found, the most
     frequent first, each `consists-of` the infrastructure, restricted to `CONNECTOR_OBSERVABLE_TYPES`, to the
     observable types the hunt expects and to `INFRASTRUCTURE_TRACKER_CREATE_CERTIFICATES`;
   - one indicator per observable (STIX pattern, `x_opencti_detection` set, main observable type) `based-on` it;
   - `related-to` relationships from the infrastructure and `indicates` relationships from every indicator to the
     threats the hunt targets;
   - one observed-data per number of hosts, referencing the observables that many hosts hold, stamped with the hunt
     run (`x_opencti_hunt_run_id`).

   Every object inherits the markings and the author of the hunt and has a deterministic identifier. The
   infrastructure, observables, indicators and relationships keep their standard identifiers, so every run of the hunt
   grows the same infrastructure; the identifiers of the observed-data derive from the hunt run too, so each run
   records what it observed and a retry of a run updates its own observed-data.
7. The run is reported with the number of hosts, the distinct IP addresses and domains, the queries run and an evidence
   sample of the fingerprints matched (values hashed and truncated).

## Limits

| Limit | Value |
|---|---|
| Records per run | `limits.max_results` of the run (set by OpenCTI), shared by all the source queries of the run; hosts are capped to the same limit after merging. Censys pages hold 100 hits, Silent Push 1,000 scans, urlscan.io 100 scans; Team Cymru Scout returns at most 5,000 IP addresses. |
| Run timeout | `limits.timeout_seconds` of the run: every call is bounded by the time left. |
| Enrichment | `INFRASTRUCTURE_TRACKER_INTERNETDB_MAX_LOOKUPS` IP addresses per run, 15 seconds per lookup at most. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run; private IP addresses, IPv6 addresses and internal domains are never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception and its completion (hits, suppressed hosts, objects
sent) or failure. Source failures and InternetDB lookup failures are logged as warnings with the source error; failed
runs are reported to OpenCTI with the error of the first failing source.

## Additional information

- Use the preview of a hunt to check the query every source receives before scheduling it.
- Search quotas apply per source account: schedule infrastructure hunts daily or weekly rather than hourly, and keep
  the fingerprints of a hunt specific enough (JARM alone matches many legitimate servers; combine it with a
  certificate or HTTP fingerprint, or restrict the `sources`).
