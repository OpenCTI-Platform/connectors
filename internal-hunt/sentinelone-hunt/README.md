# OpenCTI SentinelOne Hunt Connector

The SentinelOne hunt connector executes the hunts of OpenCTI on SentinelOne Singularity, through the PowerQuery API of
the Singularity Data Lake. It is a connector of type `INTERNAL_HUNT` registered for the `sentinelone` hunt platform.

## Before you start

| | |
|---|---|
| Credential | The API token of a SentinelOne service user. |
| Console | **Policies and settings > User management > Service users** of the management console (**Settings > Users > Service Users** in earlier consoles). |
| Network | The management console of your tenant (`https://<your-tenant>.sentinelone.net`). |

Step by step:

1. In **Service users**, create `opencti-hunt` with a read-only role that can search events (for example **Viewer**),
   scoped to the accounts or sites to hunt, and an expiration date.
2. Copy the API token (shown once) into `SENTINELONE_HUNT_API_TOKEN` and the URL of the console into
   `SENTINELONE_HUNT_API_URL`.
3. Optionally, restrict the hunts to some accounts with `SENTINELONE_HUNT_ACCOUNT_IDS` (comma-separated); the token
   must reach each of them.

Least-privilege permissions:

| Permission | Why |
|---|---|
| Service user API token | Authenticate the queries, sent as a Bearer token to the console of the tenant. |
| Read-only role on the accounts or sites to hunt (for example Viewer) | Search the events of the Singularity Data Lake with PowerQuery. |

The connector never ingests nor modifies data: it only launches, polls and deletes its own queries. A read-only role
also keeps a native query from writing to the Data Lake (`| savelookup` writes a lookup table). A service user is
preferred to a personal token: it does not depend on a person and its token expires on the date you set.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
SENTINELONE_HUNT_API_URL=https://your-tenant.sentinelone.net
SENTINELONE_HUNT_API_TOKEN=ChangeMe
```

A hunt run refused by the platform names the missing permission in plain words, with what to grant.

Table of Contents

- [OpenCTI SentinelOne Hunt Connector](#opencti-sentinelone-hunt-connector)
  - [Before you start](#before-you-start)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [SentinelOne permissions](#sentinelone-permissions)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Query languages](#query-languages)
  - [Behavior](#behavior)
  - [Quotas and limits](#quotas-and-limits)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

A hunt is a falsifiable hypothesis plus the logic to test it: a canonical Sigma rule and, optionally, a native query
per platform. For every hunt run dispatched by OpenCTI (one hunt, one time window), the connector:

1. takes the native PowerQuery of the hunt for SentinelOne, or translates its Sigma rule into a PowerQuery with
   [pySigma](https://github.com/SigmaHQ/pySigma) and the
   [SentinelOne PowerQuery backend](https://github.com/7RedViolin/pySigma-backend-sentinelone-pq);
2. runs it as a Long Running Query of the Singularity Data Lake over the run time window, within the run timeout and
   result limit;
3. sends the resulting knowledge to OpenCTI: observed-data referencing the IOC observables found in the results, and
   the key of every hit (OpenCTI keeps one sighting of every technique and indicator of the hunt on the SentinelOne
   Singularity Security Platform, updated at each run);
4. reports the run (hit count, distinct hosts/users/peers, translated query, redacted evidence sample).

Raw events never leave SentinelOne: OpenCTI only receives counts and evidence values that are SHA-256 hashed and
truncated.

Indicator hunts look up their values, one query per observable type, in the fields of the SentinelOne EDR telemetry
that hold them:

| Observable type | Fields | Match |
|---|---|---|
| `IPv4-Addr`, `IPv6-Addr` | `dst.ip.address`, `src.ip.address` | Exact, case-insensitive (`in:anycase`) |
| `Domain-Name` | `event.dns.request` | The domain and its subdomains, case-insensitive |
| `Hostname` | `event.dns.request` | Exact, case-insensitive |
| `Url` | `url.address` | Substring, case-insensitive (`contains`) |
| `StixFile` MD5 | `tgt.file.md5` | Exact, case-insensitive |
| `StixFile` SHA-1 | `tgt.file.sha1`, `src.process.image.sha1`, `src.process.parent.image.sha1` | Exact, case-insensitive |
| `StixFile` SHA-256 | `tgt.file.sha256`, `src.process.image.sha256`, `src.process.parent.image.sha256`, `module.sha256` | Exact, case-insensitive |

Other types (email and MAC addresses, other hash algorithms, user accounts...) are reported not searched.

## Installation

### Requirements

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261014.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API (`INTERNAL_HUNT`, `register_hunt_platform`,
  `listen_hunt`, `report_hunt_run`) and stops with an explicit message otherwise.
- SentinelOne Singularity with the Singularity Data Lake (the EDR telemetry the console searches with PowerQuery).

### SentinelOne permissions

The account, the least-privilege permissions, the console steps and a configuration example are in [Before you start](#before-you-start).

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `SentinelOne Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `sentinelone` | No | Hunt platform slug, keep `sentinelone`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Security Platform name | `connector.security_platform_name` | `CONNECTOR_SECURITY_PLATFORM_NAME` | `SentinelOne Singularity` | No | OpenCTI Security Platform the hunts run against (created when missing). Use one name per SentinelOne tenant. |
| Security Platform type | `connector.security_platform_type` | `CONNECTOR_SECURITY_PLATFORM_TYPE` | `EDR` | No | `SIEM`, `EDR`, `XDR`, `SOAR`, `NDR` or `ISPM` (`XDR` when the Data Lake also holds the third-party data you hunt). |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | `3` | No | Connector-side limit of concurrent hunt runs, each holding one query on the platform at a time (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create: `IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Url`, `StixFile`, `Email-Addr`, widened with `Hostname`, `User-Account`, `Mac-Addr`. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| Console URL | `sentinelone_hunt.api_url` | `SENTINELONE_HUNT_API_URL` | | Yes | URL of the management console of your tenant, e.g. `https://your-tenant.sentinelone.net`. |
| API token | `sentinelone_hunt.api_token` | `SENTINELONE_HUNT_API_TOKEN` | | Yes | API token of the service user. |
| Account IDs | `sentinelone_hunt.account_ids` | `SENTINELONE_HUNT_ACCOUNT_IDS` | | No | Accounts searched, comma-separated. Empty searches every account the token can reach. |
| EDR telemetry only | `sentinelone_hunt.edr_only` | `SENTINELONE_HUNT_EDR_ONLY` | `true` | No | Restrict translated rules and indicator lookups to the SentinelOne EDR telemetry and check their field names against the EDR schema. Set to `false` to also search the third-party data of the Data Lake. |
| Verify TLS | `sentinelone_hunt.verify_ssl` | `SENTINELONE_HUNT_VERIFY_SSL` | `true` | No | Verify the TLS certificate of the console. |
| Sigma pipeline | `sentinelone_hunt.sigma_pipeline` | `SENTINELONE_HUNT_SIGMA_PIPELINE` | `sentinelone_pq` | No | pySigma pipeline: `sentinelone_pq` (field mapping of the SentinelOne EDR telemetry) or `none` (rules already written with SentinelOne field names). |
| Poll interval | `sentinelone_hunt.poll_interval` | `SENTINELONE_HUNT_POLL_INTERVAL` | `1` | No | Seconds between two query status checks, at most 10. |

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-sentinelone-hunt:latest
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

At startup the connector registers the `sentinelone` hunt platform in OpenCTI with the `powerquery` language and the
Security Platform identity named by `CONNECTOR_SECURITY_PLATFORM_NAME`. Hunts then run on it from OpenCTI (manually,
on schedule, when the threat landscape changes or from playbooks), and their runs appear in the hunt detail page. A
preview run only translates the hunt logic: the translated query is shown in OpenCTI and SentinelOne is never queried.

## Query languages

The connector executes `powerquery` (SentinelOne PowerQuery, the query language of the Singularity Data Lake).

- **Sigma rules** are translated with the `sentinelone_pq` pipeline of the backend, which maps the Sigma fields to the
  SentinelOne EDR fields and adds the event type and operating system of the rule log source
  (`event.type in:anycase ("Process Creation")`, `endpoint.os in:anycase ("windows")`). The connector writes the
  conditions in the forms the PowerQuery reference documents: negations as `!(...)` (a `not` without parentheses
  silently matches nothing), `starts_with` and `ends_with` for prefixes and suffixes, `in:anycase` for whole values
  (`=` and `in` compare with case), and a `matches` regular expression for wildcards in the middle of a value. A CIDR
  range becomes the address prefixes it covers (`172.16.0.0/12` gives sixteen `starts_with` conditions). A hunt may
  select another pipeline through a native query entry with an empty query and a `pipeline`. Sigma documents with
  several rules are joined with `or`.
- With `SENTINELONE_HUNT_EDR_ONLY=true` (the default), translated rules and indicator lookups start with the EDR
  filter `dataSource.name='SentinelOne' and dataSource.category='security'`, and SentinelOne checks their field names
  against the EDR schema: a field the schema does not know fails the run with its name instead of matching nothing.
  Write a native query for a rule whose fields the pipeline does not map.
- **Native queries** written for the `sentinelone` platform (language `powerquery`) are executed verbatim: filters,
  commands and aggregations (`event.type = 'DNS Resolved' | group count() by event.dns.request`) are supported. End
  them with `| columns ...` to choose the fields read: PowerQuery returns the columns it is asked for, and the hosts,
  users and IOC observables of the run come from them. A native query starting with the EDR filter has its field
  names checked too.

## Behavior

1. The query runs over the run window (`startTime` / `endTime`, no time condition is added to the query text) and is
   capped with `| limit <max_results>` (PowerQuery returns 1,000 rows without `limit`). When the cap is reached, the
   total hit count is read with a second query, `| group count()`.
2. Queries are launched as Long Running Queries, polled every `SENTINELONE_HUNT_POLL_INTERVAL` seconds until all their
   steps are done, then deleted; they are also deleted when the run times out. A launch throttled by SentinelOne
   (HTTP 429) is retried with backoff within the run timeout.
3. Events matching a benign pattern of the hunt are suppressed.
4. With hits, the connector sends one observed-data per public IP address, domain,
   URL, file hash or email address found, with the number of result events holding it, restricted to the observable types the
   hunt expects. Objects inherit the markings and author of the hunt and have deterministic identifiers; those of the
   observed-data derive from the hunt run too, so a retry of a run updates its own objects and two runs
   never share one. The run reports the key of every hit it read: OpenCTI counts the hits it never saw for the hunt and the platform
   as new, and keeps one sighting per technique and indicator of the hunt on the Security Platform, updated in
   place at each run (`count` = distinct hits, `first_seen` / `last_seen` = first and latest hit).
5. The run is reported with the hit count, the distinct hosts (`endpoint.name`), users (`src.process.user`,
   `tgt.process.user`) and network peers, the query executed and an evidence sample. The raw text (`message`), event
   and agent identifiers (`event.id`, `agent.uuid`) are never sampled; host names, user names and command lines only
   appear hashed and truncated in the evidence. Each hit is
   keyed by the id SentinelOne gives its event (`event.id`), so a hit found again by a later run adds nothing to the
   sighting count. The event time is read from `timestamp` (nanoseconds since the epoch).

No incident is created by the connector: OpenCTI drafts incidents itself when the hits exceed the escalation threshold
of the hunt.

## Quotas and limits

Quotas of the platform, from its vendor documentation:

| Quota | Value | Source |
|---|---|---|
| Query lifetime | A Long Running Query expires 30 seconds after its launch or its last poll. | [Long Running Query API](https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/mgmt-console-api/references/lrq-api.md) |
| Query launches | A launch may be refused with HTTP 429 (the vendor measured no 429 on status or cancellation calls); no launch rate is documented by the vendor. | [Long Running Query API](https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/mgmt-console-api/references/lrq-api.md) |
| Request rate | 60 requests in a burst, then 30 requests per second, per client IP address (Singularity Data Lake limit published for 2026-09-10). | [Long Running Query API](https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/mgmt-console-api/references/lrq-api.md) |
| Concurrent queries | The concurrent query budget of an account is not documented by the vendor. | - |
| Rows per query | 1,000 rows without `limit` or `group` (the **Show All** button of the console adds `limit 100000`). | [PowerQuery commands](https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/powerquery/references/commands-reference.md) |
| Regular expressions | 1,000 bytes per `matches` expression. | [PowerQuery syntax](https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/powerquery/references/syntax-and-operators.md) |
| Retired endpoints | `/api/powerQuery` and `/web/api/v2.1/dv/events/pq` are retired on 2027-02-15; the connector uses the Long Running Query API. | [Long Running Query API](https://github.com/Sentinel-One/ai-siem/blob/main/plugins/s1-secops-skills/skills/mgmt-console-api/references/lrq-api.md) |

Limits of the connector:

| Limit | Value |
|---|---|
| Results read per run | `limits.max_results` of the run (set by OpenCTI), at most 10,000 rows; the total hit count is kept. |
| Run timeout | `limits.timeout_seconds` of the run: launches, retries and polling are bounded by the time left, and the query is deleted when the run times out. |
| Concurrent runs | 3 by default (`CONNECTOR_MAX_CONCURRENT_RUNS`), each holding one query at a time, since the account budget is not documented. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run, IOC types by default, private IP addresses and internal domains never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception and its completion (hits, suppressed events, objects
sent) or failure. Failed runs are reported to OpenCTI with the SentinelOne error message (for example the syntax error
of an invalid query, the `Unknown EDR field` of a misspelled field or the `401` of an expired token).

## Additional information

- The retention of the Singularity Data Lake defines what a hunt can see.
- One connector instance executes against one SentinelOne tenant. Deploy one instance (with its own Security Platform
  name) per tenant to hunt.
