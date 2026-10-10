# OpenCTI Elastic Security Hunt Connector

The Elastic Security hunt connector executes the hunts of OpenCTI on the Elasticsearch cluster of Elastic Security. It
is a connector of type `INTERNAL_HUNT` registered for the `elastic-security` hunt platform.

## Before you start

| | |
|---|---|
| Credential | An Elasticsearch API key (or a user name and password) holding a dedicated role. |
| Console | Kibana: **Stack Management > Security > Roles** and **Stack Management > Security > API keys** (or `POST /_security/api_key`). |
| Network | The Elasticsearch HTTP API (port `9200` by default, or the Elastic Cloud endpoint) reachable from the connector. |

Step by step:

1. In **Stack Management > Roles > Create role**, create `opencti_hunt`: no cluster privilege; index privileges `read` and `view_index_metadata` on the indices of `ELASTIC_SECURITY_HUNT_INDICES`; for cross-cluster search, `read` as a remote index privilege.
2. In **Stack Management > API keys > Create API key**, restrict the key to the privileges of `opencti_hunt` (or call `POST /_security/api_key` with `role_descriptors` holding them).
3. Copy the `encoded` value of the key into `ELASTIC_SECURITY_HUNT_API_KEY`.

Least-privilege permissions:

| Permission | Why |
|---|---|
| Index privilege `read` on `ELASTIC_SECURITY_HUNT_INDICES` | Run ES\|QL, EQL and Lucene searches on the hunted data. |
| Index privilege `view_index_metadata` on the same indices | Resolve index patterns and field mappings. |
| Remote index privilege `read` (cross-cluster search only) | Hunt `remote:index` patterns. |

No cluster privilege is needed: the connector only deletes its own async searches, and never writes to the cluster.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
ELASTIC_SECURITY_HUNT_URL=https://elastic.example.com:9200
ELASTIC_SECURITY_HUNT_API_KEY=ChangeMe
ELASTIC_SECURITY_HUNT_INDICES=logs-*,winlogbeat-*
ELASTIC_SECURITY_HUNT_QUERY_LANGUAGE=esql
```

Once the connector runs, open it in OpenCTI (**Data > Ingestion > Connectors**) and click **Test connection** on its **Hunted platform** card. It runs one search on the hunted indices. A missing permission is named in plain words, with what to grant; a hunt run refused by the platform reports the same sentence.

Table of Contents

- [OpenCTI Elastic Security Hunt Connector](#opencti-elastic-security-hunt-connector)
  - [Before you start](#before-you-start)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Elasticsearch permissions](#elasticsearch-permissions)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Query languages](#query-languages)
  - [Behavior](#behavior)
  - [Limits](#limits)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

A hunt is a falsifiable hypothesis plus the logic to test it: a canonical Sigma rule and, optionally, a native query
per platform. For every hunt run dispatched by OpenCTI (one hunt, one time window), the connector:

1. takes the native ES|QL, EQL or Lucene query of the hunt for Elastic Security, or translates its Sigma rule with
   [pySigma](https://github.com/SigmaHQ/pySigma) and the
   [Elasticsearch backend](https://github.com/SigmaHQ/pySigma-backend-elasticsearch);
2. runs it on Elasticsearch over the run time window, within the run timeout and result limit;
3. sends the resulting knowledge to OpenCTI: observed-data referencing the IOC observables found in the results, and the key of every hit (OpenCTI keeps one sighting of every technique and indicator of the hunt on the Security
   Platform of Elastic Security, updated at each run);
4. reports the run (hit count, distinct hosts/users/peers, translated query, redacted evidence sample).

Raw events never leave Elasticsearch: OpenCTI only receives counts and evidence values that are SHA-256 hashed and
truncated.

## Installation

### Requirements

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261008.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API (`INTERNAL_HUNT`, `register_hunt_platform`,
  `listen_hunt`, `report_hunt_run`) and stops with an explicit message otherwise.
- Elasticsearch 8.13 or later for ES|QL (async ES|QL queries), 7.10 or later for EQL and Lucene, reachable from the
  connector (Elastic Cloud deployments included: use the Elasticsearch endpoint URL).

### Elasticsearch permissions

The account, the least-privilege permissions, the console steps and a configuration example are in [Before you start](#before-you-start).

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Elastic Security Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `elastic-security` | No | Hunt platform slug, keep `elastic-security`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Security Platform name | `connector.security_platform_name` | `CONNECTOR_SECURITY_PLATFORM_NAME` | `Elastic Security` | No | OpenCTI Security Platform the hunts run against (created when missing). Use one name per cluster. |
| Security Platform type | `connector.security_platform_type` | `CONNECTOR_SECURITY_PLATFORM_TYPE` | `SIEM` | No | `SIEM`, `EDR`, `XDR`, `SOAR`, `NDR` or `ISPM`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create: `IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Url`, `StixFile`, `Email-Addr`, widened with `Hostname`, `User-Account`, `Mac-Addr`. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| Elasticsearch URL | `elastic_security_hunt.url` | `ELASTIC_SECURITY_HUNT_URL` | | Yes | URL of the Elasticsearch cluster, e.g. `https://elastic.example.com:9200`. |
| API key | `elastic_security_hunt.api_key` | `ELASTIC_SECURITY_HUNT_API_KEY` | | Yes (or user name and password) | Encoded API key (the base64 `id:api_key` value). |
| User name | `elastic_security_hunt.username` | `ELASTIC_SECURITY_HUNT_USERNAME` | | No | Used when no API key is set. |
| Password | `elastic_security_hunt.password` | `ELASTIC_SECURITY_HUNT_PASSWORD` | | No | Used when no API key is set. |
| Verify TLS | `elastic_security_hunt.verify_ssl` | `ELASTIC_SECURITY_HUNT_VERIFY_SSL` | `true` | No | Verify the TLS certificate of the cluster. |
| CA certificate | `elastic_security_hunt.ca_cert` | `ELASTIC_SECURITY_HUNT_CA_CERT` | | No | Path to a CA bundle verifying the cluster certificate (self-managed clusters). |
| Indices | `elastic_security_hunt.indices` | `ELASTIC_SECURITY_HUNT_INDICES` | `logs-*,winlogbeat-*,filebeat-*,auditbeat-*,endgame-*` | No | Comma-separated index patterns (and `cluster:pattern` remote patterns) the hunts search. |
| Query language | `elastic_security_hunt.query_language` | `ELASTIC_SECURITY_HUNT_QUERY_LANGUAGE` | `esql` | No | Language Sigma rules are translated into: `esql`, `eql` or `lucene`. |
| Sigma pipeline | `elastic_security_hunt.sigma_pipeline` | `ELASTIC_SECURITY_HUNT_SIGMA_PIPELINE` | `ecs_windows` | No | pySigma pipeline(s), chained with `+`: `ecs_windows`, `ecs_windows_old`, `ecs_kubernetes`, `ecs_macos_esf`, `ecs_zeek_beats`, `ecs_zeek_corelight`, `zeek` or `none`. |
| Timestamp field | `elastic_security_hunt.timestamp_field` | `ELASTIC_SECURITY_HUNT_TIMESTAMP_FIELD` | `@timestamp` | No | Field holding the event time. |

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-elastic-security-hunt:latest
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

At startup the connector registers the `elastic-security` hunt platform in OpenCTI with the `esql`, `eql` and `lucene`
languages and the Security Platform identity named by `CONNECTOR_SECURITY_PLATFORM_NAME`. Hunts then run on it from
OpenCTI (manually, on schedule, when the threat landscape changes or from playbooks), and their runs appear in the hunt
detail page. A preview run only translates the hunt logic: the translated query is shown in OpenCTI and Elasticsearch
is never queried.

## Query languages

The connector executes `esql`, `eql` and `lucene`.

- **Sigma rules** are translated into `ELASTIC_SECURITY_HUNT_QUERY_LANGUAGE` with the configured pipeline
  (`ecs_windows` maps Windows and Sysmon fields to ECS, as indexed by Elastic Defend, Winlogbeat and the Windows
  integration). ES|QL queries start with `from <ELASTIC_SECURITY_HUNT_INDICES>`; EQL and Lucene queries search those
  indices. A hunt may select another pipeline through a native query entry with an empty query and a `pipeline` (for
  example `ecs_zeek_beats`). Sigma documents with several rules are joined with `OR` in Lucene; in ES|QL and EQL each
  rule must be its own hunt.
- **Native queries** written for the `elastic-security` platform are executed verbatim in their language:
  - `esql`: a full ES|QL query (`from logs-endpoint.events.* | where ...`), including aggregations;
  - `eql`: an EQL query (`process where ...`, `sequence by host.id [...] [...]`), over the configured indices;
  - `lucene`: a Lucene query string (`process.name:rundll32.exe AND ...`), over the configured indices.

## Behavior

1. Every query is restricted to the run window with a range filter on `ELASTIC_SECURITY_HUNT_TIMESTAMP_FIELD` (no time
   condition is added to the query text).
2. ES|QL queries are capped with `| limit <max_results>`; when the cap is reached, the total hit count is read with a
   second `| stats count(*)` query. EQL searches return at most `max_results` events or sequences with their total.
   Lucene searches return the most recent `max_results` documents with the exact total (`track_total_hits`).
3. ES|QL and EQL queries run as async searches long-polled within the run timeout; their stored results are deleted
   when the run ends or times out. Partial results (shard failures, search timeouts, lower-bound totals) are kept,
   marked truncated and logged.
4. Events matching a benign pattern of the hunt are suppressed.
5. With hits, the connector sends one
   observed-data per public IP address, domain, URL, file hash or email address found, with the number of result events
   holding it, restricted to the observable types the hunt expects. Objects inherit the
   markings and author of the hunt and have deterministic identifiers; those of the observed-data derive
   from the hunt run too, so a retry of a run updates its own objects and two runs never share one. The run reports the key of every hit it read: OpenCTI counts the hits it never saw for the hunt and the platform
   as new, and keeps one sighting per technique and indicator of the hunt on the Security Platform, updated in
   place at each run (`count` = distinct hits, `first_seen` / `last_seen` = first and latest hit).
6. The run is reported with the hit count, the distinct hosts, users and network peers, the query executed and an
   evidence sample. `event.original`, `message`, `log.original` and bookkeeping fields (`_id`, `_index`,
   `agent.id`...) are never sampled; host names, user names and command lines only appear hashed and truncated in the
   evidence.

No incident is created by the connector: OpenCTI drafts incidents itself when the hits exceed the escalation threshold
of the hunt.

## Limits

| Limit | Value |
|---|---|
| Results read per run | `limits.max_results` of the run (set by OpenCTI), at most 10,000 (the default `index.max_result_window` and ES\|QL result size); the total hit count is kept. |
| Run timeout | `limits.timeout_seconds` of the run: every request is bounded by the time left, async searches are long-polled 30 seconds at most per request and deleted when the run times out. |
| Async search lifetime | 10 minutes `keep_alive`, so an interrupted connector never leaves stored searches behind. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run, IOC types by default, private IP addresses and internal domains never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception, partial results and its completion (hits, suppressed
events, objects sent) or failure. Failed runs are reported to OpenCTI with the Elasticsearch error reason (for example
the `verification_exception` of an invalid ES|QL query or the `security_exception` of a missing privilege).

## Additional information

- ES|QL is the default because it returns only the matched rows and supports aggregations; choose `eql` for sequence
  hunts and `lucene` for clusters older than 8.13.
- One connector instance executes against one cluster (cross-cluster search patterns included). Deploy one instance
  (with its own Security Platform name) per cluster to hunt.
