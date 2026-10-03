# OpenCTI OpenSearch OCSF Hunt Connector

The OpenSearch OCSF hunt connector executes the hunts of OpenCTI on security events normalized to the
[Open Cybersecurity Schema Framework (OCSF)](https://schema.ocsf.io/) and stored in OpenSearch (self-managed OpenSearch,
Amazon OpenSearch Service, Amazon Security Lake data indexed in OpenSearch...). It is a connector of type
`INTERNAL_HUNT` registered for the `opensearch` hunt platform.

Table of Contents

- [OpenCTI OpenSearch OCSF Hunt Connector](#opencti-opensearch-ocsf-hunt-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [OpenSearch permissions](#opensearch-permissions)
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

1. takes the native PPL or Lucene query of the hunt for OpenSearch, or translates its Sigma rule with
   [pySigma](https://github.com/SigmaHQ/pySigma), the
   [OCSF pipeline](https://github.com/SigmaHQ/pySigma-pipeline-ocsf) (Sigma fields and log sources to OCSF classes and
   attributes) and the [OpenSearch backend](https://github.com/SigmaHQ/pySigma-backend-opensearch);
2. runs it over the run time window, within the run timeout and result limit;
3. sends the resulting knowledge to OpenCTI: a sighting of every technique and indicator of the hunt on the OpenSearch
   Security Platform identity, and an observed-data referencing the IOC observables found in the results;
4. reports the run (hit count, distinct hosts/users/peers, translated query, redacted evidence sample).

Raw events never leave OpenSearch: OpenCTI only receives counts and evidence values that are SHA-256 hashed and
truncated.

## Installation

### Requirements

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261002.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API (`INTERNAL_HUNT`, `register_hunt_platform`,
  `listen_hunt`, `report_hunt_run`) and stops with an explicit message otherwise.
- OpenSearch 2.x or later with the SQL plugin (bundled with the default distribution, it serves PPL), reachable from
  the connector on its REST port (`9200` by default).
- Events normalized to OCSF in the indices the connector searches.

### OpenSearch permissions

With the security plugin, create a dedicated internal user (for example `svc_opencti_hunt`) mapped to a role granting:

| Permission | Why |
|---|---|
| Cluster permission `cluster:admin/opensearch/ppl` | Run PPL queries (not needed with `opensearch-lucene` only). |
| Index permissions `read` on the index patterns of `OPENSEARCH_OCSF_HUNT_INDICES` | Search the OCSF events. |
| Index permission `indices:admin/mappings/get` on the same patterns | PPL reads the index mappings to resolve fields. |

The connector authenticates with HTTP basic authentication. On Amazon OpenSearch Service, enable fine-grained access
control and use a user of the internal user database. Leave `OPENSEARCH_OCSF_HUNT_USERNAME` and
`OPENSEARCH_OCSF_HUNT_PASSWORD` empty for a cluster without the security plugin.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `OpenSearch OCSF Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `opensearch` | No | Hunt platform slug, keep `opensearch`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Security Platform name | `connector.security_platform_name` | `CONNECTOR_SECURITY_PLATFORM_NAME` | `OpenSearch` | No | OpenCTI Security Platform the hunts run against (created when missing). Use one name per cluster. |
| Security Platform type | `connector.security_platform_type` | `CONNECTOR_SECURITY_PLATFORM_TYPE` | `SIEM` | No | `SIEM`, `EDR`, `XDR`, `SOAR`, `NDR` or `ISPM`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create: `IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Url`, `StixFile`, `Email-Addr`, widened with `Hostname`, `User-Account`, `Mac-Addr`. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| OpenSearch URL | `opensearch_ocsf_hunt.url` | `OPENSEARCH_OCSF_HUNT_URL` | | Yes | URL of the cluster, e.g. `https://opensearch.example.com:9200`. |
| User name | `opensearch_ocsf_hunt.username` | `OPENSEARCH_OCSF_HUNT_USERNAME` | | With the security plugin | User of the basic authentication. |
| Password | `opensearch_ocsf_hunt.password` | `OPENSEARCH_OCSF_HUNT_PASSWORD` | | With the security plugin | Password of the user. |
| Verify TLS | `opensearch_ocsf_hunt.verify_ssl` | `OPENSEARCH_OCSF_HUNT_VERIFY_SSL` | `true` | No | Verify the TLS certificate of the cluster. |
| CA certificate | `opensearch_ocsf_hunt.ca_cert` | `OPENSEARCH_OCSF_HUNT_CA_CERT` | | No | Path to a CA bundle verifying a certificate of a private CA. |
| Indices | `opensearch_ocsf_hunt.indices` | `OPENSEARCH_OCSF_HUNT_INDICES` | `ocsf-*` | No | Comma-separated index patterns holding the OCSF events. |
| Query language | `opensearch_ocsf_hunt.query_language` | `OPENSEARCH_OCSF_HUNT_QUERY_LANGUAGE` | `ppl` | No | Language Sigma rules are translated into: `ppl` or `opensearch-lucene`. |
| Sigma pipeline | `opensearch_ocsf_hunt.sigma_pipeline` | `OPENSEARCH_OCSF_HUNT_SIGMA_PIPELINE` | `ocsf` | No | pySigma pipeline(s), chained with `+`: `ocsf` or `none`. |
| Timestamp field | `opensearch_ocsf_hunt.timestamp_field` | `OPENSEARCH_OCSF_HUNT_TIMESTAMP_FIELD` | `time` | No | Field holding the event time. |
| Timestamp format | `opensearch_ocsf_hunt.timestamp_format` | `OPENSEARCH_OCSF_HUNT_TIMESTAMP_FORMAT` | `epoch_millis` | No | `epoch_millis` (the OCSF `time` attribute, a number of milliseconds) or `date` (a date field such as `time_dt`). |

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-opensearch-ocsf-hunt:latest
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

At startup the connector registers the `opensearch` hunt platform in OpenCTI with the `ppl` and `opensearch-lucene`
languages and the Security Platform identity named by `CONNECTOR_SECURITY_PLATFORM_NAME`. Hunts then run on it from
OpenCTI (manually, on schedule, when the threat landscape changes or from playbooks), and their runs appear in the hunt
detail page. A preview run only translates the hunt logic: the translated query is shown in OpenCTI and OpenSearch is
never queried.

## Query languages

The connector executes `ppl` and `opensearch-lucene`.

- **Sigma rules** are translated into `OPENSEARCH_OCSF_HUNT_QUERY_LANGUAGE` with the `ocsf` pipeline: Sigma log
  sources become OCSF class and type filters (`type_uid=100701` for Windows process creation, `class_uid=4003` for DNS
  activity...) and Sigma fields become OCSF attributes (`process.cmd_line`, `dst_endpoint.ip`, `query.hostname`...).
  PPL queries read `source=<OPENSEARCH_OCSF_HUNT_INDICES>`; Lucene queries search those indices. A Sigma document with
  several rules is joined with `OR` in Lucene and rejected in PPL (one query per hunt). A hunt may disable the
  pipeline through a native query entry with an empty query and the `none` pipeline.
- **Native queries** written for the `opensearch` platform are executed as written (a trailing `;` is removed): PPL
  queries (`ppl`) start with their own `source=` command; Lucene query strings (`opensearch-lucene`) search the
  configured indices.

## Behavior

1. The query is restricted to the run window on `OPENSEARCH_OCSF_HUNT_TIMESTAMP_FIELD`: a `where` command inserted
   right after the `source` command of a PPL query, or a `range` filter next to the Lucene query string.
2. PPL queries are capped with `| head <max_results>`, and the hit count is read with
   `| stats count() as opencti_hit_count` when there are results. Lucene searches return the most recent documents
   with the exact total (`track_total_hits`); a search that timed out or lost a shard is reported as truncated.
3. Events matching a benign pattern of the hunt are suppressed.
4. With hits, the connector sends one sighting per technique and indicator of the hunt (`where_sighted_refs` = the
   OpenSearch Security Platform, `count` = hits, `first_seen` / `last_seen` = first and last event) and one
   observed-data referencing the public IP addresses, domains, URLs, file hashes and email addresses found in the
   results, restricted to the observable types the hunt expects. Objects inherit the markings and author of the hunt
   and have deterministic identifiers, so re-runs over the same window update them.
5. The run is reported with the hit count, the distinct hosts, users and network peers (OCSF `device.hostname`,
   `actor.user.name`, `src_endpoint.ip`, `dst_endpoint.ip`...), the query executed and an evidence sample. The raw event
   (`raw_data`) and bookkeeping fields (`metadata.uid`, `metadata.version`, `_id`, `_index`...) are never sampled; host
   names, user names and command lines only appear hashed and truncated in the evidence.

No incident is created by the connector: OpenCTI drafts incidents itself when the hits exceed the escalation threshold
of the hunt.

## Limits

| Limit | Value |
|---|---|
| Results read per run | `limits.max_results` of the run (set by OpenCTI), at most 10,000 (the default `index.max_result_window`); the total hit count is kept. PPL also returns at most `plugins.query.size_limit` rows: raise this cluster setting to read more events per run. |
| Run timeout | `limits.timeout_seconds` of the run: every call is bounded by the time left. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run, IOC types by default, private IP addresses and internal domains never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception and its completion (hits, suppressed events, objects
sent) or failure. Failed runs are reported to OpenCTI with the OpenSearch error, including the details of PPL errors
(for example `can't resolve Symbol(namespace=FIELD_NAME, name=...)` for a field missing from the mappings).

## Additional information

- The OCSF `time` attribute is an epoch in milliseconds. When your indices map it as a `date`, or only hold `time_dt`,
  set `OPENSEARCH_OCSF_HUNT_TIMESTAMP_FORMAT=date` (and the field name accordingly).
- One connector instance executes against one cluster. Deploy one instance (with its own Security Platform name) per
  cluster to hunt.
