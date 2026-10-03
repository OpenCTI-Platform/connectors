# OpenCTI Splunk Hunt Connector

The Splunk hunt connector executes the hunts of OpenCTI on Splunk Enterprise or Splunk Cloud. It is a connector of type
`INTERNAL_HUNT` registered for the `splunk` hunt platform.

Table of Contents

- [OpenCTI Splunk Hunt Connector](#opencti-splunk-hunt-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Splunk permissions](#splunk-permissions)
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

1. takes the native SPL query of the hunt for Splunk, or translates its Sigma rule into SPL with
   [pySigma](https://github.com/SigmaHQ/pySigma) and the
   [Splunk backend](https://github.com/SigmaHQ/pySigma-backend-splunk);
2. runs it as a Splunk search job over the run time window, within the run timeout and result limit;
3. sends the resulting knowledge to OpenCTI: a sighting of every technique and indicator of the hunt on the Splunk
   Security Platform identity, and observed-data referencing the IOC observables found in the results;
4. reports the run (hit count, distinct hosts/users/peers, translated query, redacted evidence sample).

Raw events never leave Splunk: OpenCTI only receives counts and evidence values that are SHA-256 hashed and truncated.

## Installation

### Requirements

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261002.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API (`INTERNAL_HUNT`, `register_hunt_platform`,
  `listen_hunt`, `report_hunt_run`) and stops with an explicit message otherwise.
- Splunk Enterprise or Splunk Cloud 9.0 or later, with its REST API (management port, `8089` by default) reachable
  from the connector.

### Splunk permissions

Create a dedicated service account (for example `svc_opencti_hunt`) with a role that grants:

| Permission | Why |
|---|---|
| Capability `search` | Create search jobs, read their status and results, cancel and delete them. |
| Read permission on the app `SPLUNK_HUNT_APP` | The search jobs run in this app namespace (`search` by default). |
| Capability `edit_tokens_own` | Only to let the account create its own authentication token. |
| Indexes allowed to search (`srchIndexesAllowed`) | Every index the hunts must cover (for example `wineventlog`, `sysmon`, `main`). |
| Read access to the data models | Only with the `splunk_cim` pipeline and the `data_model` output format (`tstats` searches). |

Create an authentication token for the account (Settings > Tokens) and set it as `SPLUNK_HUNT_TOKEN`; user name and
password authentication is supported when tokens are disabled. Jobs run in the `SPLUNK_HUNT_OWNER` /
`SPLUNK_HUNT_APP` namespace (`nobody` / `search` by default) and are deleted once their results are read.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Splunk Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `splunk` | No | Hunt platform slug, keep `splunk`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Security Platform name | `connector.security_platform_name` | `CONNECTOR_SECURITY_PLATFORM_NAME` | `Splunk` | No | OpenCTI Security Platform the hunts run against (created when missing). Use one name per Splunk deployment. |
| Security Platform type | `connector.security_platform_type` | `CONNECTOR_SECURITY_PLATFORM_TYPE` | `SIEM` | No | `SIEM`, `EDR`, `XDR`, `SOAR`, `NDR` or `ISPM`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create: `IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Url`, `StixFile`, `Email-Addr`, widened with `Hostname`, `User-Account`, `Mac-Addr`. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| Splunk URL | `splunk_hunt.url` | `SPLUNK_HUNT_URL` | | Yes | URL of the Splunk REST API, e.g. `https://splunk.example.com:8089`. |
| Token | `splunk_hunt.token` | `SPLUNK_HUNT_TOKEN` | | Yes (or user name and password) | Splunk authentication token. |
| User name | `splunk_hunt.username` | `SPLUNK_HUNT_USERNAME` | | No | Used when no token is set. |
| Password | `splunk_hunt.password` | `SPLUNK_HUNT_PASSWORD` | | No | Used when no token is set. |
| Verify TLS | `splunk_hunt.verify_ssl` | `SPLUNK_HUNT_VERIFY_SSL` | `true` | No | Verify the TLS certificate of the REST API. |
| App | `splunk_hunt.app` | `SPLUNK_HUNT_APP` | `search` | No | App namespace of the search jobs. |
| Owner | `splunk_hunt.owner` | `SPLUNK_HUNT_OWNER` | `nobody` | No | User namespace of the search jobs. |
| Search prefix | `splunk_hunt.search_prefix` | `SPLUNK_HUNT_SEARCH_PREFIX` | | No | SPL constraint added to every search, e.g. `index=wineventlog OR index=sysmon`, or `` `opencti_hunt_scope` ``. |
| Sigma pipeline | `splunk_hunt.sigma_pipeline` | `SPLUNK_HUNT_SIGMA_PIPELINE` | `splunk_windows` | No | pySigma pipeline(s), chained with `+`: `splunk_windows`, `splunk_sysmon_acceleration`, `splunk_cim` or `none`. |
| Output format | `splunk_hunt.output_format` | `SPLUNK_HUNT_OUTPUT_FORMAT` | `default` | No | `default` (plain searches) or `data_model` (CIM `tstats` searches, requires `splunk_cim`). |
| Poll interval | `splunk_hunt.poll_interval` | `SPLUNK_HUNT_POLL_INTERVAL` | `2` | No | Seconds between two search job status checks. |

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-splunk-hunt:latest
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

At startup the connector registers the `splunk` hunt platform in OpenCTI with the `spl` language and the Security
Platform identity named by `CONNECTOR_SECURITY_PLATFORM_NAME`. Hunts then run on it from OpenCTI (manually, on schedule,
when the threat landscape changes or from playbooks), and their runs appear in the hunt detail page. A preview run only
translates the hunt logic: the translated SPL is shown in OpenCTI and Splunk is never queried.

## Query languages

The connector executes `spl`.

- **Sigma rules** are translated with the configured pipeline: `splunk_windows` (Windows event and Sysmon field names),
  `splunk_sysmon_acceleration` (adds keywords that accelerate Sysmon searches, chain it after `splunk_windows`) or
  `splunk_cim` (CIM field names).
  With `SPLUNK_HUNT_OUTPUT_FORMAT=data_model` and `splunk_cim`, rules become `| tstats` searches over the CIM data
  models (`Endpoint.Processes`, `Network_Traffic.All_Traffic`...). A hunt may select another pipeline through a native
  query entry with an empty query and a `pipeline` (for example `splunk_cim`).
- **Native queries** written for the `splunk` platform (language `spl`) are executed verbatim: either a search
  expression (`index=main sourcetype=sysmon EventCode=1 ...`) or a generating command (`| tstats ...`).

## Behavior

1. The query becomes a search: plain expressions get the `search` command and the configured search prefix, both
   parenthesized so that their `OR` operators keep their meaning (`search (<prefix>) (<query>) | <pipeline>`).
   Generating commands (`| tstats`, `| inputlookup`...) are executed as written when no search prefix is configured.
   With a search prefix, a `| tstats` search gets the prefix in its `where` clause
   (`| tstats ... where (<prefix>) AND (<condition>) by ...`) and any other generating command is refused (the run
   fails with an explicit error), so no hunt ever searches outside the configured scope. With the
   [OpenCTI for Splunk Enterprise add-on](https://github.com/OpenCTI-Platform/splunk-enterprise-add-on), set
   `SPLUNK_HUNT_SEARCH_PREFIX` to `` `opencti_hunt_scope` `` to reuse the indexes the add-on scopes hunts to.
2. The search job runs over the run window (`earliest_time` / `latest_time` in UTC), is polled every
   `SPLUNK_HUNT_POLL_INTERVAL` seconds until done, then its results are read page by page and the job is deleted.
3. Events matching a benign pattern of the hunt are suppressed.
4. With hits, the connector sends one sighting per technique and indicator of the hunt (`where_sighted_refs` = the
   Splunk Security Platform, `count` = hits, `first_seen` / `last_seen` = first and last event) and one observed-data
   per number of observations, referencing the public IP addresses, domains, URLs, file hashes and email addresses that
   many result events hold, restricted to the observable types the hunt expects. Objects inherit the markings and author
   of the hunt and have deterministic identifiers; those of the sightings and observed-data derive from the hunt run
   too, so a retry of a run updates its own objects and two runs never share one.
5. The run is reported with the hit count (the Splunk `resultCount`), the distinct hosts, users and network peers, the
   SPL executed and an evidence sample. `_raw` and Splunk bookkeeping fields (`_time`, `_cd`, `punct`, `date_*`...)
   are never sampled; host names, user names and command lines only appear hashed and truncated in the evidence.

No incident is created by the connector: OpenCTI drafts incidents itself when the hits exceed the escalation threshold
of the hunt.

## Limits

| Limit | Value |
|---|---|
| Results read per run | `limits.max_results` of the run (set by OpenCTI), read in pages of 10,000; the total hit count is kept. |
| Run timeout | `limits.timeout_seconds` of the run: every REST call is bounded by the time left, and the search job is cancelled when the run times out. |
| Search job lifetime | Jobs are created with a 600 seconds TTL and deleted once read, so an interrupted connector never leaves jobs behind. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run, IOC types by default, private IP addresses and internal domains never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception, the search job creation, cancellation or deletion, and
its completion (hits, suppressed events, objects sent) or failure. Failed runs are reported to OpenCTI with the Splunk
error message (for example the `Error in 'search' command` text of an invalid query).

## Additional information

- Sigma field names depend on how your data is onboarded: choose the pipeline that matches your sourcetypes (Windows
  event logs and Sysmon with `splunk_windows`, CIM-compliant add-ons with `splunk_cim`), or write native SPL queries.
- One connector instance executes against one Splunk deployment. Deploy one instance (with its own Security Platform
  name) per Splunk deployment to hunt.
