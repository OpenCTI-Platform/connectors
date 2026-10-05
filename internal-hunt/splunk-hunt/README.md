# OpenCTI Splunk Hunt Connector

The Splunk hunt connector executes the hunts of OpenCTI on Splunk Enterprise or Splunk Cloud. It is a connector of type
`INTERNAL_HUNT` registered for the `splunk` hunt platform.

## Before you start

| | |
|---|---|
| Credential | An authentication token of a dedicated service account (user name and password when tokens are disabled). |
| Console | Splunk Web: **Settings > Roles**, **Settings > Users**, **Settings > Tokens**. |
| Network | The REST API (management port, `8089` by default) reachable from the connector. |

Step by step:

1. In **Settings > Roles > New Role**, create `opencti_hunt` without inherited roles: capability `search`, and on the **Indexes** tab the indexes the hunts must cover.
2. Give the role read access to the app of `SPLUNK_HUNT_APP` (`search` by default): **Apps > Manage Apps > Permissions** of the app.
3. In **Settings > Users > New User**, create `svc_opencti_hunt` with the role `opencti_hunt` only.
4. In **Settings > Tokens**, enable token authentication if needed, then **New Token** for `svc_opencti_hunt`, and set it as `SPLUNK_HUNT_TOKEN`.

Least-privilege permissions:

| Permission | Why |
|---|---|
| Capability `search` | Create the search jobs of the hunts, read their status and results, cancel and delete them. |
| Read on the app `SPLUNK_HUNT_APP` | The search jobs run in this app namespace (`search` by default). |
| Indexes allowed to search (`srchIndexesAllowed`) | Every index the hunts must cover, for example `wineventlog`, `sysmon`, `main`. |
| Capability `edit_tokens_own` | Optional: lets the account create its own authentication token. |
| Read access to the data models | Only with the `splunk_cim` pipeline and the `data_model` output format (`tstats` searches). |

Jobs run in the `SPLUNK_HUNT_OWNER` / `SPLUNK_HUNT_APP` namespace (`nobody` / `search` by default) and are deleted once their results are read.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
SPLUNK_HUNT_URL=https://splunk.example.com:8089
SPLUNK_HUNT_TOKEN=ChangeMe
SPLUNK_HUNT_APP=search
SPLUNK_HUNT_SEARCH_PREFIX=index=wineventlog OR index=sysmon
```

Once the connector runs, open it in OpenCTI (**Data > Ingestion > Connectors**) and click **Test connection** on its **Hunted platform** card. It checks the token, the `search` capability of the roles of the account, then runs one search in the app. A missing permission is named in plain words, with what to grant; a hunt run refused by the platform reports the same sentence.

Table of Contents

- [OpenCTI Splunk Hunt Connector](#opencti-splunk-hunt-connector)
  - [Before you start](#before-you-start)
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
    - [Indicator hunts](#indicator-hunts)
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
3. sends the resulting knowledge to OpenCTI: observed-data referencing the IOC observables found in the results, and the key of every hit (OpenCTI keeps one sighting of every technique and indicator of the hunt on the Splunk
   Security Platform, updated at each run);
4. reports the run (hit count, distinct hosts/users/peers, translated query, redacted evidence sample).

Indicator hunts (a list of IP addresses, domains, URLs or hashes, no query language) are looked up value by value, see
[Indicator hunts](#indicator-hunts).

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

The account, the least-privilege permissions, the console steps and a configuration example are in [Before you start](#before-you-start).

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
4. With hits, the connector sends one observed-data
   per public IP address, domain, URL, file hash or email address found, with the number of result events holding it, restricted to the observable types the hunt expects. Objects inherit the markings and author
   of the hunt and have deterministic identifiers; those of the observed-data derive from the hunt run
   too, so a retry of a run updates its own objects and two runs never share one. The run reports the key of every hit it read: OpenCTI counts the hits it never saw for the hunt and the platform
   as new, and keeps one sighting per technique and indicator of the hunt on the Security Platform, updated in
   place at each run (`count` = distinct hits, `first_seen` / `last_seen` = first and latest hit).
5. The run is reported with the hit count (the Splunk `resultCount`), the distinct hosts, users and network peers, the
   SPL executed and an evidence sample. `_raw` and Splunk bookkeeping fields (`_time`, `_cd`, `punct`, `date_*`...)
   are never sampled; host names, user names and command lines only appear hashed and truncated in the evidence.

No incident is created by the connector: OpenCTI drafts incidents itself when the hits exceed the escalation threshold
of the hunt.

### Indicator hunts

An indicator hunt carries a list of values instead of a query: IP addresses, domains, host names, URLs, email
addresses, MAC addresses and file hashes, taken by OpenCTI from indicators, observables, reports, threats or pasted as
text. The connector registers as supporting indicator lookups and, for each run:

1. groups the values by observable type in batches of `limits.ioc_batch_size` values (50 by default);
2. runs one search per batch over the run window, within the search prefix:
   `search (<prefix>) ("198.51.100.7" OR "198.51.100.8") | eval ioc=mvappend(if(match(_raw, ...), "<key>", null()), ...) | stats count as hits min(_time) as first_seen max(_time) as last_seen values(host) as hosts by ioc`.
   Each event is credited to every value its raw text holds as a whole token (`198.51.100.7` never matches
   `198.51.100.70`, `evil.com` matches `cdn.evil.com` but not `evil.com.au`), so the counts are exact;
3. reports, for every value, whether it was seen, its hits, its first and last event and at most ten hosts;
4. sends nothing else: OpenCTI keeps one sighting per hunt, indicator or observable the value comes from, and Security
   Platform, updated in place at each run (a pasted value is created as an observable so that OpenCTI can sight it).
   The lookups return counts, not single events, so OpenCTI cannot tell the hits of two runs apart and counts every
   hit of a run as new; scheduled runs only search since the previous run, so the counts barely overlap.

Preview the query in OpenCTI shows the searches of every batch without running them.

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
