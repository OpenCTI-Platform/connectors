# OpenCTI CrowdStrike LogScale Hunt Connector

The CrowdStrike LogScale hunt connector executes the hunts of OpenCTI on CrowdStrike Falcon Next-Gen SIEM or on a
Falcon LogScale cluster. It is a connector of type `INTERNAL_HUNT` registered for the `crowdstrike-logscale` hunt
platform.

## Before you start

| | |
|---|---|
| Credential | Falcon Next-Gen SIEM (`falcon`): an API client ID and secret. LogScale (`logscale`): a personal API token, or an organization token scoped to the repository. |
| Console | Falcon console: **Support and resources > API clients and keys**. LogScale: the API tokens of your account or organization. |
| Network | The Falcon API of your cloud (`https://api.crowdstrike.com`, `https://api.us-2.crowdstrike.com`, `https://api.eu-1.crowdstrike.com`...) or the LogScale URL. |

Step by step:

1. Falcon: in **Support and resources > API clients and keys > Create API client**, create `opencti-hunt` with the scope **NGSIEM**: Read and Write.
2. Copy the client ID and the secret (shown once) into `CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_ID` and `CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_SECRET`, and set `CROWDSTRIKE_LOGSCALE_HUNT_BASE_URL` to the API of your cloud.
3. LogScale instead: set `CROWDSTRIKE_LOGSCALE_HUNT_DEPLOYMENT=logscale`, create a token with search access to the repository (or view) of `CROWDSTRIKE_LOGSCALE_HUNT_REPOSITORY`, and set it with the URL in `CROWDSTRIKE_LOGSCALE_HUNT_LOGSCALE_TOKEN` and `CROWDSTRIKE_LOGSCALE_HUNT_LOGSCALE_URL`.

Least-privilege permissions:

| Permission | Why |
|---|---|
| API client scope `NGSIEM` Read (`falcon`) | Read the status and results of the query jobs. |
| API client scope `NGSIEM` Write (`falcon`) | Start the query jobs and stop them. |
| Search (`ReadAccess` / `QueryDashboard`) on `CROWDSTRIKE_LOGSCALE_HUNT_REPOSITORY` (`logscale`) | Run query jobs on the repository or view. |

The connector never ingests nor modifies data: it only creates and deletes its own query jobs. With `falcon`, the API client credentials are exchanged for an OAuth2 token, renewed one minute before it expires.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
CROWDSTRIKE_LOGSCALE_HUNT_DEPLOYMENT=falcon
CROWDSTRIKE_LOGSCALE_HUNT_BASE_URL=https://api.crowdstrike.com
CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_ID=ChangeMe
CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_SECRET=ChangeMe
CROWDSTRIKE_LOGSCALE_HUNT_REPOSITORY=search-all
```

Once the connector runs, open it in OpenCTI (**Data > Ingestion > Connectors**) and click **Test connection** on its **Hunted platform** card. It runs one query job on the repository. A missing permission is named in plain words, with what to grant; a hunt run refused by the platform reports the same sentence.

Table of Contents

- [OpenCTI CrowdStrike LogScale Hunt Connector](#opencti-crowdstrike-logscale-hunt-connector)
  - [Before you start](#before-you-start)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [CrowdStrike permissions](#crowdstrike-permissions)
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

1. takes the native LogScale query of the hunt for CrowdStrike, or translates its Sigma rule into a LogScale query
   with [pySigma](https://github.com/SigmaHQ/pySigma) and the
   [CrowdStrike backend](https://github.com/SigmaHQ/pySigma-backend-crowdstrike);
2. runs it as a LogScale query job over the run time window, within the run timeout and result limit;
3. sends the resulting knowledge to OpenCTI: a sighting of every technique and indicator of the hunt on the
   CrowdStrike Falcon Security Platform identity, and observed-data referencing the IOC observables found in the
   results;
4. reports the run (hit count, distinct hosts/users/peers, translated query, redacted evidence sample).

Raw events never leave CrowdStrike: OpenCTI only receives counts and evidence values that are SHA-256 hashed and
truncated.

## Installation

### Requirements

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261002.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API (`INTERNAL_HUNT`, `register_hunt_platform`,
  `listen_hunt`, `report_hunt_run`) and stops with an explicit message otherwise.
- Either Falcon Next-Gen SIEM (the `falcon` deployment, through the CrowdStrike API of your Falcon cloud), or a Falcon
  LogScale cluster, self-hosted or LogScale Cloud (the `logscale` deployment).

### CrowdStrike permissions

The account, the least-privilege permissions, the console steps and a configuration example are in [Before you start](#before-you-start).

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `CrowdStrike LogScale Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `crowdstrike-logscale` | No | Hunt platform slug, keep `crowdstrike-logscale`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Security Platform name | `connector.security_platform_name` | `CONNECTOR_SECURITY_PLATFORM_NAME` | `CrowdStrike Falcon` | No | OpenCTI Security Platform the hunts run against (created when missing). Use one name per Falcon tenant or LogScale cluster. |
| Security Platform type | `connector.security_platform_type` | `CONNECTOR_SECURITY_PLATFORM_TYPE` | `SIEM` | No | `SIEM`, `EDR`, `XDR`, `SOAR`, `NDR` or `ISPM`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create: `IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Url`, `StixFile`, `Email-Addr`, widened with `Hostname`, `User-Account`, `Mac-Addr`. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| Deployment | `crowdstrike_logscale_hunt.deployment` | `CROWDSTRIKE_LOGSCALE_HUNT_DEPLOYMENT` | `falcon` | No | `falcon` (Falcon Next-Gen SIEM) or `logscale` (LogScale cluster). |
| CrowdStrike API URL | `crowdstrike_logscale_hunt.base_url` | `CROWDSTRIKE_LOGSCALE_HUNT_BASE_URL` | `https://api.crowdstrike.com` | No | API URL of your Falcon cloud: `https://api.us-2.crowdstrike.com`, `https://api.eu-1.crowdstrike.com`, `https://api.laggar.gcw.crowdstrike.com`. |
| Client ID | `crowdstrike_logscale_hunt.client_id` | `CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_ID` | | With `falcon` | CrowdStrike API client ID. |
| Client secret | `crowdstrike_logscale_hunt.client_secret` | `CROWDSTRIKE_LOGSCALE_HUNT_CLIENT_SECRET` | | With `falcon` | CrowdStrike API client secret. |
| LogScale URL | `crowdstrike_logscale_hunt.logscale_url` | `CROWDSTRIKE_LOGSCALE_HUNT_LOGSCALE_URL` | | With `logscale` | URL of the LogScale cluster, e.g. `https://cloud.us.humio.com`. |
| LogScale token | `crowdstrike_logscale_hunt.logscale_token` | `CROWDSTRIKE_LOGSCALE_HUNT_LOGSCALE_TOKEN` | | With `logscale` | LogScale API token. |
| Repository | `crowdstrike_logscale_hunt.repository` | `CROWDSTRIKE_LOGSCALE_HUNT_REPOSITORY` | `search-all` | No | Repository or view searched: `search-all`, `investigate_view`, `third-party` (Next-Gen SIEM) or a LogScale repository. |
| Verify TLS | `crowdstrike_logscale_hunt.verify_ssl` | `CROWDSTRIKE_LOGSCALE_HUNT_VERIFY_SSL` | `true` | No | Verify the TLS certificate of the API. |
| Sigma pipeline | `crowdstrike_logscale_hunt.sigma_pipeline` | `CROWDSTRIKE_LOGSCALE_HUNT_SIGMA_PIPELINE` | `crowdstrike_falcon` | No | pySigma pipeline(s), chained with `+`: `crowdstrike_falcon`, `crowdstrike_fdr` or `none`. |
| Poll interval | `crowdstrike_logscale_hunt.poll_interval` | `CROWDSTRIKE_LOGSCALE_HUNT_POLL_INTERVAL` | `1` | No | Seconds between two query job status checks when LogScale gives no `pollAfter` hint. |

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-crowdstrike-logscale-hunt:latest
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

At startup the connector registers the `crowdstrike-logscale` hunt platform in OpenCTI with the `logscale` language and
the Security Platform identity named by `CONNECTOR_SECURITY_PLATFORM_NAME`. Hunts then run on it from OpenCTI
(manually, on schedule, when the threat landscape changes or from playbooks), and their runs appear in the hunt detail
page. A preview run only translates the hunt logic: the translated query is shown in OpenCTI and CrowdStrike is never
queried.

## Query languages

The connector executes `logscale` (the LogScale Query Language, also used by Falcon Next-Gen SIEM and Falcon
Investigate).

- **Sigma rules** are translated with the configured pipeline: `crowdstrike_falcon` (Falcon sensor telemetry, with
  `#event_simpleName` tags such as `ProcessRollup2` or `DnsRequest`) or `crowdstrike_fdr` (Falcon Data Replicator
  events, where `event_simpleName` is a plain field). A hunt may select another pipeline through a native query entry
  with an empty query and a `pipeline`. Sigma documents with several rules are joined with `or`.
- **Native queries** written for the `crowdstrike-logscale` platform (language `logscale`) are executed verbatim:
  filters, functions and aggregations (`#event_simpleName=DnsRequest | groupBy([DomainName])`) are supported.

## Behavior

1. The query job runs over the run window (`start` / `end` in epoch milliseconds, no time condition is added to the
   query text) and is capped with `| tail(limit=<max_results>)`. When the cap is reached, the total hit count is read
   with a second `| count()` query job.
2. Query jobs are polled at the `pollAfter` pace LogScale returns (or every `CROWDSTRIKE_LOGSCALE_HUNT_POLL_INTERVAL`
   seconds) until done, then deleted; they are also deleted when the run times out. LogScale warnings are logged, and a run with warnings is reported as partial results (OpenCTI then reads its hit count as a lower bound and never concludes benign from zero hits).
3. Events matching a benign pattern of the hunt are suppressed.
4. With hits, the connector sends one sighting per technique and indicator of the hunt (`where_sighted_refs` = the
   CrowdStrike Falcon Security Platform, `count` = hits, `first_seen` / `last_seen` = first and last event, read from
   `@timestamp` or `timestamp`) and one observed-data per public IP address, domain,
   URL, file hash or email address found, with the number of result events holding it, restricted to the observable types the
   hunt expects. Objects inherit the markings and author of the hunt and have deterministic identifiers; those of the
   sightings and observed-data derive from the hunt run too, so a retry of a run updates its own objects and two runs
   never share one.
5. The run is reported with the hit count, the distinct hosts (`ComputerName`), users (`UserName`) and network peers,
   the query executed and an evidence sample. `@rawstring`, sensor and customer identifiers (`aid`, `cid`) and
   LogScale bookkeeping fields (`@id`, `#repo`, `@ingesttimestamp`...) are never sampled; host names, user names and
   command lines only appear hashed and truncated in the evidence.

No incident is created by the connector: OpenCTI drafts incidents itself when the hits exceed the escalation threshold
of the hunt.

## Limits

| Limit | Value |
|---|---|
| Results read per run | `limits.max_results` of the run (set by OpenCTI), at most 10,000 events; the total hit count is kept. |
| Run timeout | `limits.timeout_seconds` of the run: token requests, job creation and polling are bounded by the time left, and the job is deleted when the run times out. |
| Query job lifetime | Jobs are deleted once read; LogScale also expires jobs that are not polled any more. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run, IOC types by default, private IP addresses and internal domains never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception, LogScale warnings and its completion (hits, suppressed
events, objects sent) or failure. Failed runs are reported to OpenCTI with the CrowdStrike or LogScale error message
(for example the parser error of an invalid query or the `access denied` of a missing API scope).

## Additional information

- The Next-Gen SIEM data retention and the repository (or view) define what a hunt can see: `search-all` covers the
  Falcon sensor telemetry and the third-party data ingested in Next-Gen SIEM.
- One connector instance executes against one Falcon tenant or LogScale cluster. Deploy one instance (with its own
  Security Platform name) per tenant or cluster to hunt.
