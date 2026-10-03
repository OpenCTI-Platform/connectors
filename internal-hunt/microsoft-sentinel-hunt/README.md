# OpenCTI Microsoft Sentinel Hunt Connector

The Microsoft Sentinel hunt connector executes the hunts of OpenCTI on the Log Analytics workspace of Microsoft
Sentinel. It is a connector of type `INTERNAL_HUNT` registered for the `microsoft-sentinel` hunt platform.

Table of Contents

- [OpenCTI Microsoft Sentinel Hunt Connector](#opencti-microsoft-sentinel-hunt-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Azure permissions](#azure-permissions)
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

1. takes the native KQL query of the hunt for Microsoft Sentinel, or translates its Sigma rule into KQL with
   [pySigma](https://github.com/SigmaHQ/pySigma) and the
   [Kusto backend](https://github.com/AttackIQ/pySigma-backend-kusto);
2. runs it with the [Log Analytics query API](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/api/overview)
   over the run time window, within the run timeout and result limit;
3. sends the resulting knowledge to OpenCTI: a sighting of every technique and indicator of the hunt on the Microsoft
   Sentinel Security Platform identity, and an observed-data referencing the IOC observables found in the results;
4. reports the run (hit count, distinct hosts/users/peers, translated query, redacted evidence sample).

Raw events never leave the workspace: OpenCTI only receives counts and evidence values that are SHA-256 hashed and
truncated.

## Installation

### Requirements

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261002.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API (`INTERNAL_HUNT`, `register_hunt_platform`,
  `listen_hunt`, `report_hunt_run`) and stops with an explicit message otherwise.
- A Microsoft Sentinel workspace and network access to the Log Analytics query API (`api.loganalytics.io`) and to
  Microsoft Entra ID (`login.microsoftonline.com`), or their sovereign cloud equivalents.

### Azure permissions

Register an application in Microsoft Entra ID (or use a managed identity with `MICROSOFT_SENTINEL_HUNT_AUTH_TYPE=
azure_credential`) and grant it:

| Permission | Why |
|---|---|
| Azure role `Log Analytics Reader` (or `Microsoft Sentinel Reader`) on the workspace | Run read-only queries on the workspace tables. |
| The same role on every workspace of `MICROSOFT_SENTINEL_HUNT_ADDITIONAL_WORKSPACES` | Cross-workspace queries. |

No API permission (Microsoft Graph or Log Analytics API) is required with an Azure role assignment, and the connector
never writes to the workspace. The access token is requested for the `<api_url>/.default` scope.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Microsoft Sentinel Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `microsoft-sentinel` | No | Hunt platform slug, keep `microsoft-sentinel`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Security Platform name | `connector.security_platform_name` | `CONNECTOR_SECURITY_PLATFORM_NAME` | `Microsoft Sentinel` | No | OpenCTI Security Platform the hunts run against (created when missing). Use one name per workspace. |
| Security Platform type | `connector.security_platform_type` | `CONNECTOR_SECURITY_PLATFORM_TYPE` | `SIEM` | No | `SIEM`, `EDR`, `XDR`, `SOAR`, `NDR` or `ISPM`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | | No | Connector-side limit of concurrent hunt runs (the platform budget is the minimum of both). |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create: `IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Url`, `StixFile`, `Email-Addr`, widened with `Hostname`, `User-Account`, `Mac-Addr`. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| Authentication | `microsoft_sentinel_hunt.auth_type` | `MICROSOFT_SENTINEL_HUNT_AUTH_TYPE` | `app_registration` | No | `app_registration` (client secret) or `azure_credential` (managed identity, workload identity or `az login`). |
| Tenant ID | `microsoft_sentinel_hunt.tenant_id` | `MICROSOFT_SENTINEL_HUNT_TENANT_ID` | | With `app_registration` | Microsoft Entra tenant ID. |
| Client ID | `microsoft_sentinel_hunt.client_id` | `MICROSOFT_SENTINEL_HUNT_CLIENT_ID` | | With `app_registration` | Application (client) ID. |
| Client secret | `microsoft_sentinel_hunt.client_secret` | `MICROSOFT_SENTINEL_HUNT_CLIENT_SECRET` | | With `app_registration` | Client secret of the application. |
| Workspace ID | `microsoft_sentinel_hunt.workspace_id` | `MICROSOFT_SENTINEL_HUNT_WORKSPACE_ID` | | Yes | Workspace ID (GUID) of the Log Analytics workspace of Microsoft Sentinel. |
| Additional workspaces | `microsoft_sentinel_hunt.additional_workspaces` | `MICROSOFT_SENTINEL_HUNT_ADDITIONAL_WORKSPACES` | | No | Comma-separated workspace IDs or resource IDs queried together with the main workspace. |
| API URL | `microsoft_sentinel_hunt.api_url` | `MICROSOFT_SENTINEL_HUNT_API_URL` | `https://api.loganalytics.io` | No | `https://api.loganalytics.us` (Azure Government) or `https://api.loganalytics.azure.cn` (Azure China). |
| Authority host | `microsoft_sentinel_hunt.authority_host` | `MICROSOFT_SENTINEL_HUNT_AUTHORITY_HOST` | `login.microsoftonline.com` | No | `login.microsoftonline.us` (Azure Government) or `login.chinacloudapi.cn` (Azure China). |
| Sigma pipeline | `microsoft_sentinel_hunt.sigma_pipeline` | `MICROSOFT_SENTINEL_HUNT_SIGMA_PIPELINE` | `sentinel_asim` | No | pySigma pipeline(s), chained with `+`: `sentinel_asim`, `azure_monitor`, `microsoft_xdr` or `none`. |

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-microsoft-sentinel-hunt:latest
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

At startup the connector registers the `microsoft-sentinel` hunt platform in OpenCTI with the `kql` language and the
Security Platform identity named by `CONNECTOR_SECURITY_PLATFORM_NAME`. Hunts then run on it from OpenCTI (manually,
on schedule, when the threat landscape changes or from playbooks), and their runs appear in the hunt detail page. A
preview run only translates the hunt logic: the translated KQL is shown in OpenCTI and the workspace is never queried.

## Query languages

The connector executes `kql`.

- **Sigma rules** are translated with the configured pipeline: `sentinel_asim` (ASIM parsers such as
  `imProcessCreate`, `imNetworkSession`, `imDns`), `azure_monitor` (`SecurityEvent` and Azure Monitor tables) or
  `microsoft_xdr` (`DeviceProcessEvents` and the other Defender XDR tables streamed to Sentinel). A hunt may select
  another pipeline through a native query entry with an empty query and a `pipeline` (for example `microsoft_xdr`).
  When a hunt holds several Sigma rules, their queries are combined with `union`.
- **Native queries** written for the `microsoft-sentinel` platform (language `kql`) are executed verbatim: any tabular
  KQL expression, starting with a table, a function or a `let` statement.

## Behavior

1. The query is restricted to the run window with the API `timespan` parameter (no time filter is added to the query
   text) and capped with `| take <max_results>`. When the cap is reached, the total hit count is read with a second
   `| count` query.
2. Queries wait up to the run timeout for their answer (`Prefer: wait`, at most 10 minutes). Partial results returned
   by the API with an error are kept, marked truncated and logged.
3. Events matching a benign pattern of the hunt are suppressed.
4. With hits, the connector sends one sighting per technique and indicator of the hunt (`where_sighted_refs` = the
   Microsoft Sentinel Security Platform, `count` = hits, `first_seen` / `last_seen` = first and last event, read from
   `TimeGenerated`, `Timestamp`, `EventStartTime` or `TimeCreated`) and one observed-data referencing the public IP
   addresses, domains, URLs, file hashes and email addresses found in the results, restricted to the observable types
   the hunt expects. Objects inherit the markings and author of the hunt and have deterministic identifiers, so re-runs
   over the same window update them.
5. The run is reported with the hit count, the distinct hosts, users and network peers, the KQL executed and an
   evidence sample. Raw payload columns (`EventData`, `RawEventData`, `AdditionalFields`, `Message`...) and Log
   Analytics bookkeeping columns (`TenantId`, `_ResourceId`, `Type`...) are never sampled; host names, user names and
   command lines only appear hashed and truncated in the evidence.

No incident is created by the connector: OpenCTI drafts incidents itself when the hits exceed the escalation threshold
of the hunt.

## Limits

| Limit | Value |
|---|---|
| Results read per run | `limits.max_results` of the run (set by OpenCTI); the Log Analytics API itself returns at most 500,000 rows and 64 MB per query. |
| Run timeout | `limits.timeout_seconds` of the run: token requests and queries are bounded by the time left, and the run fails as timed out when it expires. |
| Query lookback | The run window; the API enforces the workspace retention. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run, IOC types by default, private IP addresses and internal domains never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception, partial results and its completion (hits, suppressed
events, objects sent) or failure. Failed runs are reported to OpenCTI with the Log Analytics error message (for example
the `SemanticError` text of an invalid query) or the Microsoft Entra authentication error.

## Additional information

- Sigma field names depend on the tables you query: choose the pipeline that matches your data (ASIM normalized
  parsers, raw `SecurityEvent`, or Defender XDR tables), or write native KQL queries.
- One connector instance executes against one workspace (plus its additional workspaces). Deploy one instance (with
  its own Security Platform name) per Sentinel workspace to hunt.
