# OpenCTI Microsoft Defender Hunt Connector

The Microsoft Defender hunt connector executes the hunts of OpenCTI with the advanced hunting of Microsoft Defender
XDR. It is a connector of type `INTERNAL_HUNT` registered for the `microsoft-defender` hunt platform.

## Before you start

| | |
|---|---|
| Credential | A Microsoft Entra ID app registration with a client secret. |
| Console | Azure portal or Microsoft Entra admin center: **Microsoft Entra ID > App registrations**. Granting admin consent needs a Privileged Role Administrator, Cloud Application Administrator or Application Administrator. |
| Network | `login.microsoftonline.com` and `graph.microsoft.com` reachable from the connector. |

Step by step:

1. In **Microsoft Entra ID > App registrations > New registration**, register `opencti-hunt` (single tenant); note its **Directory (tenant) ID** and **Application (client) ID**.
2. In the app, **API permissions > Add a permission > Microsoft Graph > Application permissions**, select **ThreatHunting.Read.All**, then **Grant admin consent for &lt;tenant&gt;**.
3. In the app, **Certificates & secrets > New client secret**, and copy its value (it is shown once).

Least-privilege permissions:

| Permission | Why |
|---|---|
| Microsoft Graph application permission `ThreatHunting.Read.All`, admin consent granted | Run read-only advanced hunting queries (`POST /security/runHuntingQuery`). |

No other permission and no Azure role is required, and the connector never writes to the tenant. The access token is
requested with the client credentials flow for the `<graph_url>/.default` scope.

Copy-ready configuration (`.env` of the `docker-compose.yml`):

```env
OPENCTI_URL=https://opencti.example.com
OPENCTI_TOKEN=ChangeMe
CONNECTOR_ID=ChangeMe-UUIDv4
MICROSOFT_DEFENDER_HUNT_TENANT_ID=ChangeMe
MICROSOFT_DEFENDER_HUNT_CLIENT_ID=ChangeMe
MICROSOFT_DEFENDER_HUNT_CLIENT_SECRET=ChangeMe
```

Once the connector runs, open it in OpenCTI (**Data > Ingestion > Connectors**) and click **Test connection** on its
**Hunted platform** card. It requests a token from Microsoft Entra ID, then runs `DeviceInfo | take 1` over the last 7
days. A refused credential or a missing permission is named in plain words, with what to grant; a hunt run refused by
the platform reports the same sentence. A tenant without device telemetry passes with a warning.

Table of Contents

- [OpenCTI Microsoft Defender Hunt Connector](#opencti-microsoft-defender-hunt-connector)
  - [Before you start](#before-you-start)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Microsoft Entra ID permissions](#microsoft-entra-id-permissions)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Query languages](#query-languages)
  - [Indicator hunts](#indicator-hunts)
  - [Behavior](#behavior)
  - [Quotas and limits](#quotas-and-limits)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

A hunt is a falsifiable hypothesis plus the logic to test it: a canonical Sigma rule and, optionally, a native query
per platform. For every hunt run dispatched by OpenCTI (one hunt, one time window), the connector:

1. takes the native KQL query of the hunt for Microsoft Defender XDR, or translates its Sigma rule into KQL with
   [pySigma](https://github.com/SigmaHQ/pySigma), the
   [Kusto backend](https://github.com/AttackIQ/pySigma-backend-kusto) and its `microsoft_xdr` pipeline; an indicator
   hunt looks its values up in the tables that hold them;
2. runs it with the [advanced hunting API of Microsoft Graph](https://learn.microsoft.com/en-us/graph/api/security-security-runhuntingquery)
   over the run time window, within the run timeout, the result limit and the advanced hunting quotas of the tenant;
3. sends the resulting knowledge to OpenCTI: observed-data referencing the IOC observables found in the results, and
   the key of every hit (OpenCTI keeps one sighting of every technique and indicator of the hunt on the Microsoft
   Defender XDR Security Platform, updated at each run);
4. reports the run (hit count, distinct hosts/users/peers, translated query, redacted evidence sample).

Raw events never leave the tenant: OpenCTI only receives counts and evidence values that are SHA-256 hashed and
truncated.

## Installation

### Requirements

- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type).
- [`pycti`](https://pypi.org/project/pycti/) matching your OpenCTI version (pinned to `7.261014.0`). At startup, the
  connector checks that the installed pycti provides the hunt connector API (`INTERNAL_HUNT`, `register_hunt_platform`,
  `listen_hunt`, `report_hunt_run`) and stops with an explicit message otherwise.
- A Microsoft Defender XDR tenant (Defender for Endpoint, Office 365, Identity or Cloud Apps feeding advanced hunting),
  and network access to Microsoft Graph (`graph.microsoft.com`) and to Microsoft Entra ID
  (`login.microsoftonline.com`), or their national cloud equivalents.

### Microsoft Entra ID permissions

The account, the least-privilege permissions, the console steps and a configuration example are in [Before you start](#before-you-start).

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

| Parameter | config.yml | Environment variable | Default | Mandatory | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | | Yes | URL of the OpenCTI platform. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | | Yes | Token of the connector user. |
| Connector ID | `connector.id` | `CONNECTOR_ID` | | Yes | A unique UUIDv4 for this connector instance. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `Microsoft Defender Hunt` | No | Name of the connector in OpenCTI. |
| Hunt platform | `connector.scope` | `CONNECTOR_SCOPE` | `microsoft-defender` | No | Hunt platform slug, keep `microsoft-defender`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | `debug`, `info`, `warn` or `error`. |
| Security Platform name | `connector.security_platform_name` | `CONNECTOR_SECURITY_PLATFORM_NAME` | `Microsoft Defender XDR` | No | OpenCTI Security Platform the hunts run against (created when missing). Use one name per tenant. |
| Security Platform type | `connector.security_platform_type` | `CONNECTOR_SECURITY_PLATFORM_TYPE` | `XDR` | No | `SIEM`, `EDR`, `XDR`, `SOAR`, `NDR` or `ISPM`. |
| Concurrent runs | `connector.max_concurrent_runs` | `CONNECTOR_MAX_CONCURRENT_RUNS` | `2` | No | Connector-side limit of concurrent hunt runs, each holding one query on the platform at a time (the platform budget is the minimum of both). Defaults to 2: the advanced hunting call and CPU quotas are shared by the whole tenant. |
| Observable types | `connector.observable_types` | `CONNECTOR_OBSERVABLE_TYPES` | IOC types | No | Observable types the connector may create: `IPv4-Addr`, `IPv6-Addr`, `Domain-Name`, `Url`, `StixFile`, `Email-Addr`, widened with `Hostname`, `User-Account`, `Mac-Addr`. |
| Observables per run | `connector.max_observables` | `CONNECTOR_MAX_OBSERVABLES` | `100` | No | Maximum number of observables created per run (the most frequent first). |
| Tenant ID | `microsoft_defender_hunt.tenant_id` | `MICROSOFT_DEFENDER_HUNT_TENANT_ID` | | Yes | Microsoft Entra tenant ID of the app registration. |
| Client ID | `microsoft_defender_hunt.client_id` | `MICROSOFT_DEFENDER_HUNT_CLIENT_ID` | | Yes | Application (client) ID. |
| Client secret | `microsoft_defender_hunt.client_secret` | `MICROSOFT_DEFENDER_HUNT_CLIENT_SECRET` | | Yes | Client secret of the application. |
| Login URL | `microsoft_defender_hunt.login_url` | `MICROSOFT_DEFENDER_HUNT_LOGIN_URL` | `https://login.microsoftonline.com` | No | `https://login.microsoftonline.us` (US Government L5, DoD). |
| Graph URL | `microsoft_defender_hunt.graph_url` | `MICROSOFT_DEFENDER_HUNT_GRAPH_URL` | `https://graph.microsoft.com` | No | `https://graph.microsoft.us` (US Government L4) or `https://dod-graph.microsoft.us` (US Government L5, DoD). |
| Sigma pipeline | `microsoft_defender_hunt.sigma_pipeline` | `MICROSOFT_DEFENDER_HUNT_SIGMA_PIPELINE` | `microsoft_xdr` | No | pySigma pipeline: `microsoft_xdr` or `none`. |

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-microsoft-defender-hunt:latest
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

At startup the connector registers the `microsoft-defender` hunt platform in OpenCTI with the `kql` language, indicator
hunt support and the Security Platform identity named by `CONNECTOR_SECURITY_PLATFORM_NAME`. Hunts then run on it from
OpenCTI (manually, on schedule, when the threat landscape changes or from playbooks), and their runs appear in the hunt
detail page. A preview run only translates the hunt logic: the translated KQL (or the indicator lookups) is shown in
OpenCTI and advanced hunting is never queried.

## Query languages

The connector executes `kql`.

- **Sigma rules** are translated with the `microsoft_xdr` pipeline, which maps the Sigma categories to the Defender XDR
  tables: `process_creation` to `DeviceProcessEvents`, `image_load` to `DeviceImageLoadEvents`, `file_*` to
  `DeviceFileEvents`, `registry_*` to `DeviceRegistryEvents` and `network_connection` to `DeviceNetworkEvents`. A rule
  of another category (`dns_query`, for instance) does not translate: write a native query for it. When a hunt holds
  several Sigma rules, their queries are combined with `union`.
- **Native queries** written for the `microsoft-defender` platform (language `kql`) are executed verbatim: any tabular
  KQL expression of advanced hunting, starting with a table, a function or a `let` statement. The advanced hunting
  columns a native query references are reported as the matched fields of its hits.

## Indicator hunts

An indicator hunt looks up its values with one advanced hunting query per observable type (by batches of
`limits.ioc_batch_size` values): a fuzzy `union` of the tables that hold the type, each filtered on the run window, so
that a table the tenant does not hold (no Defender for Office 365 license, for instance) is left out instead of failing
the query.

| Observable type | Tables and columns |
|---|---|
| `IPv4-Addr`, `IPv6-Addr` | `DeviceNetworkEvents` (`RemoteIP`, `LocalIP`), `DeviceLogonEvents` and `DeviceEvents` (`RemoteIP`), `DeviceFileEvents` (`FileOriginIP`), `EmailEvents` (`SenderIPv4` / `SenderIPv6`), `AADSignInEventsBeta`, `CloudAppEvents` (`IPAddress`), `IdentityLogonEvents` (`IPAddress`, `DestinationIPAddress`) |
| `Domain-Name` | The domain and its subdomains in `RemoteUrl`, `FileOriginUrl`, `FileOriginReferrerUrl` (device tables), `EmailUrlInfo` (`UrlDomain`), `EmailEvents` (`SenderFromDomain`, `SenderMailFromDomain`) and `UrlClickEvents` (`Url`) |
| `Hostname` | The host itself in `RemoteUrl` (device tables), `EmailUrlInfo` (`UrlDomain`) and `UrlClickEvents` (`Url`) |
| `Url` | The URL within `RemoteUrl`, `FileOriginUrl`, `FileOriginReferrerUrl` (device tables), `EmailUrlInfo` and `UrlClickEvents` (`Url`), case-sensitively |
| `Email-Addr` | `EmailEvents` (`SenderFromAddress`, `SenderMailFromAddress`, `RecipientEmailAddress`) |
| `StixFile` (MD5, SHA-1, SHA-256) | The file and the process that acted (`SHA256` / `InitiatingProcessSHA256`...) in `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceImageLoadEvents`, `DeviceEvents` and `DeviceNetworkEvents`; SHA-256 in `EmailAttachmentInfo` too |

Other types (`Mac-Addr`, `User-Account`, SHA-512 hashes...) are reported not searched. Each value is reported seen
(with its hit count, first and last time and hosts), not seen, or not searched; the hosts of a value are the
`DeviceName` of the events holding it.

## Behavior

1. The query is restricted to the run window with the `Timespan` of the advanced hunting request; a translated Sigma
   rule and the indicator lookups also filter `Timestamp` on the window (a native query is left as written). The query
   is capped with `| take <max_results>` (at most 10,000 rows); when the cap is reached, the total hit count is read
   with a second `| count` query and the run is marked truncated if more events matched.
2. Every call to advanced hunting waits for the quotas of the tenant (45 calls per minute, 1,500 calls per hour), and a
   throttled call (HTTP 429) is sent again after its `Retry-After` delay, within the run timeout. The Microsoft Graph
   token is cached until 5 minutes before it expires.
3. Events matching a benign pattern of the hunt are suppressed.
4. Each hit names its machine (`DeviceName`), its user (`AccountName`, `InitiatingProcessAccountName`,
   `RecipientEmailAddress`, `AccountUpn`), its process (`InitiatingProcessFolderPath`) and its event: the `ReportId`
   of the event within its device (`DeviceId`) or its message (`NetworkMessageId` and recipient), and its time. The
   key of a hit derives from that event id, so it stays the same from one run to the next.
5. With hits, the connector sends one observed-data per public IP address, domain, URL, file hash or email address
   found, with the number of result events holding it, restricted to the observable types the hunt expects. Objects
   inherit the markings and author of the hunt and have deterministic identifiers; those of the observed-data derive
   from the hunt run too, so a retry of a run updates its own objects and two runs never share one. The run reports the
   key of every hit it read: OpenCTI counts the hits it never saw for the hunt and the platform as new, and keeps one
   sighting per technique and indicator of the hunt on the Security Platform, updated in place at each run (`count` =
   distinct hits, `first_seen` / `last_seen` = first and latest hit).
6. The run is reported with the hit count, the distinct hosts, users and network peers, the KQL executed and an
   evidence sample. Raw payload columns (`AdditionalFields`, `RawEventData`) and bookkeeping columns (`ReportId`,
   `DeviceId`, `NetworkMessageId`, `TenantId`, `MachineGroup`...) are never sampled; host names, user names and command
   lines only appear hashed and truncated in the evidence.

No incident is created by the connector: OpenCTI drafts incidents itself when the hits exceed the escalation threshold
of the hunt.

## Quotas and limits

Quotas of the platform, from its vendor documentation:

| Quota | Value | Source |
|---|---|---|
| Per query | 100,000 rows, 64 MB of results and 10 minutes of running time. | [Advanced hunting quotas and usage parameters](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview#quotas-and-usage-parameters) |
| CPU | Allocated per tenant from its size and refreshed every 15 minutes: queries are blocked at 100% until the next cycle. | [Advanced hunting quotas and usage parameters](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-overview#quotas-and-usage-parameters) |
| Calls | At least 45 calls per minute per tenant, depending on its size; the Defender for Endpoint API also states 1,500 calls per hour. The Microsoft Graph page of `runHuntingQuery` states no call rate. | [Advanced hunting API](https://learn.microsoft.com/en-us/defender-xdr/api-advanced-hunting), [Defender for Endpoint advanced hunting API](https://learn.microsoft.com/en-us/defender-endpoint/api/run-advanced-query-api) |

Limits of the connector:

| Limit | Value |
|---|---|
| Results read per query | `limits.max_results` of the run (set by OpenCTI), at most 10,000 rows; the run is marked truncated beyond. |
| Query lookback | The run window, within the 30 days of data advanced hunting keeps. |
| API quotas | 45 calls per minute and 1,500 calls per hour per tenant, spent by the connector at most at that pace; advanced hunting also bounds the running time of the queries of a tenant, and answers 429 beyond. A run that cannot send its next call before its deadline fails with an explicit message. |
| Run timeout | `limits.timeout_seconds` of the run: token requests, quota waits and queries are bounded by the time left, and the run fails as timed out when it expires. |
| Evidence | `limits.evidence_max_items` values, previews truncated to `limits.evidence_max_value_length`. |
| Observables | `CONNECTOR_MAX_OBSERVABLES` per run, IOC types by default, private IP addresses and internal domains never created. |

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Every run logs its reception, capped results and its completion (hits, suppressed
events, objects sent) or failure. Failed runs are reported to OpenCTI with the advanced hunting error message (for
example the syntax error of an invalid query) or the Microsoft Entra authentication error (an `AADSTS` code).

The tests under `tests/live` check the connector on a real tenant, read-only. They are skipped unless
`MICROSOFT_DEFENDER_HUNT_TENANT_ID`, `MICROSOFT_DEFENDER_HUNT_CLIENT_ID` and `MICROSOFT_DEFENDER_HUNT_CLIENT_SECRET`
are set:

```shell
pytest tests/live -s
```

## Additional information

- Advanced hunting holds the Defender XDR tables only: a hunt on Microsoft Sentinel tables (`SecurityEvent`, ASIM
  parsers) runs with the Microsoft Sentinel hunt connector.
- One connector instance executes against one tenant. Deploy one instance (with its own Security Platform name) per
  Microsoft Defender XDR tenant to hunt.
