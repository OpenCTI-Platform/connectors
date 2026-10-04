# OpenCTI Cloudflare Rules List Connector

A **STREAM** connector that pushes **IPv4** threat-intelligence indicators and
observables from OpenCTI into a
[Cloudflare Rules List](https://developers.cloudflare.com/waf/tools/lists/),
where they can be referenced from WAF custom rules, firewall rules, and other
Cloudflare security configurations.

## Table of Contents

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
- [Behavior](#behavior)
  - [Dissemination assurance (deployment write-back)](#dissemination-assurance-deployment-write-back)
- [Capabilities and limitations](#capabilities-and-limitations)
- [Development](#development)

## Introduction

Cloudflare Rules Lists are reusable collections of IP addresses scoped to a
Cloudflare account. This connector subscribes to an OpenCTI live stream and
keeps a target Rules List (of **IP** kind) in sync with the IPv4 indicators and
`IPv4-Addr` observables known to OpenCTI.

Cloudflare's list-items API follows a **replace/snapshot** model: each upload
replaces the full contents of the list. The connector therefore maintains an
in-memory snapshot of all known IPv4 values and pushes the complete snapshot at
most once per `CLOUDFLARE_SYNC_INTERVAL`.

## Requirements

- OpenCTI Platform 7.x. The connector pins `pycti==7.260803.0`; because pycti
  follows the platform's CalVer scheme, its major version must match your
  OpenCTI platform. Align the pin with your platform version if it differs.
- A Cloudflare account and an existing Rules List of **IP** kind
- A Cloudflare API token with the `Account > Account Filter Lists > Edit`
  permission
- Python 3.11 or 3.12 (for local runs; the SDK requires `< 3.13`)

## Configuration variables

Configuration is read (in precedence order) from environment variables, then a
`config.yml` or `.env` file next to the connector, then field defaults.

### OpenCTI configuration

| Parameter     | config.yml      | Docker env var   | Mandatory | Description                              |
| ------------- | --------------- | ---------------- | --------- | ---------------------------------------- |
| OpenCTI URL   | `opencti.url`   | `OPENCTI_URL`    | Yes       | The base URL of the OpenCTI instance.    |
| OpenCTI Token | `opencti.token` | `OPENCTI_TOKEN`  | Yes       | The API token to connect to OpenCTI.     |

### Base connector configuration

| Parameter          | config.yml                   | Docker env var               | Default               | Mandatory | Description                                                                 |
| ------------------ | ---------------------------- | ---------------------------- | --------------------- | --------- | --------------------------------------------------------------------------- |
| Connector ID       | `connector.id`               | `CONNECTOR_ID`               | /                     | Yes       | A unique `UUIDv4` identifier for this connector instance.                    |
| Connector Name     | `connector.name`             | `CONNECTOR_NAME`             | `Cloudflare Rules List` | No      | Name of the connector as shown in OpenCTI.                                  |
| Connector Scope    | `connector.scope`            | `CONNECTOR_SCOPE`            | `cloudflare`          | No        | The scope of the stream connector (comma-separated).                        |
| Log Level          | `connector.log_level`        | `CONNECTOR_LOG_LEVEL`        | `error`               | No        | `debug`, `info`, `warn`, `warning`, or `error`.                             |
| Live Stream ID     | `connector.live_stream_id`   | `CONNECTOR_LIVE_STREAM_ID`   | /                     | Yes       | The ID of the OpenCTI live stream to connect to (e.g. `live`).              |
| Listen Delete      | `connector.live_stream_listen_delete` | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` | `true` | No | Whether to receive delete events from the live stream. Must be `true` for the connector to drop removed IPs from the list. |
| No Dependencies    | `connector.live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `true` | No | Whether to ignore object dependencies when processing live-stream events.   |

### Cloudflare configuration

| Parameter            | config.yml             | Docker env var          | Default | Mandatory | Description                                                            |
| -------------------- | ---------------------- | ----------------------- | ------- | --------- | --------------------------------------------------------------------- |
| Account ID           | `cloudflare.account_id`| `CLOUDFLARE_ACCOUNT_ID` | /       | Yes       | Cloudflare account ID that owns the Rules List.                       |
| API Token            | `cloudflare.api_token` | `CLOUDFLARE_API_TOKEN`  | /       | Yes       | API token with `Account > Account Filter Lists > Edit` permission.    |
| List ID              | `cloudflare.list_id`   | `CLOUDFLARE_LIST_ID`    | /       | Yes       | ID of the existing Rules List (IP kind) to sync into.                 |
| API Base URL         | `cloudflare.api_base_url` | `CLOUDFLARE_API_BASE_URL` | `https://api.cloudflare.com/client/v4` | No | Base URL of the Cloudflare API. Override only for testing or a compatible gateway. |
| Sync Interval        | `cloudflare.sync_interval` | `CLOUDFLARE_SYNC_INTERVAL` | `PT1H` | No     | Minimum interval between snapshot uploads (ISO-8601 duration: `PT30M`, `PT1H`, `PT1H30M`, etc.). |

> The Rules List must already exist and be of **IP** kind. Create it under
> Cloudflare → Manage Account → Configurations → Lists, then copy its ID.

## Deployment

### Docker Deployment

Build the image and start the container:

```shell
docker compose up -d
# -or, if you've made local changes-
docker compose up -d --build
```

### Manual Deployment

Create a `config.yml` from the sample, fill in your values, then:

```shell
cd src
pip install -r requirements.txt
python main.py
```

`git` must be available when installing requirements because `connectors-sdk` is
fetched from its repository.

## Behavior

1. **Verify** the configured Cloudflare Rules List exists (and log its kind).
2. **Full sync** on startup: load all IPv4 indicators and `IPv4-Addr`
   observables from OpenCTI into an in-memory snapshot, then immediately push
   that snapshot to Cloudflare. When a listing fails or Cloudflare rejects the
   snapshot, the next live-stream events retry the full sync (at most once per
   `CLOUDFLARE_SYNC_INTERVAL`) until it succeeds.
3. **Listen** to the OpenCTI live stream — cache IPv4 values on create/update,
   drop them on delete.
4. **Replace** the entire Cloudflare list with the current snapshot, then poll
   the resulting bulk operation to completion. This push is triggered by
   live-stream events and throttled to **at most once per
   `CLOUDFLARE_SYNC_INTERVAL`** — an idle stream produces no uploads even after
   the interval elapses.

IPv4 values are extracted from three shapes: STIX indicators with an
`[ipv4-addr:value = '...']` pattern, STIX SCOs with `type: "ipv4-addr"`, and
OpenCTI observables with `entity_type: "IPv4-Addr"`.

Each entry written to the Cloudflare list is tagged with a comment of the form
`OpenCTI: <id>`, recording the STIX id of the source OpenCTI object (the same id
for the startup full sync and the live stream; the internal id for an API object
without one).

### Dissemination assurance (deployment write-back)

The connector reports to OpenCTI whether each IPv4 indicator is actually in the Cloudflare Rules List. The status is
stored on the `deployed-on` relationship between the indicator and the `Cloudflare` Security Platform entity (created
if it does not exist). `IPv4-Addr` observables are pushed as before and not reported.

| When                                      | Reported to OpenCTI                                                                                   |
|-------------------------------------------|-------------------------------------------------------------------------------------------------------|
| Snapshot uploaded                         | `deployed` for the indicators added or whose IP changed since the previous upload                     |
| Snapshot rejected by Cloudflare           | `failed` for those indicators, with a short reason such as "Cloudflare refused the list update: permission denied" (the Cloudflare response is written to the connector log); they are retried with the next upload |
| Snapshot uploaded without an indicator    | `removed` for the indicators of the previous upload dropped by a delete event, or by an update that revokes them or leaves them without an IPv4 value (when the last object is dropped, an empty snapshot clears the list) |
| Reconciliation, indicator present         | `active`, with the Cloudflare list item id as external id                                             |
| Reconciliation, indicator absent          | `removed` (deleted from the list outside of OpenCTI); the next upload restores the item and reports the indicator `deployed` again |
| Reconciliation, `pending` (analyst retry) | The indicator is added to the snapshot, uploaded and reported `deployed` or `failed`                  |
| Reconciliation, withdrawal or expiry      | Revoked, expired or withdrawn indicators still listed are deleted from the list and reported `removed`; the ones already absent are reported `removed` and dropped from the snapshot, so no upload restores them |
| Reconciliation, unknown indicator         | Items whose comment carries the STIX id of an indicator with no deployment are reported `active` (backfill) |

- **Reconciliation**: every `DEPLOYMENT_RECONCILIATION_INTERVAL` minutes, the items of the list are read back (cursor
  pagination). Deployments are matched by the OpenCTI id of the item comment when it is a STIX indicator id, by item
  id, then by IP address. A read-back error, a cursor repeated by the API or a malformed item (not an object, or
  without IP address or id) skips the run: indicators are never reported `removed` from a partial listing.
- **Withdrawal safety**: a withdrawal deletes the list item (`DELETE /rules/lists/{id}/items`, never an empty snapshot)
  only when it belongs to the indicator, and drops the indicator from the snapshot.
- **Shared IP addresses**: a Cloudflare list holds an IP address once, so the objects sharing an address are uploaded
  as one item whose comment names the first indicator holding it (else the first observable). The reconciliation
  confirms every indicator of the snapshot holding the address of an item, and a withdrawal keeps an item another
  object still holds: the snapshot without the withdrawn indicator is uploaded instead.
- **Startup**: the initial full sync reads every IPv4 indicator and observable from OpenCTI and always uploads its
  snapshot, even an empty one, so the items a previous run left in the list are cleared. It succeeds once Cloudflare
  accepts the snapshot. When a listing fails, nothing is uploaded and the list keeps its items; when Cloudflare
  rejects the snapshot, the indicators are reported `failed`. Until a full sync succeeds, every stream event retries
  it (at most once per `CLOUDFLARE_SYNC_INTERVAL`) instead of uploading a snapshot of the stream objects alone, and
  the reconciliation starts once it succeeds.
- **Hits**: not reported. Hits of a list are the firewall events of the rules referencing it, which the connector does
  not manage.
- **IOC validation requests**: OpenAEV runs the benign validation tests requested in OpenCTI and writes their results;
  the requests only target indicators this connector reports `deployed` or `active`. The two analyst requests carried by
  a deployment are handled by the reconciliation: a retry (`pending`) uploads the indicator again, a withdrawal deletes
  its list item.
- **Graceful degradation**: on OpenCTI platforms without the deployment write-back API the feature is a no-op (logged
  once). Write-back errors are logged as warnings and never block the dissemination.

#### What you see in OpenCTI

The [Deployments tabs](https://docs.opencti.io/latest/usage/dissemination-assurance/#viewing-deployments) of an
indicator and of the `Cloudflare` Security Platform show one row per IPv4 indicator, with its status and the time of
the last report (no hit count: the firewall events belong to the rules using the list).

- A `failed` deployment shows the reason the connector reported, for example "Cloudflare refused the list update:
  permission denied" or "Cloudflare did not complete the list update in time"; the HTTP status and the Cloudflare
  response are in the connector log.
- **Deploy again** sets the deployment to `pending`: the next reconciliation adds the indicator to the snapshot,
  uploads it and reports `deployed` or `failed`.
- **Remove from this platform** withdraws the indicator: the next reconciliation deletes its list item, unless another
  object holds the same address, and reports it `removed`.

| Environment variable                 | Default      | Description                                                                   |
|--------------------------------------|--------------|-------------------------------------------------------------------------------|
| `DEPLOYMENT_REPORTING_ENABLED`       | `true`       | Report the deployment status of the uploaded indicators.                      |
| `DEPLOYMENT_RECONCILIATION_INTERVAL` | `60`         | Minutes between two reconciliations, `0` disables the reconciliation.         |
| `SECURITY_PLATFORM_NAME`             | `Cloudflare` | Name of the Security Platform entity in OpenCTI.                              |
| `SECURITY_PLATFORM_TYPE`             |              | Type of the Security Platform entity (`security_platform_type_ov`), optional. |
| `SECURITY_PLATFORM_ID`               |              | Id of an existing Security Platform entity, used instead of the name.         |

## Capabilities and limitations

- **IPv4 only.** IPv6 addresses, domains, URLs, file hashes, and every other
  indicator/observable type are ignored. Indicators match only when their STIX
  pattern is `[ipv4-addr:value = '...']` (a single address, or a CIDR inside the
  quotes); compound patterns contribute only their first IPv4 value.
- **No built-in score, label, confidence, or marking filtering.** Every IPv4 the
  connector sees is pushed to the list. To restrict *which* entities reach the
  connector, scope the OpenCTI **live stream definition** (e.g. by score or
  labels) — the connector itself applies no filtering.
- **The startup full sync is not stream-filtered.** It loads *all* IPv4
  indicators and `IPv4-Addr` observables from the platform via the OpenCTI API,
  regardless of the live stream's filters. Only the incremental live updates
  honor the stream definition, so a filtered stream and the full sync can
  disagree on what belongs in the list.
- **State is in-memory.** The snapshot is rebuilt by a full sync on every
  restart; nothing is persisted locally.
- **Removals happen on delete events and withdrawals.** A revoked or expired indicator is
  dropped from the list when its delete event arrives, which requires
  `CONNECTOR_LIVE_STREAM_LISTEN_DELETE=true`, or when the deployment reconciliation withdraws it.
- **The Cloudflare list is owned by the connector.** Because each sync *replaces*
  the entire list, any items added to it outside the connector are overwritten on
  the next push. Use a dedicated list.

## Development

Run the test suite (requires Python 3.11/3.12):

```shell
pip install -r tests/test-requirements.txt pytest-cov
pytest tests/ --cov=cloudflare_rules_list --cov-report=term-missing
```

`pytest-cov` is installed explicitly above (it is intentionally not listed in
`tests/test-requirements.txt`).
