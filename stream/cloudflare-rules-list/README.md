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
most once per `CONNECTOR_SYNC_INTERVAL`.

## Requirements

- OpenCTI Platform 7.x. The connector pins `pycti==7.260715.0`; because pycti
  follows the platform's CalVer scheme, its major version must match your
  OpenCTI platform. Align the pin with your platform version if it differs.
- A Cloudflare account and an existing Rules List of **IP** kind
- A Cloudflare API token with the `Account > Account Filter Lists > Edit`
  permission
- Python 3.11 or 3.12 (for local runs; the SDK requires `< 3.13`)

## Configuration variables

Configuration is read (in precedence order) from environment variables, then a
`config.yml` or `.env` file next to the connector, then field defaults.

A full, generated reference is available in
[`__metadata__/CONNECTOR_CONFIG_DOC.md`](__metadata__/CONNECTOR_CONFIG_DOC.md).

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
| Sync Interval      | `connector.sync_interval`    | `CONNECTOR_SYNC_INTERVAL`    | `1h`                  | No        | Minimum interval between snapshot uploads (`30m`, `1h`, `1h30m`, seconds).  |

### Cloudflare configuration

| Parameter            | config.yml             | Docker env var          | Default | Mandatory | Description                                                            |
| -------------------- | ---------------------- | ----------------------- | ------- | --------- | --------------------------------------------------------------------- |
| Account ID           | `cloudflare.account_id`| `CLOUDFLARE_ACCOUNT_ID` | /       | Yes       | Cloudflare account ID that owns the Rules List.                       |
| API Token            | `cloudflare.api_token` | `CLOUDFLARE_API_TOKEN`  | /       | Yes       | API token with `Account > Account Filter Lists > Edit` permission.    |
| List ID              | `cloudflare.list_id`   | `CLOUDFLARE_LIST_ID`    | /       | Yes       | ID of the existing Rules List (IP kind) to sync into.                 |
| API Base URL         | `cloudflare.api_base_url` | `CLOUDFLARE_API_BASE_URL` | `https://api.cloudflare.com/client/v4` | No | Base URL of the Cloudflare API. Override only for testing or a compatible gateway. |

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
   that snapshot to Cloudflare.
3. **Listen** to the OpenCTI live stream — cache IPv4 values on create/update,
   drop them on delete.
4. **Replace** the entire Cloudflare list with the current snapshot, then poll
   the resulting bulk operation to completion. This push is triggered by
   live-stream events and throttled to **at most once per
   `CONNECTOR_SYNC_INTERVAL`** — an idle stream produces no uploads even after
   the interval elapses.

IPv4 values are extracted from three shapes: STIX indicators with an
`[ipv4-addr:value = '...']` pattern, STIX SCOs with `type: "ipv4-addr"`, and
OpenCTI observables with `entity_type: "IPv4-Addr"`.

Each entry written to the Cloudflare list is tagged with a comment of the form
`OpenCTI: <id>`, recording the source OpenCTI object ID.

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
- **Removals happen on delete events only.** A revoked or expired indicator is
  dropped from the list when its delete event arrives, which requires
  `CONNECTOR_LIVE_STREAM_LISTEN_DELETE=true`.
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
