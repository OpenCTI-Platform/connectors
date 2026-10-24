# OpenCTI CrowdStrike Incidents Connector

Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
  - [Data flow](#data-flow)
  - [STIX 2.1 mapping](#stix-21-mapping)
  - [Incremental collection and resilience](#incremental-collection-and-resilience)
- [Known caveats](#known-caveats)
- [Debugging](#debugging)
- [Additional information](#additional-information)

## Introduction

[CrowdStrike Falcon Next-Gen SIEM](https://www.crowdstrike.com/platform/next-gen-siem/) raises
**alerts** when one of its **correlation rules** matches the logs ingested in the platform.

This connector retrieves these Next-Gen SIEM alerts through the CrowdStrike Falcon **Alerts API**
and imports each of them into OpenCTI as an **Incident**, with:

- the **victim** observables: hosts, IP addresses and user accounts involved;
- the MITRE ATT&CK techniques declared by the correlation rule;
- optionally (`enrich_from_events`), the **threat** observables read from the alert's source event
  in Next-Gen SIEM: the executed file and its hashes, and its execution context.

```
Incident « <rule> (<alert short ID>) »
├── Victim      : Hostname · IPv4/IPv6 (internal and public) · User-Account
├── Threat      : File (name, SHA-256, MD5, SHA-1)            ← enrich_from_events
├── TTP         : Attack-Pattern (MITRE ATT&CK), if declared by the rule
├── Description : alert context (hosts, users, status, priority, detection IDs)
└── Note        : execution context (command line, process chain)  ← enrich_from_events
```

> Next-Gen SIEM alerts only exist when a correlation rule fires. The alert payload only describes
> the affected assets; the threat side (file, hashes, command line) lives in the source event,
> stored in LogScale and read through the LogScale search API.

## Installation

### Requirements

- OpenCTI Platform >= 7.261008.0
- A CrowdStrike Falcon API client (Support and resources > API clients and keys) with the scopes:

  | Scope | Access | Needed for |
  |---|---|---|
  | **Alerts** | Read | Always: retrieving the alerts. Source: [PSFalcon `Get-FalconAlert`](https://github.com/CrowdStrike/psfalcon/blob/master/public/alerts.ps1) ("Requires 'Alerts: Read'"). |
  | **NGSIEM** | **Read and Write** | Only with `enrich_from_events`: reading the source events requires starting a LogScale search (`POST /humio/api/v1/repositories/{repository}/queryjobs`), which is refused with Read only (`403 access denied, scope not permitted`, verified on a tenant). The connector never writes data to Next-Gen SIEM: the Write access is only needed to start searches. |
- The base URL of the CrowdStrike cloud region of the tenant, e.g. `https://api.crowdstrike.com`
  (US-1), `https://api.us-2.crowdstrike.com` (US-2), `https://api.eu-1.crowdstrike.com` (EU-1).

## Configuration variables

The exhaustive, generated list of every parameter is available in
[Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md).

Main parameters (environment variable prefix `CROWDSTRIKE_INCIDENTS_`):

| Parameter            | Default                       | Description                                                                                      |
|----------------------|-------------------------------|--------------------------------------------------------------------------------------------------|
| `api_base_url`       | `https://api.crowdstrike.com` | Base URL of the CrowdStrike API for the tenant's cloud region.                                   |
| `client_id`          | (required)                    | CrowdStrike API client ID.                                                                       |
| `client_secret`      | (required)                    | CrowdStrike API client secret.                                                                   |
| `import_start_date`  | `P7D`                         | How far back to look on the first run (ISO 8601 duration). Ignored once a cursor is stored.      |
| `products`           | `ngsiem`                      | Alert products to import. **Only `ngsiem` is supported**: the configuration schema only allows this value, and any other value is rejected. |
| `severity_min`       | (none)                        | Minimum severity to import: `informational`, `low`, `medium`, `high` or `critical`.              |
| `include_hidden`     | `false`                       | Also import the alerts hidden in the Falcon console.                                             |
| `enrich_from_events` | `false`                       | Enrich each Incident with the threat observables of the alert's source event. Requires the **NGSIEM: Write** scope (see Requirements). |
| `tlp_level`          | `amber+strict`                | TLP marking applied to every created object.                                                    |
| `connector.duration_period` | `PT5M`                 | Interval between two runs.                                                                       |

In-code constants (not configurable):

| Constant   | Value                                     | Notes                                                                 |
|------------|-------------------------------------------|-----------------------------------------------------------------------|
| Page size  | 1000 alerts                               | Maximum of `POST /alerts/combined/alerts/v1`.                         |
| User-Agent | `OpenCTI-CrowdStrike-Incidents-Connector` | Sent on every API call.                                               |
| Auth       | OAuth2 client credentials                 | Token request, refresh and retries are handled by the official [falconpy](https://github.com/CrowdStrike/falconpy) SDK. |
| Event search view | `search-all`                       | LogScale view used for the source events (searching the repositories directly is forbidden). |
| Alerts per event search | 1000                         | One search per page of alerts; LogScale queries are limited to 66 000 characters. |
| Events per alert (search result margin) | 3                | The search returns at most 3 events per alert (search results are capped by `head`). |
| Event search timeout | 300 s, polled every 2 s           | A search not completed in time is stopped; the page is imported without enrichment. |

## Deployment

### Docker Deployment

Build the image, or use the published one:

```shell
docker build . -t opencti/connector-crowdstrike-incidents:latest
```

Fill in the environment variables of `docker-compose.yml`, then:

```shell
docker compose up -d
```

### Manual Deployment

```shell
cp config.yml.sample src/config.yml   # then fill in the values
pip install -r requirements.txt
cd src
python main.py
```

## Usage

The connector runs every `duration_period`. To force an immediate run, go to
**Data management > Ingestion > Connectors**, select the connector and click the refresh button.

To re-import from scratch, reset the connector state from the same page: the next run starts again
from `now - import_start_date`.

## Behavior

### Data flow

```mermaid
flowchart LR
    A[CrowdStrike Alerts API] -->|POST /alerts/combined/alerts/v1<br/>product + updated_timestamp| B[Client - falconpy]
    B -->|pages of alerts, oldest first| C[collect]
    C --> D[transform<br/>alert to Incident + observables]
    L[CrowdStrike LogScale search API] -.->|enrich_from_events<br/>1 search per page| D
    D -->|1 bundle per page| E[send]
    E --> F[OpenCTI]
    E -->|checkpoint updated_timestamp| G[(Connector state)]
```

API reference:

| Step                                          | Endpoint                          | falconpy                      |
|-----------------------------------------------|-----------------------------------|-------------------------------|
| Get alerts (complete payload, 1000 per call)  | `POST /alerts/combined/alerts/v1` | `Alerts.get_alerts_combined`  |
| Start a source events search (`enrich_from_events`) | `POST /humio/api/v1/repositories/search-all/queryjobs` | `NGSIEM.start_search` |
| Poll / stop the search | `GET` / `DELETE /humio/api/v1/repositories/search-all/queryjobs/{id}` | `NGSIEM.get_search_status` / `NGSIEM.stop_search` |

The FQL filter is `product:['ngsiem']+updated_timestamp:>='<cursor>'+show_in_ui:true`, sorted by
`updated_timestamp|asc` (`show_in_ui:true` is dropped when `include_hidden` is enabled). The `ngsiem` product value is documented in CrowdStrike's
[falcon-mcp `detections.py`](https://github.com/CrowdStrike/falcon-mcp/blob/main/falcon_mcp/resources/detections.py).

### STIX 2.1 mapping

Each alert produces one **Incident** and its related objects. Every object is created by the
`CrowdStrike` organization and carries the configured TLP marking.

#### Alert → Incident

| CrowdStrike field                             | OpenCTI Incident        | Notes                                                                                                     |
|-----------------------------------------------|-------------------------|-----------------------------------------------------------------------------------------------------------|
| `display_name`, `composite_id`                | `name`                  | `<rule> (<first 8 characters of the alert ID>)`, e.g. `Obas implants (99284cc7)`. Falls back to `name` for the rule, then to `composite_id`. See below. |
| `description`                                 | `description`           | Followed by a table: hosts, users, product, type, status, priority, priority explanation, detection ID, event IDs. |
| `severity_name`                               | `severity`              | `Informational` and `Low` → `low`, `Medium` → `medium`, `High` → `high`, `Critical` → `critical`.         |
| —                                             | `incident_type`         | Always `alert`.                                                                                           |
| `product`                                     | `source`                | `CrowdStrike Falcon Next-Gen SIEM`.                                                                       |
| `created_timestamp`                           | `created`               |                                                                                                           |
| `start_time` / `end_time`                     | `first_seen` / `last_seen` | Detection window of the correlation rule.                                                              |
| `mitre_attack[].tactic`                       | `labels`                | e.g. `Execution`, `Persistence`.                                                                          |
| `falcon_host_link`, `composite_id`            | External reference      | `source_name` `CrowdStrike Falcon Next-Gen SIEM`, `url` = console link, `external_id` = `composite_id`.   |

**Why this name**: OpenCTI identifies an Incident by its **name and creation date** (its standard
ID is computed from these two fields, whatever STIX ID the connector sends). The name must therefore
be:

- **stable** across alert updates: hosts and users can be added or changed on an existing alert, so
  they are in the description, not in the name. Otherwise an update would create a second Incident;
- **unique** per alert: two alerts of the same rule can share a creation date (to the millisecond).
  The short alert ID keeps them as two Incidents instead of merging them.

An updated alert therefore updates its existing Incident.

#### Related objects

| CrowdStrike field                 | OpenCTI object                          | Relationship (from the Incident) |
|-----------------------------------|-----------------------------------------|----------------------------------|
| `host_names[]`                    | `Hostname` observable                   | `related-to`                     |
| `source_ips[]`                    | `IPv4-Addr` / `IPv6-Addr` observable    | `related-to`                     |
| `users[].user_name`, `users[].sid` (or `user_names[]`) | `User-Account` (`account_login`, `user_id`) | `related-to`. One account per (login, SID) pair: the same login with different SIDs (e.g. local `Administrator` on several hosts) gives distinct accounts. A login from `user_names[]` is only added when no account with a SID has this login. |
| `mitre_attack[].technique_id`, `technique` | `Attack-Pattern`               | `uses`                           |

Attack Patterns are only created for MITRE ATT&CK IDs (`T1234` or `T1234.567`). Their STIX ID only
depends on the MITRE ID, so they **merge with the techniques already imported** by the MITRE ATT&CK
connector instead of creating duplicates. For the same reason they carry **no author and no TLP
marking**: adding the connector's marking to the shared ATT&CK techniques would hide them from users
not cleared for it. The `uses` relationship itself carries the author and the marking.

#### Source event → threat observables (`enrich_from_events`)

Each Next-Gen SIEM alert has a `ngsiem-rule-match-event` in LogScale, keyed by
`Ngsiem.indicator.id` (the last segment of the alert `composite_id`). The connector retrieves the
events of a whole page with a single search:

```
Ngsiem.event.type="ngsiem-rule-match-event"
| in(field="Ngsiem.indicator.id", values=[<up to 1000 IDs>])
| head(limit=<number of IDs>)
```

The search window starts from the oldest detection window (`start_time`) of the page minus one hour:
a source event can predate its alert by days (correlation rule lookback).

| Source event field | OpenCTI | Relationship / notes |
|---|---|---|
| `Vendor.FileName` | `File` name | Incident `related-to` File (threat) |
| `process.hash.sha256`, `process.hash.md5`, `process.hash.sha1` | `File` hashes | Hashes made only of zeros, and malformed hashes (not hexadecimal or wrong length), are dropped (see Known caveats) |
| `Vendor.aip` | `IPv4-Addr` / `IPv6-Addr` | Incident `related-to` IP: public IP of the affected host (victim) |
| `process.command_line` | `Note` on the Incident, "Command line" row | Temporary, see Known caveats |
| `process.executable` | `Note` on the Incident, "Executable" row | |
| `Vendor.GrandParentBaseFileName`, `process.parent.name`, `Vendor.FileName` | `Note` on the Incident, "Process chain" row | e.g. `cmd.exe → powershell.exe → implant.exe` |
| `threat.tactic.name`, `threat.technique.name` | — | Not mapped: names without MITRE ID; the alert provides the IDs when the rule declares them |

No Indicator is created from the file hashes.

The execution context is in a **Note** attached to the Incident, not in the Incident description.
The Note is only sent when the source event is found, and its ID is derived from its content and the
alert creation date. So when an alert is updated while the enrichment is unavailable (failed search,
event out of the LogScale retention), the update does not erase the execution context.

#### Not mapped

`agent_id`, `aggregate_id`, `cid`, `origin_cid`, `correlation_rule_*`, `crawled_timestamp`,
`timestamp`, `seconds_to_resolved`, `seconds_to_triaged`, `show_in_ui`, `poly_id`, `pattern_id`,
`vendor_pattern_id`, `priority_details`, `data_domains`, `source_products`, `source_vendors`,
`source_hosts` (duplicate of `host_names`), `usernames` (duplicate of `user_names`),
`enriched_entities` (always empty on Next-Gen SIEM alerts).

### Incremental collection and resilience

- **Cursor**: `updated_timestamp`. Alerts updated in CrowdStrike after their first import (status
  change, etc.) are fetched again and update the existing Incident.
- **One call per page**: `POST /alerts/combined/alerts/v1` returns complete alerts, so each page is
  a consistent snapshot (no gap between listing IDs and reading details).
- **Pagination without `after` token**: CrowdStrike documents that this endpoint paginates "on live
  data" and that records may appear on several pages, or on none, when sorting on a field that
  changes over time such as `updated_timestamp`. The `after` token is therefore not used. Each page
  is a fresh query from the last `updated_timestamp` seen (the cursor), which excludes the alerts
  already processed **at the cursor timestamp only**:

  ```
  product:['ngsiem'] + (updated_timestamp:>'<cursor>', (updated_timestamp:'<cursor>' + composite_id:![<processed IDs>]))
  ```

  An alert updated during or between runs moves past the cursor and is imported again (its update
  is never dropped), and alerts sharing the cursor timestamp are drained without skipping any, even
  if one of them is updated meanwhile.
- **Boundary alerts**: the IDs of the alerts already processed at the cursor timestamp are stored in
  the state and excluded from the next query at that timestamp, so they are not re-sent at every
  run.
- **Invalid alerts**: an alert without `composite_id` or `updated_timestamp` is skipped with a
  warning naming it; the other alerts of the page are imported.
- **Checkpoint after every bundle**: the cursor is saved after each page is sent to OpenCTI, so a
  crash during a large backlog resumes where it stopped instead of restarting.
- **Per-alert failures**: an alert that cannot be parsed or converted is logged and skipped; the
  cursor still moves past it.
- **Lenient parsing**: blank or `null` values (host names, IPs, users) are ignored instead of
  dropping the whole alert.
- **API errors**: a non-success response stops the run with an explicit error (a `403` mentions the
  `Alerts: Read` scope); the next scheduled run retries from the last saved cursor.
- **Source events search failures** (`enrich_from_events`): enrichment is best effort. When the
  search fails (e.g. `403` without the NGSIEM: Write scope), is cancelled or times out, the Incidents of the page
  are still created with their victim observables, and a warning is logged. Alerts whose source event
  is not found are imported without threat observables.
- **State reset**: resetting the connector state in OpenCTI clears the cursor, even while the
  connector is running (the connectors-sdk only overwrites the keys present in the stored state; the
  connector resets its own fields first).

## Known caveats

- **Only Next-Gen SIEM alerts are supported.** Other Alerts API products (`epp`, `idp`, `xdr`, ...)
  have a different payload (devices, files, hashes) and are ignored, even if configured.
- **Checkpointing deviates from the connectors-sdk rule** that processors must not call
  `state.save()`: it is needed to resume large backlogs.
- **falconpy is used instead of the connectors-sdk `BaseClientApi`**: the official SDK handles the
  OAuth2 flow, token refresh and cloud regions.
- **Observables describe the affected internal assets**, not threat indicators: host names, private
  IP addresses and machine accounts (e.g. `HOST$`) are common.
- **Renaming a correlation rule creates new Incidents**: the rule name is part of the Incident name,
  which OpenCTI uses (with the creation date) to identify it. Alerts updated after the rename get a
  new Incident. A stable identity key in the connectors-sdk models would remove this limit.
- **More than 5 000 alerts sharing the exact same `updated_timestamp`** cannot be paginated (the
  exclusion list would be too long): the run fails with an explicit error.
- **Alerts updated during a run are sent twice** (harmless upsert): once at their old position,
  once at their new `updated_timestamp`.
- **Hidden alerts filter not verified live**: `include_hidden: false` filters on `show_in_ui:true`
  (falconpy documents `show_in_ui: false` as "This alert is not displayed in Falcon"); the test
  tenant had no hidden alert to confirm it.
- **Unknown severities are always imported**, even when `severity_min` is set.
- **Alert retention**: alerts older than the CrowdStrike retention period (about 90 days observed)
  cannot be imported, whatever `import_start_date` is.
- **No MITRE technique** is attached to an alert when its correlation rule does not declare any.
- **`enrich_from_events` requires a Write scope** (NGSIEM: Write) for a connector that only imports
  data: CrowdStrike requires it to start a LogScale search. It is therefore disabled by default.
- **Placeholder hashes are dropped**: CrowdStrike sends hashes made only of zeros when it did not
  compute them (an all-zero SHA-1 is common). OpenCTI matches Files on any of their hashes, so sending
  this shared placeholder merged unrelated binaries into a single File during tests. Only the
  placeholder value is dropped: the File is still created with its real hashes.
- **Command line and process chain are in a Note, not in observables**: the connectors-sdk has no
  `Process` observable model yet
  ([#7968](https://github.com/OpenCTI-Platform/connectors/issues/7968)). They will move to a `Process`
  observable once the model exists.
- **Command lines are imported verbatim** and may contain secrets passed as arguments (tokens,
  passwords), which then appear in the execution context Note.
- **Source events of other event types**: the threat mapping was validated on process events
  (`ProcessRollup2`); correlation rules on other event types (network, DNS, e-mail) may expose fields
  that are not mapped yet.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. Each run logs the cursor it starts from, the number of alerts
fetched per page, and every skipped alert with its `composite_id`.

## Additional information

Out of scope for this version:

- Alerts of products other than `ngsiem`.
- CrowdStrike **Cases** (Incident Response Cases in OpenCTI): the Cases API requires another scope.
- Writing back to CrowdStrike (alert status, comments).

Possible improvements:

- Optional creation of **Indicators** (IoCs) from the threat observables (file hashes).
- Move the command line and process chain to a **`Process` observable** once available in the
  connectors-sdk ([#7968](https://github.com/OpenCTI-Platform/connectors/issues/7968)).
- **Mask secrets** passed as command line arguments (e.g. `--token`, `--password`).
- Map the threat fields of source events of other types (network, DNS, e-mail).

This connector supersedes the proof of concept of
[#7523](https://github.com/OpenCTI-Platform/connectors/pull/7523). Issue:
[#3039](https://github.com/OpenCTI-Platform/connectors/issues/3039).
