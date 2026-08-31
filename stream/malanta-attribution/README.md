# OpenCTI Malanta Attribution Connector

| Status    | Date | Comment |
|-----------|------|---------|
| Community | -    | -       |

Derives Intrusion Sets and `indicates` relationships from the `apt:` attribution labels Malanta places on indicators.

## Table of Contents

- [OpenCTI Malanta Attribution Connector](#opencti-malanta-attribution-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Step 1 — Create the live stream](#step-1--create-the-live-stream)
    - [Step 2 — Start the connector](#step-2--start-the-connector)
    - [Step 3 — Configure the TAXII ingester](#step-3--configure-the-taxii-ingester)
    - [Leave "Import from date" empty in production](#leave-import-from-date-empty-in-production)
    - [Backfilling existing indicators](#backfilling-existing-indicators)
  - [Usage](#usage)
  - [Behavior](#behavior)
    - [What it creates](#what-it-creates)
    - [What it deliberately does not do](#what-it-deliberately-does-not-do)
    - [Feedback-loop safety](#feedback-loop-safety)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

Malanta publishes pre-attack infrastructure intelligence over TAXII 2.1. OpenCTI's
built-in TAXII ingester imports that feed correctly and needs no custom code — but it
applies no transformation. Threat-actor attribution therefore arrives as flat label
strings on indicators:

```json
"labels": ["IOC", "apt:APT38", "domain", "source:lazarus.day", "redistributed-by:malanta"]
```

A label is not pivotable. Analysts cannot navigate from an actor to its infrastructure,
and nothing links `apt:APT38` on one indicator to the same actor on another.

This connector closes that gap. It listens to the OpenCTI event stream and, for each
**Malanta** indicator carrying an `apt:` label, creates the matching **Intrusion Set** and an
**`indicates`** relationship from the indicator to it.

Provenance is checked on every event: indicators authored by another source are skipped, so
a second feed using the same `apt:` convention is never attributed to Malanta. The source is
configurable via `MALANTA_ATTRIBUTION_SOURCE_AUTHOR`.

It is designed to run **alongside** OpenCTI's native TAXII ingestion, not to replace it:
the platform handles the bulk import, pagination, watermark and backpressure, while this
connector only reacts to the small share of indicators that carry attribution.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- The Malanta TAXII feed ingested into OpenCTI (see [Step 3](#step-3--configure-the-taxii-ingester))
- A live stream configured in OpenCTI

## Configuration variables

Configuration is set either in `docker-compose.yml` (for Docker) or in `config.yml` (for
manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                                    |
|---------------|------------|-----------------------------|-----------|----------------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                               |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | Token of a user allowed to write knowledge. A dedicated connector user is recommended over the admin token. |

### Base connector environment variables

| Parameter                   | config.yml                  | Docker environment variable            | Default              | Mandatory | Description                                                                 |
|-----------------------------|-----------------------------|----------------------------------------|----------------------|-----------|-----------------------------------------------------------------------------|
| Connector ID                | id                          | `CONNECTOR_ID`                         |                      | Yes       | A unique `UUIDv4` identifier for this connector instance.                   |
| Connector Name              | name                        | `CONNECTOR_NAME`                       | Malanta Attribution  | No        | Name of the connector.                                                      |
| Connector Scope             | scope                       | `CONNECTOR_SCOPE`                      | indicator            | No        | Entity types processed by the connector.                                    |
| Log Level                   | log_level                   | `CONNECTOR_LOG_LEVEL`                  | error                | No        | Verbosity of the logs: `debug`, `info`, `warn`, or `error`.                 |
| Live Stream ID              | live_stream_id              | `CONNECTOR_LIVE_STREAM_ID`             |                      | Yes       | ID of the live stream created in the OpenCTI UI.                            |
| Live Stream Listen Delete   | live_stream_listen_delete   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`  | false                | No        | Listen for delete events. Off by default: this connector only adds attribution. |
| Live Stream No Dependencies | live_stream_no_dependencies | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES`| true                 | No        | Ignore dependencies when processing stream events.                          |

### Connector extra parameters environment variables

| Parameter             | config.yml            | Docker environment variable                    | Default     | Mandatory | Description                                                                                          |
|-----------------------|-----------------------|------------------------------------------------|-------------|-----------|------------------------------------------------------------------------------------------------------|
| Label Prefix          | label_prefix          | `MALANTA_ATTRIBUTION_LABEL_PREFIX`             | `apt:`      | No        | Label namespace treated as attribution. Labels without this prefix are ignored.                       |
| Actor Separators      | actor_separators      | `MALANTA_ATTRIBUTION_ACTOR_SEPARATORS`         | `,`         | No        | Characters splitting several actors inside one label (see [Behavior](#behavior)).                     |
| Author Name           | author_name           | `MALANTA_ATTRIBUTION_AUTHOR_NAME`              | `Malanta.ai`| No        | Organization credited with the derived objects. Keep identical to the feed's author so they merge.    |
| Author Description    | author_description    | `MALANTA_ATTRIBUTION_AUTHOR_DESCRIPTION`       |             | No        | Optional description for that organization.                                                           |
| Source Author         | source_author         | `MALANTA_ATTRIBUTION_SOURCE_AUTHOR`            | `Malanta.ai`| No        | Only process indicators authored by this organization. Prevents crediting another feed's `apt:` labels to Malanta. Empty string processes every source. |
| Create Intrusion Sets | create_intrusion_sets | `MALANTA_ATTRIBUTION_CREATE_INTRUSION_SETS`    | true        | No        | Create the Intrusion Set when absent. Disable to emit relationships only.                             |
| Minimum Confidence    | min_confidence        | `MALANTA_ATTRIBUTION_MIN_CONFIDENCE`           | 0           | No        | Skip indicators below this confidence. `0` processes everything.                                      |

## Deployment

> ### ⚠️ Order matters: start the connector **before** the ingester
>
> This connector reacts to OpenCTI's live event stream. Indicators that are already in the
> platform when it starts generate **no events**, so they receive **no attribution** — even
> though they carry `apt:` labels.
>
> Deploy in this order and the problem never arises:
>
> | | Step |
> |---|---|
> | **1** | [Create the live stream](#step-1--create-the-live-stream) |
> | **2** | [Start this connector](#step-2--start-the-connector) |
> | **3** | [Configure the TAXII ingester](#step-3--configure-the-taxii-ingester) |
>
> Every indicator the ingester pulls then flows past the connector live, and no backfill is
> needed.
>
> **If you have already ingested the feed**, that is recoverable — run
> [`backfill.py`](#backfilling-existing-indicators) once and the existing indicators get their
> attribution.

### Step 1 — Create the live stream

In **Data → Data Sharing → Live Streams**, create a stream and copy its ID into
`CONNECTOR_LIVE_STREAM_ID`.

Filter the stream to `Indicator` entities, and — if you ingest several feeds into the same
platform — to those authored by the Malanta organization. Both filters are performance
optimisations that stop the connector being woken for events it would discard anyway.

> Correctness does not depend on them. The connector independently checks each indicator's
> author against `MALANTA_ATTRIBUTION_SOURCE_AUTHOR` and skips anything from another source,
> so a missing stream filter costs throughput, not accuracy.

### Step 2 — Start the connector

#### Docker

Build the image locally if needed:

```shell
docker build . -t opencti/connector-malanta-attribution:latest
```

Set the environment variables in `docker-compose.yml`, then:

```shell
docker compose up -d
```

#### Manual

Copy `config.yml.sample` to `config.yml` and fill it in, then:

```shell
cd src
pip3 install -r requirements.txt
python3 main.py
```

### Step 3 — Configure the TAXII ingester

With the connector already listening, configure the platform's built-in TAXII ingester —
**Data → Ingestion → TAXII feeds → `+`**:

| Field                    | Value                                             |
|--------------------------|---------------------------------------------------|
| Name                     | `Malanta Pre-Attack Indicators`                   |
| TAXII server URL         | `https://app.malanta.ai/feeds/taxii2/default`     |
| TAXII version            | `TAXII 2.1`                                       |
| TAXII Collection         | `pre-attack-indicators`                           |
| Authentication type      | `Bearer token`                                    |
| Token                    | your Malanta API key                              |
| Import from date         | **leave empty in production** — see below         |

> The connector never contacts Malanta and never needs the API key. That credential stays
> in the ingester configuration, where OpenCTI encrypts it at rest.

#### Leave "Import from date" empty in production

Setting a date bounds the import to objects modified since then. That is useful for a quick
trial, but it produces an **incomplete graph**, because the feed's three object streams are
filtered independently.

If you must bound the import — for a phased rollout, or while sizing the platform — treat it
as provisional and **re-run unbounded afterwards** to complete the graph. Re-ingestion is
safe: all ids are deterministic, so a second pass upserts rather than duplicating. Run
`backfill.py` (see below) afterwards so the newly-arrived indicators get their attribution.

### Backfilling existing indicators

The connector reacts to live stream events, so indicators that were already in OpenCTI when
it started produce no events and therefore no attribution. Starting the connector **before**
the ingester avoids this entirely and is the recommended order.

When that ordering was not followed — or after the connector was stopped for a while, or
after re-running a previously bounded import — `src/backfill.py` repairs the gap:

```shell
cd src
export OPENCTI_URL=http://localhost:8080
export OPENCTI_TOKEN=<token>

python3 backfill.py --dry-run   # report what would be created, write nothing
python3 backfill.py             # apply
```

It pages every indicator in the platform, skips those authored by another source, parses
`apt:` labels with the connector's own parser, and emits attribution through the same
converter. Backfilled objects are therefore identical to ones produced live — same
deterministic ids, same author, same inherited markings and confidence — so **re-running it
is a no-op**.

| Option | Default | Description |
|---|---|---|
| `--dry-run` | off | Report what would be created without writing. |
| `--label-prefix` | `apt:` | Must match `MALANTA_ATTRIBUTION_LABEL_PREFIX`. |
| `--actor-separators` | `,` | Must match `MALANTA_ATTRIBUTION_ACTOR_SEPARATORS`. |
| `--author-name` | `Malanta.ai` | Must match `MALANTA_ATTRIBUTION_AUTHOR_NAME`, or derived objects will not merge. |
| `--source-author` | `Malanta.ai` | Must match `MALANTA_ATTRIBUTION_SOURCE_AUTHOR`. Empty string backfills every source. |

## Usage

The connector runs continuously. After deployment it reacts to indicator events within
seconds; there is no scheduling to configure.

## Behavior

### What it creates

For an indicator carrying `apt:APT38`:

1. An **Intrusion Set** named `APT38`, and
2. An **`indicates`** relationship, `Indicator → Intrusion Set`.

Both use deterministic IDs (`pycti.IntrusionSet.generate_id`,
`pycti.StixCoreRelationship.generate_id`), so replaying the stream upserts rather than
duplicates. Derived objects inherit the indicator's `confidence` and `object_marking_refs`
so they are never less restricted than their source.

Three quirks of the live feed are handled:

- **Comma-joined tokens.** `apt:APT17,APT5` is split into two actors. Those actors usually
  also appear as their own tokens on the same object, so results are de-duplicated.
- **Names containing spaces.** `apt:Earth Lusca` stays one actor; whitespace is never a
  separator.
- **Inconsistent casing.** `apt:turla` and `apt:Turla` resolve to one Intrusion Set. The
  first spelling seen is kept for display.

### What it deliberately does not do

- **It does not attribute Malanta's infrastructure clusters.** The feed emits its own
  intrusion sets representing infrastructure clusters, with opaque names, plus `indicates`
  relationships from indicators to them. An `apt:` label on an indicator pointing at a
  cluster does *not* make that cluster the actor — a cluster may aggregate infrastructure
  from several actors. Attribution is applied to indicators only, and cluster entities are
  left exactly as ingested.
- **It does not merge aliases.** `APT44` and `Sandworm` remain separate Intrusion Sets
  until an analyst merges them in OpenCTI.
- **It does not revoke attribution.** Delete events are ignored by default; removing a
  label upstream does not remove the relationship.

### Feedback-loop safety

The connector emits only Intrusion Sets and relationships, reacts only to `indicator`
events, and never modifies the indicator that triggered it. Its own writes therefore
cannot re-trigger it.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` to log every skipped indicator and the reason.

| Symptom                              | Likely cause                                                                                   |
|--------------------------------------|------------------------------------------------------------------------------------------------|
| No attribution appears               | Stream filter excludes indicators; or the indicators genuinely carry no `apt:` labels.          |
| Nothing is attributed at all         | `MALANTA_ATTRIBUTION_SOURCE_AUTHOR` does not match the indicators' author, so every event is skipped as "another source". Check the feed's author name in **Data → Entities → Organizations**. Run at `debug` to see the comparison. |
| Clusters show very few indicators    | `Import from date` was set, so most indicators fall outside the window. See [above](#leave-import-from-date-empty-in-production). |
| Only recent indicators are attributed| Indicators ingested before the connector started produce no stream events. Run [`backfill.py`](#backfilling-existing-indicators). |
| `Missing stream ID`                  | `CONNECTOR_LIVE_STREAM_ID` unset or left at `ChangeMe`.                                          |
| Intrusion Sets appear unattributed   | `MALANTA_ATTRIBUTION_AUTHOR_NAME` differs from the feed's author, so the identities do not merge. |

## Additional information

Only a share of Malanta's indicators carry attribution labels; the connector is a no-op
for the rest, which is why it can sit in front of a very large feed without becoming a
bottleneck.
