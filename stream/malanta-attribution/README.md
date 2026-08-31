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
    - [Prerequisite: ingest the Malanta feed](#prerequisite-ingest-the-malanta-feed)
    - [Prerequisite: create the live stream](#prerequisite-create-the-live-stream)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
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

This connector closes that gap. It listens to the OpenCTI event stream and, for every
indicator carrying an `apt:` label, creates the matching **Intrusion Set** and an
**`indicates`** relationship from the indicator to it.

It is designed to run **alongside** OpenCTI's native TAXII ingestion, not to replace it:
the platform handles the bulk import, pagination, watermark and backpressure, while this
connector only reacts to the small share of indicators that carry attribution.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- The Malanta TAXII feed ingested into OpenCTI (see [prerequisites](#prerequisite-ingest-the-malanta-feed))
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
| Create Intrusion Sets | create_intrusion_sets | `MALANTA_ATTRIBUTION_CREATE_INTRUSION_SETS`    | true        | No        | Create the Intrusion Set when absent. Disable to emit relationships only.                             |
| Minimum Confidence    | min_confidence        | `MALANTA_ATTRIBUTION_MIN_CONFIDENCE`           | 0           | No        | Skip indicators below this confidence. `0` processes everything.                                      |

## Deployment

### Prerequisite: ingest the Malanta feed

This connector derives attribution from indicators that are already in OpenCTI. Ingest
the feed first, using the platform's built-in TAXII ingester — **Data → Ingestion → TAXII
feeds → `+`**:

| Field                    | Value                                             |
|--------------------------|---------------------------------------------------|
| Name                     | `Malanta Pre-Attack Indicators`                   |
| TAXII server URL         | `https://app.malanta.ai/feeds/taxii2/default`     |
| TAXII version            | `TAXII 2.1`                                       |
| TAXII Collection         | `pre-attack-indicators`                           |
| Authentication type      | `Bearer token`                                    |
| Token                    | your Malanta API key                              |
| Import from date         | leave empty to import the full collection         |

> The connector never contacts Malanta and never needs the API key. That credential stays
> in the ingester configuration, where OpenCTI encrypts it at rest.

**Start this connector _before_ enabling the ingester.** Indicators already present in
OpenCTI generate no new stream events, so anything ingested beforehand will not be
attributed until it is next updated.

### Prerequisite: create the live stream

In **Data → Data Sharing → Live Streams**, create a stream and copy its ID into
`CONNECTOR_LIVE_STREAM_ID`. Filtering the stream to `Indicator` entities — and, if you
run several feeds, to those authored by the Malanta organization — keeps the connector
from being woken for events it will ignore anyway.

### Docker Deployment

Build the image locally if needed:

```shell
docker build . -t opencti/connector-malanta-attribution:6.9.0
```

Set the environment variables in `docker-compose.yml`, then:

```shell
docker compose up -d
```

### Manual Deployment

Copy `config.yml.sample` to `config.yml` and fill it in, then:

```shell
cd src
pip3 install -r requirements.txt
python3 main.py
```

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

> **If you extend this connector to write back to the indicator itself** (adding a label,
> for instance), you must exclude self-authored events explicitly, or it will loop.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` to log every skipped indicator and the reason.

| Symptom                              | Likely cause                                                                                   |
|--------------------------------------|------------------------------------------------------------------------------------------------|
| No attribution appears               | Stream filter excludes indicators; or the indicators genuinely carry no `apt:` labels.          |
| Only recent indicators are attributed| Expected. Indicators ingested before the connector started produce no stream events.             |
| `Missing stream ID`                  | `CONNECTOR_LIVE_STREAM_ID` unset or left at `ChangeMe`.                                          |
| Intrusion Sets appear unattributed   | `MALANTA_ATTRIBUTION_AUTHOR_NAME` differs from the feed's author, so the identities do not merge. |

## Additional information

Only a share of Malanta's indicators carry attribution labels; the connector is a no-op
for the rest, which is why it can sit in front of a very large feed without becoming a
bottleneck.
