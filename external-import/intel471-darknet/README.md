# OpenCTI Intel 471 Darknet Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

The Intel 471 Darknet connector polls the [Intel 471](https://intel471.com/)
alerts API and forwards every supported alert (forum posts, private /
instant messages, breach alerts, reports, spot reports and actors) to
OpenCTI as a fully linked STIX 2.1 bundle.

## Table of Contents

- [OpenCTI Intel 471 Darknet Connector](#opencti-intel-471-darknet-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

The connector authenticates against the Intel 471 REST API with an
HTTP-Basic credential pair, enumerates the configured watcher groups and
their watchers, then polls the alerts endpoint on the schedule given by
`CONNECTOR_DURATION_PERIOD`. Each alert is normalised into a STIX bundle made
of:

- one `Incident` per alert,
- one `media-content` observable per post / private message / instant
  message,
- one `channel` SDO per forum / chat room (deduplicated by name),
- one `Report` per Intel 471 report / spot report / breach alert,
- one `Identity` per author (deduplicated by handle),
- the matching `related-to`, `targets`, `located-at` and `based-on`
  relationships.

## Installation

### Requirements

- OpenCTI Platform >= 6.7.0 (matches the `pycti==7.260515.0` pin in
  `src/requirements.txt`; the `pycti` 7.x line targets the OpenCTI
  6.7+ API).
- An Intel 471 account with API access.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

For a manual deployment, the configuration file is `src/config.yml`: `src/config.yml.sample` can be used as a template.

`CONNECTOR_RUN_EVERY` (`<int><d|h|m|s>`, e.g. `10m`) is deprecated: it is
still read and converted into `CONNECTOR_DURATION_PERIOD` when the latter is
not set.

## Deployment

### Docker Deployment

Build the Docker image from this directory:

```bash
docker build -t opencti/connector-intel471-darknet:latest .
```

Configure the connector in `docker-compose.yml` and start it:

```bash
docker compose up -d
```

### Manual Deployment

1. Create `src/config.yml` from `src/config.yml.sample` and fill in the
   OpenCTI and Intel 471 credentials.

2. Install the Python dependencies:

   ```bash
   pip3 install -r src/requirements.txt
   ```

3. Start the connector:

   ```bash
   python3 src/main.py
   ```

## Usage

Once the connector is running, it polls the Intel 471 alerts endpoint
on the cadence set by `CONNECTOR_DURATION_PERIOD`. The first run imports every
alert newer than `INTEL471_DARKNET_INITIAL_HISTORY_ALERTS`; subsequent
runs only import alerts newer than the previous successful run (stored
as `last_run` in the connector state).

You can also force an immediate run from the OpenCTI UI:

**Data → Ingestion → Connectors → Intel 471 Darknet → Refresh**.

## Behavior

```mermaid
graph LR
    subgraph Intel471
        Watchers[Watcher groups + watchers]
        Alerts[/alerts/]
        Reports[/reports/{uid}/]
        Actors[/actors/{uid}/]
    end

    subgraph Connector
        Poll[Periodic poll]
        Translate[intel2stix]
        Build[STIX bundle]
    end

    subgraph OpenCTI
        Incident[Incident SDO]
        MediaContent[Media-Content SCO]
        ChannelSDO[Channel SDO]
        ThreatActor[ThreatActor SDO]
        Rels[Relationships]
    end

    Watchers --> Alerts --> Poll
    Poll --> Reports
    Poll --> Actors
    Poll --> Translate --> Build
    Build --> Incident
    Build --> MediaContent
    Build --> ChannelSDO
    Build --> ThreatActor
    Build --> Rels
```

### Supported alert types

| Alert type        | Outcome                                                                                                |
|-------------------|--------------------------------------------------------------------------------------------------------|
| Post              | `media-content` + `Channel` + `Identity (author)` + `Incident`.                                        |
| Private message   | `media-content` + `Channel` (thread) + `Identity (sender/receiver)` + `Incident`.                      |
| Instant message   | `media-content` + `Channel` (chat room) + `Identity (author)` + `Incident`.                            |
| Report            | `Report` SDO with attached `rawText` / `rawTextTranslated` / `researcherComments` / `executiveSummary`.|
| Spot report       | `Report` SDO + linked entities (CVE, file, domain, IP, …) and external references.                     |
| Breach alert      | `Report` SDO + victim `Identity`/`Sector`/`Location` + linked actors / entities.                       |

### Marking enforcement

Every entity created by the connector carries the TLP marking configured
through `INTEL471_DARKNET_TLP`. The default is `AMBER`. Unknown values
are rejected at startup so a misconfiguration cannot silently fall back
to `TLP_RED`.

## Debugging

Enable verbose connector logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

The connector deliberately logs Intel 471 API responses by *summary*
(status code, counts, UIDs) only — raw response bodies can contain
sensitive content (private messages, PII, watcher queries) and are
never written to the logs.

### Common issues

| Issue                                                | Solution                                                                                                                                |
|------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| `INTEL471_API_USERNAME` / `INTEL471_API_KEY` missing | The connector cannot authenticate. Provide both credentials.                                                                            |
| `Unsupported INTEL471_DARKNET_TLP value …`           | Use one of `CLEAR`, `GREEN`, `AMBER`, `AMBER_STRICT`, `RED`.                                                                            |
| `CONNECTOR_DURATION_PERIOD … must be strictly positive` | Provide a non-zero ISO-8601 duration such as `PT30S`, `PT10M`, `PT12H`, `P7D`.                                                       |
| `Intel 471 request failed (status=4xx/5xx)`          | Inspect the Intel 471 console for credential / quota issues. The connector logs the URL and HTTP status (never the body).                |

## Additional information

- **Watcher metadata**: at startup the connector enumerates every
  watcher group and every watcher and keeps an in-memory mapping
  `{uid → description}` so each alert can be tagged with the watcher
  that produced it. Missing watcher UIDs fall back to the raw UID so an
  alert is never dropped.
- **Author deduplication**: identities (forum members, message
  senders / receivers) are looked up by name in OpenCTI before being
  created.
- **Attachments**: every Intel 471 image hosted under
  `imageOriginal` is downloaded and uploaded as a base64
  `x_opencti_files` payload on the matching `media-content` observable.
  Raw alert / report bodies are also attached for forensic inspection.
- **Timestamps**: all timestamps emitted by the connector are
  timezone-aware UTC values. The private
  `stix2.utils._TIMESTAMP_FORMAT_FRAC` constant is no longer
  referenced.
- **Network resilience**: every Intel 471 HTTP request is bounded by a
  30-second timeout and checked with `raise_for_status()`. The
  connector logs the URL + status code and keeps polling.
