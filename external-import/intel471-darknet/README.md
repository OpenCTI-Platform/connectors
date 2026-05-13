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
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Intel 471 Darknet connector environment variables](#intel-471-darknet-connector-environment-variables)
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
`CONNECTOR_RUN_EVERY`. Each alert is normalised into a STIX bundle made
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

- OpenCTI Platform >= 6.4.3
- An Intel 471 account with API access.

## Configuration variables

There are a number of configuration options, which are set either in
`docker-compose.yml` (for Docker) or in `src/config.yml` (for manual
deployment). The provided `src/config.yml.sample` can be used as a
template.

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter            | config.yml             | Docker environment variable      | Default              | Mandatory | Description                                                                                                          |
|----------------------|------------------------|----------------------------------|----------------------|-----------|----------------------------------------------------------------------------------------------------------------------|
| Connector ID         | id                     | `CONNECTOR_ID`                   |                      | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                            |
| Connector Type       | type                   | `CONNECTOR_TYPE`                 | `EXTERNAL_IMPORT`    | Yes       | Must be `EXTERNAL_IMPORT`.                                                                                           |
| Connector Name       | name                   | `CONNECTOR_NAME`                 | `Intel 471 Darknet`  | No        | Name of the connector as it appears in OpenCTI.                                                                      |
| Connector Scope      | scope                  | `CONNECTOR_SCOPE`                | `intel471-darknet`   | No        | Connector scope (used by OpenCTI to dispatch work).                                                                  |
| Log Level            | log_level              | `CONNECTOR_LOG_LEVEL`            | `info`               | No        | Verbosity of the logs: `debug`, `info`, `warn`, or `error`.                                                          |
| Run Every            | run_every              | `CONNECTOR_RUN_EVERY`            |                      | Yes       | Polling interval in the form `<int><d\|h\|m\|s>` (e.g. `7d`, `12h`, `10m`, `30s`).                                   |
| Update existing data | update_existing_data   | `CONNECTOR_UPDATE_EXISTING_DATA` | `false`              | No        | If `true`, allow updates of existing entities. Otherwise OpenCTI leaves them as-is.                                  |

### Intel 471 Darknet connector environment variables

| Parameter               | config.yml                              | Docker environment variable                | Default                          | Mandatory | Description                                                                                                                                              |
|-------------------------|-----------------------------------------|--------------------------------------------|----------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| API URL                 | intel471.api_url                        | `INTEL471_API_URL`                         | `https://api.intel471.com/v1`    | No        | Base URL of the Intel 471 REST API.                                                                                                                      |
| API username            | intel471.api_username                   | `INTEL471_API_USERNAME`                    |                                  | Yes       | Intel 471 API username (HTTP Basic).                                                                                                                     |
| API key                 | intel471.api_key                        | `INTEL471_API_KEY`                         |                                  | Yes       | Intel 471 API key (HTTP Basic password).                                                                                                                 |
| Initial history alerts  | intel471_darknet.initial_history_alerts | `INTEL471_DARKNET_INITIAL_HISTORY_ALERTS`  | `0`                              | No        | Unix epoch (seconds) of the earliest alert to import on the first run. Subsequent runs only fetch alerts newer than the previous successful run.        |
| TLP marking             | intel471_darknet.tlp                    | `INTEL471_DARKNET_TLP`                     | `AMBER`                          | No        | Marking applied to every entity created by the connector. One of `CLEAR`, `GREEN`, `AMBER`, `AMBER_STRICT`, `RED`.                                       |

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
on the cadence set by `CONNECTOR_RUN_EVERY`. The first run imports every
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
| `CONNECTOR_RUN_EVERY is required …`                  | Provide a value such as `7d`, `12h`, `10m`, `30s`.                                                                                      |
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
