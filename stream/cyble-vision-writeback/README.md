# OpenCTI Cyble Vision Writeback Connector

Table of Contents

- [OpenCTI Cyble Vision Writeback Connector](#opencti-cyble-vision-writeback-connector)
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

This stream connector is the companion of the [Cyble Vision](../../external-import/cyble-vision) import connector.
That connector brings Cyble Vision alerts into OpenCTI as Incidents. This one sends analyst triage done on those
Incidents in OpenCTI back to Cyble Vision, so both platforms show the same severity and review status.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- The [Cyble Vision](../../external-import/cyble-vision) import connector, deployed and importing alerts
- A Cyble Vision API token allowed to update alerts

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

Two settings deserve attention:

- `CONNECTOR_ID` must be different from the import connector's ID.
- `CYBLE_VISION_WRITEBACK_IGNORED_USER_NAMES` must match the OpenCTI user the import connector runs as (by default
  any user whose name contains `Cyble Vision`). Updates made by that user are the import itself, and writing them
  back would turn Vision's own severity into a customer override.

## Deployment

### Docker Deployment

Build the Docker image from the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-cyble-vision-writeback:latest
```

Set the variables in `docker-compose.yml` (at least `OPENCTI_URL`, `OPENCTI_TOKEN` and
`CYBLE_VISION_WRITEBACK_API_TOKEN`), add the service to the OpenCTI `docker-compose.yml` and start it:

```shell
docker compose up -d
```

### Manual Deployment

Copy `config.yml.sample` to `src/config.yml` and fill in the values, then install the dependencies and run the
connector:

```shell
pip3 install -r src/requirements.txt
cd src
python3 main.py
```

## Usage

The connector listens to the live stream set in `CONNECTOR_LIVE_STREAM_ID` (`live`, the global stream, by default).
To reduce traffic, create a live stream in **Data sharing → Live streams** filtered on entity type `Incident` and
label `cyble`, and use its ID.

Stream history is not replayed on first start (`CONNECTOR_LIVE_STREAM_RECOVER=false`): only changes made after the
connector starts are written back.

## Behavior

For every `update` event on an Incident, the connector:

1. Ignores the event if the change was made by one of `CYBLE_VISION_WRITEBACK_IGNORED_USER_NAMES`.
2. Reloads the Incident from OpenCTI, because stream update events can be partial.
3. Reads the Vision alert ID from the `Cyble Vision` external reference and the Vision service from the
   `cyble:<service>` label set by the import connector. Incidents without both are skipped.
4. Sends `PUT /y/alerts` to Cyble Vision with:

| OpenCTI | Cyble Vision |
|---|---|
| Severity `low` / `medium` / `high` / `critical` | `user_severity` `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` |
| Workflow status `New` / `Open` | `status` `UNREVIEWED` |
| Workflow status `In progress` | `status` `UNDER_REVIEW` |
| Workflow status `Closed` / `Resolved` / `Done` | `status` `RESOLVED` |

Create and delete events are ignored. Nothing is ever deleted in Cyble Vision.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` to log every skipped event with the reason. Each write-back is logged at `info`
level with the Vision alert ID, service and the values sent.

## Additional information

- Contact: [support@cyble.com](mailto:support@cyble.com)
- Product: [Cyble Vision](https://cyble.com)
