# OpenCTI Internal Hunt Template Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

Table of Contents

- [OpenCTI Internal Hunt Template Connector](#opencti-internal-hunt-template-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [How to adapt this skeleton](#how-to-adapt-this-skeleton)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

Connectors of type `INTERNAL_HUNT` execute the hunts of OpenCTI on a telemetry platform (SIEM, EDR, data lake) or on
internet scanning APIs. OpenCTI dispatches one message per hunt run; the connector translates the canonical Sigma rule
of the hunt with [pySigma](https://github.com/SigmaHQ/pySigma) (or executes the native query written for its platform),
runs it over the time window of the run, sends the resulting knowledge and reports the run outcome.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform providing hunts (the `INTERNAL_HUNT` connector type)
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version (pinned to `7.261002.0`; the
  connector checks at startup that the installed pycti supports hunt connectors and stops with an explicit message
  otherwise)
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library
  matching your OpenCTI version
- [`pysigma`](https://pypi.org/project/pysigma/) and the pySigma backend of the platform

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other
connector. For more information regarding variables, please refer to
[OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`, replace the "**ChangeMe**" values, install the
dependencies (preferably in a virtual environment) and start the connector from the `src` directory:

```shell
pip3 install -r requirements.txt
python3 main.py
```

## Usage

The connector registers its hunt platform in OpenCTI at startup. Hunts are then run on it by OpenCTI (manually, on
schedule, or when the threat landscape changes), and their runs appear in the hunt detail page. A preview run only
translates the hunt logic and never queries the platform.

## Behavior

For every hunt run:

1. The native query of the hunt for the platform is executed verbatim; otherwise the Sigma rule is translated with
   the configured pySigma pipeline (a native query with an empty query only selects the pipeline).
2. The query runs over the time window of the run, bounded by the run timeout and `max_results`.
3. Events matching a benign pattern of the hunt are suppressed. When the platform returned only part of the results and some returned events were benign, the run reports the non-benign returned events as its hits: the platform total cannot be corrected from a sample.
4. When there are hits, the connector sends a sighting of every technique and indicator of the hunt on the Security
   Platform identity, and one observed-data per IOC observable found, with the number of
   result events holding it (only for the observable types the hunt expects). Objects inherit the markings and the author
   of the hunt and have deterministic identifiers; those of the sightings and observed-data derive from the hunt run
   too, so a retry of a run updates its own objects and two runs never share one.
5. The run is reported with the hit count, the distinct hosts/users/peers, the translated query and an evidence sample.

Evidence and privacy guarantees: raw events never leave the connector. Evidence values are SHA-256 hashed and their
previews truncated to the run limit; host names, user names and command lines only appear there. Private IP addresses
and internal domain names are never turned into observables.

## How to adapt this skeleton

1. **Settings** (`src/connector/settings.py`): set the `scope` default to the platform slug, the Security Platform
   name, and replace the API settings of `TemplateConfig`.
2. **Client** (`src/template_client/api_client.py`): implement authentication and the search API of the platform on
   `HuntApiClient` (create the search job, poll it within the run deadline, fetch at most `max_results` events, cancel
   it on timeout). `hunt_request()` bounds each call with the `RunDeadline` of the run and raises hunt errors carrying
   the platform message.
3. **Connector** (`src/connector/connector.py`): set `languages`, the pySigma backend and pipelines, and map the
   platform events in `execute()`. Override `on_timeout()` when the platform runs asynchronous jobs.
4. **Indicator hunts** (optional): override `ioc_query(batch)` to look up a batch of values of one observable type
   (`batch.observable_type`, `batch.values`). Return a query whose events the base searches for the values, or set
   `ioc_aggregated = True` and return one row per value key (`ioc`, `hits`, `first_seen`, `last_seen`, `hosts`) for
   exact counts. Return `None` for a type the platform cannot look up: its values are reported not searched. The base
   batches the values, reports one result per value and sights the seen ones; overriding `ioc_query` makes the
   connector register as supporting indicator lookups.
5. **Requirements**: add the pySigma backend package of the platform to `src/requirements.txt`.
6. Regenerate `__metadata__/connector_config_schema.json` and `CONNECTOR_CONFIG_DOC.md` from the settings model, never
   edit these generated files by hand.

## Debugging

The connector can be debugged by setting the appropriate log level (`CONNECTOR_LOG_LEVEL=debug`). Every run logs its
reception, completion (hits, suppressed events, objects sent) or failure.

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
