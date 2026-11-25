# OpenCTI Internal Enrichment Template Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
* Please find an example of expected documentation below
* REQUIRED CHANGES => Check https://docs.opencti.io/latest/development/connectors/
-->

Table of Contents

- [OpenCTI Internal Enrichment Template Connector](#opencti-internal-enrichment-connector-template)
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

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 6.8.13
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library matching your OpenCTI version

## Configuration variables


Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)


_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._


## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from `src` directory:

```shell
python3 main.py
```

## Usage

The connector enriches the OpenCTI entities whose type is in `CONNECTOR_SCOPE`:

- automatically, when an entity is created or updated, if `CONNECTOR_AUTO` is `true`;
- manually, from the "Enrichment" button of an entity in the OpenCTI platform;
- from a playbook, with the "Enrich through connector" step.

## Behavior

<!--
Describe how the connector functions:
* What data is added to the enriched entity, and which objects are created
* Important considerations for users when utilizing this connector
* Additional relevant details
-->

The connector uses `InternalEnrichmentConnector` from `connectors-sdk`. For each entity to enrich, it:

1. skips the entity if its type is not in `CONNECTOR_SCOPE`;
2. skips the entity if its TLP is higher than `CONNECTOR_MAX_TLP`. The entity is never sent to the external source;
3. calls the processor of the entity type: `collect()` gets the data from the source, and `transform()` converts it to STIX;
4. sends the new objects to OpenCTI, with the objects it received.

In a playbook, the connector always sends one bundle back, even if it skips the entity or fails.

## How to adapt this template

1. **Settings** (`src/connector/settings.py`): change the `id`, `name`, `scope` and `max_tlp` defaults.
   Rename `TemplateConfig` and change its options for your source.
2. **Client** (`src/template_client/`): write one method per endpoint of your API (`api_client.py`),
   and one Pydantic model per response (`models.py`).
3. **Processors** (`src/connector/enrichment_processors/`): write one processor per group of entity types.
   List the types in `handled_entity_types`, then write `collect()` (call the API) and `transform()`
   (convert to STIX).
   - To update the entity, return a new version of it with the same value: it keeps the same id.
   - To link new objects to the entity, use `Reference(id=message.stix_entity.id)`.
4. **Entry point** (`src/main.py`): add your processors to the list.
5. Generate `__metadata__/connector_config_schema.json` and `CONNECTOR_CONFIG_DOC.md` from the settings.
   Never edit these files by hand.

## Debugging

To see more logs, set `CONNECTOR_LOG_LEVEL` to `debug`.
In a processor, write logs with `self.logger`, e.g. `self.logger.info("IP address not found", meta={"value": value})`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
