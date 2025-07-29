<<<<<<< HEAD
# OpenCTI Splunk Search Internal Enrichment Connector

The Splunk Search connector enriches OpenCTI Indicators by running Splunk searches and converting matching telemetry into STIX observables, sightings, and source identities.

This is an `INTERNAL_ENRICHMENT` connector with `Indicator` scope. It does not poll OpenCTI on a schedule and it does not send data to Splunk HEC. OpenCTI triggers it when a user or playbook enriches an Indicator.

## How It Works

At startup, the connector checks OpenCTI for SPL search template Indicators:

- `pattern_type = "spl"`
- label `threat-hunting-splunk`

If no templates exist, it seeds the default bundle from `splunk_bundle.py`. These seeded Indicators are Splunk searches, not IOCs to enrich. They contain placeholders such as `<IP_LIST>`, `<DOMAIN_LIST>`, `<HOSTNAME_LIST>`, `<FILE_HASH_LIST>`, and `<INDICATOR_ID>`.

When an enrichment request arrives, the connector supports two paths:

- STIX Indicator path: for `pattern_type = "stix"`, the connector extracts observable values from the callback `stix_objects` or from the STIX pattern, finds matching SPL templates for the Indicator observable type, renders each template, runs each search in Splunk, and sends one STIX bundle back to OpenCTI.
- SPL Indicator path: for `pattern_type = "spl"`, the connector treats the Indicator pattern as the Splunk query, renders any placeholders if values are available, runs it directly, and sends one STIX bundle back to OpenCTI.

Unsupported `pattern_type` values are skipped with a warning.

## Search Parameters

Each SPL template can have an attached OpenCTI Note with `note_types = "Search Parameters"` and JSON content such as:

```json
{
  "earliest_time": "-90d@d",
  "latest_time": "now",
  "timeout": 120,
  "wait_seconds": 2,
  "max_results": 1000
}
```

Search parameter precedence is:

1. Per-Indicator Note parameters
2. Connector configuration defaults

For example, if the connector default is `SPLUNK_SEARCH_EARLIEST=-30d@d` but the Note has `"earliest_time": "-90d@d"`, the search runs with `-90d@d`.

## Requirements

- OpenCTI with a connector token that can read Indicators and Notes and import STIX bundles.
- Splunk management API access using a token.
- Python dependencies from `src/requirements.txt`, including `pycti`, `stix2`, and `splunk-sdk`.

## Configuration

Configuration can be provided through Docker environment variables or through `src/config.yml` using the paths shown below.

### OpenCTI

| Parameter | config.yml path | Environment variable | Default | Required | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | none | yes | OpenCTI platform URL. |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | none | yes | Token used by the connector. |

### Connector

| Parameter | config.yml path | Environment variable | Default | Required | Description |
|---|---|---|---|---|---|
| Connector ID | `connector.id` | `CONNECTOR_ID` | none | yes | Unique connector UUID. |
| Connector type | `connector.type` | `CONNECTOR_TYPE` | none | yes | Must be `INTERNAL_ENRICHMENT`. |
| Connector name | `connector.name` | `CONNECTOR_NAME` | `SplunkSearch` | yes | Display name in OpenCTI. |
| Connector scope | `connector.scope` | `CONNECTOR_SCOPE` | `Indicator` | yes | Must include `Indicator`. |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | `info` | no | Log verbosity. |
| Auto enrichment | `connector.auto` | `CONNECTOR_AUTO` | `false` | no | Whether OpenCTI should trigger enrichment automatically. |

### Splunk

| Parameter | config.yml path | Environment variable | Default | Required | Description |
|---|---|---|---|---|---|
| Splunk host | `splunk-search.host` | `SPLUNK_HOST` | none | yes | Splunk management API host, without scheme. |
| Splunk port | `splunk-search.port` | `SPLUNK_PORT` | `8089` | no | Splunk management API port. |
| Splunk token | `splunk-search.token` | `SPLUNK_TOKEN` | none | yes | Splunk authentication token. |
| Splunk app | `splunk-search.app` | `SPLUNK_APP` | `search` | no | Splunk app context for searches. |
| Scheme | `splunk-search.scheme` | `SPLUNK_SCHEME` | `https` | no | `https` or `http`. |
| Verify SSL | `splunk-search.verify_ssl` | `SPLUNK_VERIFY_SSL` | `true` | no | Set to `false` for self-signed certificates. |
| Default earliest time | `splunk-search.earliest_time` | `SPLUNK_SEARCH_EARLIEST` | `-30d@d` | no | Fallback earliest bound when the SPL Indicator Note does not provide one. |
| Default latest time | `splunk-search.latest_time` | `SPLUNK_SEARCH_LATEST` | `now` | no | Fallback latest bound when the SPL Indicator Note does not provide one. |
| Default timeout | `splunk-search.timeout` | `SPLUNK_SEARCH_TIMEOUT` | `60` | no | Fallback search timeout in seconds. |
| Poll interval | `splunk-search.wait_seconds` | `SPLUNK_WAIT_SECONDS` | `2` | no | Fallback polling interval while waiting for Splunk jobs. |
| Max results | `splunk-search.max_results` | `SPLUNK_MAX_RESULTS` | `1000` | no | Fallback maximum result rows to read. |
| Sighting TLP | `splunk-search.sighting_tlp` | `SPLUNK_SIGHTING_TLP` | `TLP:AMBER` | no | TLP marking applied to generated Sightings. |
| Observable TLP | `splunk-search.observable_tlp` | `SPLUNK_OBSERVABLE_TLP` | `TLP:AMBER` | no | TLP marking applied to generated observables/source identities. |

Supported TLP labels are `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, and `TLP:RED`.

## Docker Deployment

Build and start the connector with the provided Docker artifacts:

```shell
docker build . -t opencti-connector-splunk-search:dev
docker compose up -d
```

Set the required variables in your environment before starting Compose:

```shell
export OPENCTI_ADMIN_TOKEN=...
export CONNECTOR_SPLUNK_SEARCH_ID=...
export SPLUNK_TOKEN=...
```

Review `docker-compose.yml` for all available variables.

## Manual Deployment

Create `src/config.yml` from `src/config.yml.sample`, then install dependencies and run the connector:

```shell
cd src
pip3 install -r requirements.txt
python3 main.py
```

## Enrichment Output

For each Splunk result row, the connector uses `splunk_result_parser.py` to create STIX objects from recognized fields such as:

- IP addresses, domains, URLs, hostnames, user agents, users, software, files, and directories
- Source identities for Splunk hosts/sourcetypes where available
- Sightings with Splunk telemetry context and TLP markings

The connector sends a single STIX bundle per enrichment request. The bundle includes the Splunk author Identity plus all generated observables, sightings, and source identities.

## Troubleshooting

- No SPL templates found: confirm the startup seed ran, or create Indicators with `pattern_type = "spl"` and label `threat-hunting-splunk`.
- Search time range seems wrong: check the Search Parameters Note attached to the SPL Indicator. Note values override connector defaults.
- Splunk authentication fails: verify `SPLUNK_HOST`, `SPLUNK_PORT`, `SPLUNK_SCHEME`, `SPLUNK_TOKEN`, and `SPLUNK_VERIFY_SSL`.
- Nothing happens automatically: `CONNECTOR_AUTO=false` means enrichment must be triggered manually or by a playbook.

For more detail, set `CONNECTOR_LOG_LEVEL=debug`.
=======
# OpenCTI Splunk Internal Enrichment Connector

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

- [OpenCTI Splunk Internal Enrichment Connector](#opencti-splunk-internal-enrichment-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

This connector enriches STIX Indicators in OpenCTI by querying Splunk for related activity based on the Indicator's pattern type. 
- If the `pattern_type` is `stix`, the connector parses the STIX pattern to determine the observable type and sends a predefined Splunk query mapped to that type.
- If the `pattern_type` is `spl` or `splunk`, the pattern is treated as a raw Splunk search and executed directly.
The connector then enriches the Indicator with results from Splunk, which can include Observed Data, Notes, or other relevant OpenCTI objects.

## Installation

### Requirements

- OpenCTI Platform >= 

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter       | config.yml      | Docker environment variable | Default         | Mandatory | Description                                                                              |
|-----------------|-----------------|-----------------------------|-----------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID    | id              | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type            | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT | Yes       | Should always be set to `INTERNAL_ENRICHMENT` for this connector.                        |
| Connector Name  | name            | `CONNECTOR_NAME`            |                 | Yes       | Name of the connector.                                                                   |
| Connector Scope | scope           | `CONNECTOR_SCOPE`           |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | log_level       | `CONNECTOR_LOG_LEVEL`       | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Connector Auto  | connector_auto	 | `CONNECTOR_AUTO`            | True            | Yes       | Must be `true` or `false` to enable or disable auto-enrichment of observables            |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter          | config.yml       | Docker environment variable | Default | Mandatory | Description                                         |
|--------------------|------------------|------------------------------|---------|-----------|-----------------------------------------------------|
| splunk_url         | splunk_url       | SPLUNK_URL                   |         | Yes       | The base URL of the Splunk instance                |
| splunk_token       | splunk_token     | SPLUNK_TOKEN                 |         | Yes       | The authentication token for accessing Splunk API  |
| splunk_verify_ssl  | splunk_verify_ssl| SPLUNK_VERIFY_SSL            | True    | No        | Whether to verify the SSL certificate              |
| enrichment_mappings| enrichment_mappings|                              |         | Yes       | Mapping of observable types to Splunk query templates |

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

Then, start the connector from recorded-future/src:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior


The connector is triggered whenever an `Indicator` is created or updated in OpenCTI. Based on the `pattern_type`, it will construct an appropriate Splunk query and execute it:
- For `stix` patterns: Parses and maps the observable to a predefined query
- For `spl`/`splunk`: Executes the provided pattern directly as a Splunk query

Query results are used to create enrichment objects such as Notes or Observed Data.


## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information


This connector is ideal for Security Operations Centers (SOCs) that want to link threat intelligence from OpenCTI with real-time or historical telemetry data from Splunk.
>>>>>>> 7a60e94c2a (Init splunk-search connector)
