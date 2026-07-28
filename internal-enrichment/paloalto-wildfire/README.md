# OpenCTI Palo Alto Networks WildFire Connector

The Palo Alto Networks WildFire connector is an **internal-enrichment** connector that
enriches `StixFile` and `Artifact` observables with WildFire file verdicts.

For each observable, the connector queries the WildFire public API by hash
(MD5 / SHA-1 / SHA-256). When the hash is unknown and the observable carries an uploaded
file, the connector submits it to WildFire for analysis and polls for the verdict
(opt-in via `submit_unknown`, disabled by default). When WildFire has a verdict, the connector:

- maps the WildFire verdict (benign, grayware, phishing, malware, command-and-control)
  to an OpenCTI score and a `wildfire:<verdict>` label,
- completes the file hashes from the WildFire report when available,
- attaches a STIX Malware Analysis object carrying the WildFire result and an external
  reference.

The connector is playbook compatible and always returns the (enriched) bundle.

Table of Contents

- [OpenCTI Palo Alto Networks WildFire Connector](#opencti-palo-alto-networks-wildfire-connector)
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

[Palo Alto Networks WildFire](https://www.paloaltonetworks.com/network-security/wildfire)
is a cloud-based malware analysis service. This connector uses the WildFire public API
to retrieve the verdict (and, when available, the report) for a file observable and
turns it into OpenCTI knowledge.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 7.260722.0
- A Palo Alto Networks WildFire API key
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library matching your OpenCTI version

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter       | config.yml     | Docker environment variable | Default         | Mandatory | Description                                                                              |
| --------------- | -------------- | --------------------------- | --------------- | --------- | ---------------------------------------------------------------------------------------- |
| Connector ID    | id             | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type           | `CONNECTOR_TYPE`            | INTERNAL_ENRICHMENT | Yes   | Should always be set to `INTERNAL_ENRICHMENT` for this connector.                        |
| Connector Name  | name           | `CONNECTOR_NAME`            | Palo Alto Networks WildFire | No | Name of the connector.                                                          |
| Connector Scope | scope          | `CONNECTOR_SCOPE`           | StixFile,Artifact | No      | The observable types the connector enriches.                                           |
| Log Level       | log_level      | `CONNECTOR_LOG_LEVEL`       | error           | No        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Connector Auto  | auto           | `CONNECTOR_AUTO`            | false           | No        | Must be `true` or `false` to enable or disable auto-enrichment of observables            |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter    | config.yml   | Docker environment variable        | Default                                          | Mandatory | Description                                                                                                |
| ------------ | ------------ | ---------------------------------- | ------------------------------------------------ | --------- | ---------------------------------------------------------------------------------------------------------- |
| API key      | api_key      | `PALOALTO_WILDFIRE_API_KEY`        |                                                  | Yes       | The Palo Alto Networks WildFire API key.                                                                   |
| API base URL | api_base_url | `PALOALTO_WILDFIRE_API_BASE_URL`   | `https://wildfire.paloaltonetworks.com/publicapi` | No        | The WildFire API base URL (use the appropriate cloud region or a WildFire appliance URL).                  |
| Submit unknown | submit_unknown | `PALOALTO_WILDFIRE_SUBMIT_UNKNOWN` | `false`                                        | No        | Submit unknown files (carried by the observable) to WildFire for analysis when no verdict exists yet (opt-in). |
| Max file size | max_file_size | `PALOALTO_WILDFIRE_MAX_FILE_SIZE` | `33554432`                                       | No        | Max size (bytes) of a file the connector downloads from OpenCTI and submits (32 MiB).                      |
| Submission timeout | submission_timeout | `PALOALTO_WILDFIRE_SUBMISSION_TIMEOUT` | `600`                                 | No        | Max time (seconds) to wait for a submitted file's verdict.                                                 |
| Max TLP      | max_tlp      | `PALOALTO_WILDFIRE_MAX_TLP`        | `TLP:AMBER`                                       | No        | Maximum TLP of the observable the connector is allowed to enrich.                                          |

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

This is an internal-enrichment connector: it runs on demand rather than on a schedule. Once deployed it enriches a `StixFile` or `Artifact` observable when:

- a user triggers enrichment from the observable's **Enrichment** panel in the OpenCTI platform,
- it is called from a playbook, or
- `CONNECTOR_AUTO=true`, in which case it runs automatically whenever an in-scope observable is created or updated.

## Behavior

On each enrichment request the connector:

1. Selects the strongest available hash on the observable (SHA-256 > SHA-1 > MD5).
2. Calls `POST /get/verdict` on the WildFire API.
3. If the hash is unknown and `submit_unknown` is enabled (opt-in; disabled by default) and the observable
   carries an uploaded file, the connector downloads the file from OpenCTI storage
   (enforcing `max_file_size` and rejecting empty files), submits it (`POST /submit/file`),
   and polls `POST /get/verdict` until the verdict is final (bounded by
   `submission_timeout`). This is the primary path for `Artifact` observables uploaded to
   OpenCTI. If still no verdict, the original bundle is returned unchanged.
4. Calls `POST /get/report` to complete the file hashes and file type when available.
5. Enriches the observable with an `x_opencti_score`, a `wildfire:<verdict>` label, the
   resolved hashes, and (for `StixFile`) the file size.
6. Creates a STIX Malware Analysis object (`product = WildFire`) referencing the
   observable, with the WildFire result mapped to the STIX `malware-result` vocabulary.

WildFire verdict mapping:

| WildFire verdict | Label                 | Score | Malware Analysis result |
| ---------------- | --------------------- | ----- | ----------------------- |
| 0                | benign                | 10    | benign                  |
| 1                | malware               | 90    | malicious               |
| 2                | grayware              | 40    | suspicious              |
| 4                | phishing              | 80    | malicious               |
| 5                | command-and-control   | 95    | malicious               |

The connector looks up a verdict by hash first and only submits a file when the hash is
unknown and a file is attached to the observable, avoiding unnecessary detonations.

## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, i.e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
