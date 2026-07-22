# OpenCTI FortiSandbox Connector

The FortiSandbox connector is an **internal-enrichment** connector that enriches
`StixFile` and `Artifact` observables with Fortinet FortiSandbox verdicts.

For each observable, the connector queries the FortiSandbox JSON-RPC API by hash
(SHA-256 / SHA-1 / MD5). When FortiSandbox has a rating, the connector:

- maps the FortiSandbox rating (clean, low/medium/high risk, suspicious, malicious) to an
  OpenCTI score and a `fortisandbox:<rating>` label,
- adds a `malware:<name>` label when FortiSandbox returns a malware name,
- completes the file hashes,
- attaches a STIX Malware Analysis object carrying the FortiSandbox result and an external
  reference (the FortiSandbox detail URL when available).

When no verdict exists yet, the connector submits the file carried by the observable for
on-demand analysis and polls for a verdict (enabled by default via `submit_unknown`; file
downloads enforce `max_file_size` and reject empty files). This is the primary path for
`Artifact` observables uploaded to OpenCTI. The connector is playbook compatible and
always returns the (enriched) bundle.

Table of Contents

- [OpenCTI FortiSandbox Connector](#opencti-fortisandbox-connector)
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

[Fortinet FortiSandbox](https://www.fortinet.com/products/sandbox/fortisandbox) is a
malware-analysis appliance/VM/cloud that returns verdicts and ratings for files. This
connector uses the FortiSandbox JSON-RPC API to retrieve the rating for a file observable
and turns it into OpenCTI knowledge.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 7.260722.0
- A FortiSandbox instance reachable from the connector, and API credentials
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
| Connector Type  | type           | `CONNECTOR_TYPE`            | INTERNAL_ENRICHMENT | Yes       | Should always be set to `INTERNAL_ENRICHMENT` for this connector.                        |
| Connector Name  | name           | `CONNECTOR_NAME`            |                 | Yes       | Name of the connector.                                                                   |
| Connector Scope | scope          | `CONNECTOR_SCOPE`           |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | log_level      | `CONNECTOR_LOG_LEVEL`       | error           | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Connector Auto  | auto           | `CONNECTOR_AUTO`            | false           | Yes       | Must be `true` or `false` to enable or disable auto-enrichment of observables            |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter      | config.yml     | Docker environment variable     | Default   | Mandatory | Description                                                                          |
| -------------- | -------------- | ------------------------------- | --------- | --------- | ----------------------------------------------------------------------------------- |
| API base URL   | api_base_url   | `FORTISANDBOX_API_BASE_URL`     |           | Yes       | FortiSandbox base URL (appliance/VM/cloud), without the `/jsonrpc` suffix.           |
| Username       | username       | `FORTISANDBOX_USERNAME`         |           | Yes       | FortiSandbox API username.                                                           |
| Password       | password       | `FORTISANDBOX_PASSWORD`         |           | Yes       | FortiSandbox API password.                                                           |
| API version    | api_version    | `FORTISANDBOX_API_VERSION`      | `4.2.4`   | No        | JSON-RPC API version sent with each request.                                         |
| SSL verify     | ssl_verify     | `FORTISANDBOX_SSL_VERIFY`       | `true`    | No        | Whether to verify the FortiSandbox TLS certificate.                                  |
| Submit unknown | submit_unknown | `FORTISANDBOX_SUBMIT_UNKNOWN`   | `true`    | No        | Submit unknown files (carried by the observable) for on-demand analysis.             |
| Max file size  | max_file_size  | `FORTISANDBOX_MAX_FILE_SIZE`    | `33554432` | No       | Max size (bytes) of a file the connector downloads from OpenCTI and submits (32 MiB).|
| Submission timeout | submission_timeout | `FORTISANDBOX_SUBMISSION_TIMEOUT` | `600` | No   | Max time (seconds) to wait for a submitted file's verdict.                           |
| Max TLP        | max_tlp        | `FORTISANDBOX_MAX_TLP`          | `TLP:AMBER` | No      | Maximum TLP of the observable the connector is allowed to enrich.                    |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==7.260701.0`. If you don't, it will take the latest version, but
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

The connector is an internal-enrichment connector: it runs on demand. Open a `StixFile` or
`Artifact` observable in the OpenCTI platform and trigger the enrichment from the
`Enrichment` panel (or let it run automatically when `CONNECTOR_AUTO` is enabled). The
connector is also playbook compatible and can be used as an enrichment step in playbooks.

## Behavior

On each enrichment request the connector:

1. Selects the strongest available hash on the observable (SHA-256 > SHA-1 > MD5) and the
   matching `ctype`.
2. Authenticates against the FortiSandbox JSON-RPC API (`/sys/login/user`) and queries
   `/scan/result/filerating`. If FortiSandbox has no rating (or `Unknown`) and
   `submit_unknown` is disabled, the original bundle is returned unchanged.
3. When `submit_unknown` is enabled (default) and the observable carries an uploaded file,
   the connector downloads the file from OpenCTI storage (enforcing `max_file_size` and
   rejecting empty files), submits it (`/alert/ondemand/submit-file`) and polls the
   submission (`/scan/result/get-jobs-of-submission`, `/scan/result/job`) for a verdict
   (bounded by `submission_timeout`). This is the primary path for `Artifact` observables
   uploaded to OpenCTI.
4. Enriches the observable with an `x_opencti_score`, a `fortisandbox:<rating>` label, a
   `malware:<name>` label (when available), and the resolved hashes.
5. Creates a STIX Malware Analysis object (`product = FortiSandbox`) referencing the
   observable, with the rating mapped to the STIX `malware-result` vocabulary.

FortiSandbox rating mapping:

| FortiSandbox rating       | Label                       | Score | Malware Analysis result |
| ------------------------- | --------------------------- | ----- | ----------------------- |
| Clean                     | fortisandbox:clean          | 10    | benign                  |
| Low Risk                  | fortisandbox:low risk       | 40    | suspicious              |
| Suspicious / Medium Risk  | fortisandbox:suspicious     | 60    | suspicious              |
| High Risk                 | fortisandbox:high risk      | 80    | malicious               |
| Malicious                 | fortisandbox:malicious      | 90    | malicious               |

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
