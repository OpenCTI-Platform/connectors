# OpenCTI VMRay Platform Connector

Table of Contents

- [OpenCTI VMRay Platform Connector](#opencti-vmray-platform-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [VMRay Platform environment variables](#vmray-platform-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)


## Introduction
VMRay is an advanced malware sandbox and threat analysis platform used by hundreds of leading security teams worldwide, including Fortune 100 enterprises, government agencies, financial institutions, and MSSPs. By combining dynamic, evasion-resistant sandboxing with rich, reusable output, VMRay enables security teams to investigate unknown, advanced, and targeted threats, reduce analysis time, and build reliable, independent threat intelligence on the attacks that actually target their environment.

This connector continuously ingests high-quality IOCs and analysis context from VMRay Platform into OpenCTI, including classifications, threat names, and other enriched observables derived from in-depth malware and phishing analysis. By bringing VMRay’s definitive verdicts and noise-free data into OpenCTI, security, IR, and threat intel teams can better correlate suspicious activity, prioritize investigations, and strengthen their overall detection and response workflows.

## Installation

### Requirements

- OpenCTI Platform >= 6.9.0

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

| Parameter         | config.yml      | Docker environment variable | Default         | Mandatory | Description                                                                                 |
|-------------------|-----------------|-----------------------------|-----------------|-----------|---------------------------------------------------------------------------------------------|
| Connector ID      | id              | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                   |                              |
| Connector Name    | name            | `CONNECTOR_NAME`            |                 | Yes       | Name of the connector.                                                                      |
| Connector Scope   | scope           | `CONNECTOR_SCOPE`           |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.    |
| Log Level         | log_level       | `CONNECTOR_LOG_LEVEL`       | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.      |
| Duration Period   | duration_period | `CONNECTOR_DURATION_PERIOD` | PT1D            | No        | Determines the time interval between each launch of the connector in ISO 8601, ex: `PT30M`. |

### VMRay Platform environment variables

Below are the parameters you'll need to set for the connector:

| Parameter                  | config.yml                 | Docker environment variable                 | Default | Mandatory | Description                                                                                                   |
|----------------------------|----------------------------|---------------------------------------------|---------|-----------|---------------------------------------------------------------------------------------------------------------|
| VMRay Server    | server                   | `VMRAY_SERVER`                   | https://cloud.vmray.com       | Yes       | VMRay Server URL                                                                                      |                        
| VMRay API Key        | api_key                   | `VMRAY_API_KEY`                  | /       | Yes       | VMRay API Key                                                                               |
| Inititla Fetch Date                  | initial_fetch_date                  | `VMRAY_INITIAL_FETCH_DATE`           | YYYY-MM-DD   | Yes       | Fetch feeds from date (ex: 2025-09-09) |
| VMRay Sample Verdict | sample_verdict | `VMRAY_SAMPLE_VERDICT` | malicious    | Yes       | Samples can be pulled based on verdict.   Supported values include malicious, suspicious
| VMRay IOCs Verdict | iocs_verdict | `VMRAY_IOCS_VERDICT` | malicious    | Yes       | IOCs can be pulled based on their verdict.   Supported values include malicious, suspicious                    |
| VMRay Default TLP | default_tlp | `VMRAY_DEFAULT_TLP` | TLP:AMBER    | Yes       | TLP markings can be assigned in OpenCTI platform. Supported values include TLP:AMBER, TLP:RED, TLP:WHITE, TLP:GREEN                   |
| VMRay Threat Names color | threat_names_color | `VMRAY_THREAT_NAMES_COLOR` | #d60904    | Yes       | Configurable color for threat names labels
| VMRay Classifications color | classifications_color | `VMRAY_CLASSIFICATIONS_COLOR` | #fa560a    | Yes       | Configurable color for family classifications labels
| VMRay VTI color | vti_color | `VMRAY_VTI_COLOR` | #40f5ef    | Yes       | Configurable color for VMRay Threat Identifier labels
| VMRay MITRE color | mitre_color | `VMRAY_MITRE_COLOR` | #a9f723    | Yes       | Configurable color for MITRE Technique ID labels

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.9.0`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
docker build . -t opencti/connector-vmray-platform:latest
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

Then, start the connector from vmray-platform/src:

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

The connector pulls feeds from VMRay Platform and ingests into OpenCTI.


## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.e., `self.helper.connector_logger.error("An error message")`.