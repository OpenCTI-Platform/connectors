# OpenCTI Doppel Alert and Takedown Connector

The **Doppel Alert and Takedown** connector is an OpenCTI internal enrichment connector
that integrates with [Doppel](https://www.doppel.com). From a suspicious observable
(a **URL** or a **Domain-Name**), triggered manually by an analyst, automatically
(auto-enrichment) or from a playbook, the connector:

1. Creates an alert in Doppel (`POST /v1/alert`).
2. Automatically requests a takedown for that alert (`PUT /v1/alert?entity=...` with
   `queue_state: "actioned"`).
3. Enriches the observable in OpenCTI with an **external reference** to the Doppel
   alert and a **Note** summarizing the created alert and the takedown request.

Table of Contents

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

## Introduction

Doppel is a brand protection and digital risk protection platform used to detect and
take down phishing sites, fraudulent domains and other online threats. This connector
lets OpenCTI users escalate a suspicious URL or domain to Doppel directly from the
platform: it opens a Doppel alert and requests a takedown in a single enrichment.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 6.8.12
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library matching your OpenCTI version
- A Doppel account with an API key and a user API key

## Configuration variables

Configuration options are set either in `docker-compose.yml` (for Docker) or in
`config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter       | config.yml | Docker environment variable | Default                     | Mandatory | Description                                                             |
| --------------- | ---------- | --------------------------- |-----------------------------| --------- | ---------------------------------------------------------------------- |
| Connector ID    | id         | `CONNECTOR_ID`              | /                           | Yes       | A unique `UUIDv4` identifier for this connector instance.              |
| Connector Type  | type       | `CONNECTOR_TYPE`            | INTERNAL_ENRICHMENT         | Yes       | Should always be set to `INTERNAL_ENRICHMENT` for this connector.     |
| Connector Name  | name       | `CONNECTOR_NAME`            | Doppel Alert and Takedown   | No        | Name of the connector.                                                 |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           | Url,Domain-Name             | No        | The types of observables the connector enriches.                       |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | error                       | No        | Log verbosity: `debug`, `info`, `warn`, or `error`.                    |
| Connector Auto  | auto       | `CONNECTOR_AUTO`            | false                       | No        | `true` or `false` to enable or disable auto-enrichment of observables. |

### Connector extra parameters environment variables

| Parameter        | config.yml         | Docker environment variable | Default                                        | Mandatory | Description                                                          |
| ---------------- | ------------------ | --------------------------- | ---------------------------------------------- | --------- | ------------------------------------------------------------------- |
| API key          | api_key            | `DOPPEL_API_KEY`            | /                                              | Yes       | Doppel API key, sent as the `x-api-key` header.                     |
| User API key     | user_api_key       | `DOPPEL_USER_API_KEY`       | /                                              | Yes       | Doppel user API key, sent as the `x-user-api-key` header.           |
| API base URL     | api_base_url       | `DOPPEL_API_BASE_URL`       | `https://api.doppel.com`                       | No        | Doppel API base URL.                                                |
| Tags             | tags               | `DOPPEL_TAGS`               | empty                                          | No        | Comma-separated list of tags added to every alert created.          |
| Takedown comment | takedown_comment   | `DOPPEL_TAKEDOWN_COMMENT`   | `Confirmed by OpenCTI — requesting takedown.`  | No        | Comment sent to Doppel with the takedown request.                   |
| Max TLP level    | max_tlp            | `DOPPEL_MAX_TLP`            | empty (no limit)                               | No        | Max TLP of the observables the connector is allowed to enrich. Values: `TLP:CLEAR`, `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, `TLP:RED`. Empty means no limit. |

## Deployment

### Docker Deployment

Before building the Docker container, set the version of pycti in `requirements.txt`
equal to whatever version of OpenCTI you're running.

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-doppel-alert-takedown:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configuration for your environment, then start the container:

```shell
docker compose up -d
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`. Replace the
`ChangeMe` values with your configuration.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r src/requirements.txt
```

Then start the connector from the `src` directory:

```shell
python3 main.py
```

## Usage

To trigger enrichment manually, open a URL or Domain-Name observable in OpenCTI and run
the **Doppel Alert and Takedown** enrichment from the observable's enrichment menu. To run
it automatically on every new/updated in-scope observable, set `CONNECTOR_AUTO=true`.
The connector is also playbook compatible and can be added as a step in a playbook.

## Behavior

For each in-scope observable (URL or Domain-Name), the connector:

- maps the OpenCTI observable type to the Doppel `entity_type`
  (`url` → `url`, `domain-name` → `domain`);
- creates a Doppel alert with the configured tags;
- requests a takedown for the alert using the configured comment;
- returns a STIX bundle containing the observable enriched with an external reference to
  the Doppel alert (`doppel_link`) and a Note summarizing the alert and takedown request.

If the takedown request fails, the alert creation is still recorded and the Note reflects
the failure; the observable is always returned so playbooks are not interrupted.

## Debugging

The connector can be debugged by setting the appropriate log level. Logging messages can
be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, e.g.
`self.helper.connector_logger.error("An error message")`.
