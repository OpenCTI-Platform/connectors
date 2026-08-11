# OpenCTI Doppel Alert and Takedown Connector

The **Doppel Alert and Takedown** connector is an OpenCTI internal enrichment connector
that integrates with [Doppel](https://www.doppel.com). It supports two explicit
workflows:

- From a suspicious **URL** or **Domain-Name**, it creates an alert in Doppel and
  requests takedown.
- From a Doppel **Incident**, it requests takedown for the already-correlated alert
  without creating a duplicate.

Both workflows set `queue_state: "actioned"` through `PUT /v1/alert` and add an
OpenCTI **Note** summarizing the result. They can be triggered manually or from a
playbook. Observable auto-enrichment remains supported.

Table of Contents

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

## Introduction

Doppel is a brand protection and digital risk protection platform used to detect and
take down phishing sites, fraudulent domains and other online threats. This connector
lets OpenCTI users escalate a suspicious URL or domain to Doppel, or request takedown
for an existing Doppel alert represented by an imported OpenCTI Incident.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 7.260715.0
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library matching your OpenCTI version
- A Doppel account with an API key and a user API key
- For Incident actions, the Doppel external-import connector configured with
  `DOPPEL_ENABLE_INCIDENTS=true`

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

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

To trigger enrichment manually, open a URL, Domain-Name, or eligible Doppel Incident in
OpenCTI and run **Doppel Alert and Takedown** from its enrichment menu. The connector is
also playbook compatible.

Incident support is opt-in. Add `Incident` to `CONNECTOR_SCOPE`, for example:

```text
CONNECTOR_SCOPE=Url,Domain-Name,Incident
CONNECTOR_AUTO=false
CONNECTOR_AUTO_UPDATE=false
```

`CONNECTOR_AUTO` and `CONNECTOR_AUTO_UPDATE` must remain `false` whenever the scope
includes `Incident`, and the connector's **Trigger filters** in OpenCTI must be empty.
The connector verifies these platform settings before every Incident action and fails
closed if any automatic trigger is enabled. This prevents newly imported or refreshed
alerts from automatically requesting takedown. Customers that use automatic URL/Domain
enrichment should run a separate connector instance for explicit Incident actions.

## Behavior

For each in-scope observable (URL or Domain-Name), the connector:

- maps the OpenCTI observable type to the Doppel `entity_type`
  (`url` → `url`, `domain-name` → `domain`);
- creates a Doppel alert with the configured tags;
- requests takedown by the newly created alert ID using the configured comment;
- returns a STIX bundle containing the observable enriched with an external reference to
  the Doppel alert (`doppel_link`) and a Note summarizing the alert and takedown request.

For an in-scope Incident, the connector:

- verifies that the Incident was created from a Doppel alert;
- resolves the Doppel alert ID from its external reference;
- reads the current alert state from Doppel before updating it;
- requests takedown for that existing alert without calling `POST /v1/alert`;
- refuses to resend the request when Doppel already reports it as `actioned` or
  `taken_down`, preventing duplicate comments after retries;
- adds a Note to the Incident recording success or failure.

If a takedown write fails after validation, the alert creation is still recorded for
observable actions and the Note reflects the failure. For Incident actions, the existing
Incident is returned unchanged with a failure Note. Correlation, automation-safety, or
GET preflight failures stop the work before any write and do not create a Note. Playbook
runs continue with their original bundle.

## Debugging

The connector can be debugged by setting the appropriate log level. Logging messages can
be added using `self.helper.connector_logger.{LOG_LEVEL}("Sample message")`, e.g.
`self.helper.connector_logger.error("An error message")`.
