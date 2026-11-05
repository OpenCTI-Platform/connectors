# OpenCTI HoneyLabs Connector

Table of Contents

- [OpenCTI HoneyLabs Connector](#opencti-honeylabs-connector)
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

[HoneyLabs](https://honeylabs.net) runs its own internet-facing honeypot sensors and publishes
what they capture. This connector imports the resulting indicators over the HoneyLabs TAXII 2.1
server:

| Collection | Contents |
|---|---|
| `attackers` | Union of `exploiters` and, on paid plans, `cve-probers`. The default. |
| `exploiters` | Addresses that ran an exploit or loader command against a sensor in the window. |
| `cve-probers` | Addresses that probed the exploit path of a specific CVE, labelled with the CVE ids (paid plans). |
| `malware-infrastructure` | Loader and command-and-control URLs extracted from captured payloads. |

Every indicator is evidence-backed: known research scanners are excluded, the confidence grades
the amount of observed activity (60 for a single sighting, 90 for a hundred or more), the
description summarises what the sensors saw, labels carry the source network, country and
indicator kind, and an external reference links to the full report on honeylabs.net. Indicators
expire on their own as activity stops.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- A HoneyLabs API key. Accounts are free at https://honeylabs.net/dashboard. The free plan serves
  7 days of history; paid plans serve 30 days and the `cve-probers` collection.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-honeylabs:latest
```

Set the environment variables in `docker-compose.yml` (at least `OPENCTI_URL`, `OPENCTI_TOKEN`,
`CONNECTOR_ID` and `HONEYLABS_API_KEY`), then:

```shell
docker compose up -d
```

### Manual Deployment

Create `config.yml` from `config.yml.sample` and fill in the `ChangeMe` values. Then, in a
virtual environment:

```shell
cd src
pip3 install -r requirements.txt
python3 main.py
```

## Usage

The connector runs on the interval in `CONNECTOR_DURATION_PERIOD` (default one hour). On the
first run it asks the TAXII server for every object added since `HONEYLABS_IMPORT_SINCE`
(default seven days ago); later runs resume from the newest `date_added` seen per collection,
which the connector keeps in its state.

## Behavior

For each configured collection the connector pages through the TAXII objects and creates, per
indicator:

- an `Indicator` (STIX pattern, `main_observable_type` IPv4-Addr or Url, validity window,
  score from the HoneyLabs confidence, labels, kill chain phase, the evidence link as an
  external reference), authored by the `HoneyLabs` organization and marked with the configured
  TLP (default `clear`);
- when `HONEYLABS_CREATE_OBSERVABLES` is true (default), the IPv4 address or URL observable and
  the `based-on` relationship between the two.

Nothing is sent to HoneyLabs except the TAXII requests themselves. HoneyLabs keeps usage
counts per key for quota accounting; TAXII polling is not metered.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. A `401` means the API key was rejected; a `403` on
`cve-probers` means the key's plan does not include it (the `attackers` union then carries
`exploiters` only, which is not an error).

## Additional information

- HoneyLabs TAXII server: https://honeylabs.net/taxii2/
- The same indicators are also available as MISP feeds and as CSV, JSON and text lists:
  https://honeylabs.net/feed/about
