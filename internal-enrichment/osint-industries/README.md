# OpenCTI OSINT Industries Connector

Table of Contents

- [OpenCTI OSINT Industries Connector](#opencti-osint-industries-connector)
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
  - [Legal and privacy notice](#legal-and-privacy-notice)
  - [Debugging](#debugging)

## Introduction

[OSINT Industries](https://www.osint.industries/) is a digital-footprint and account-discovery service. Given a selector (an email address, phone number, username, or cryptocurrency wallet), it queries 300+ modules and returns the online accounts, profiles, and breach exposures associated with that selector, together with profile details such as creation dates, locations, linked emails/URLs, and profile pictures.

This connector enriches an OpenCTI observable (`Email-Addr`, `Phone-Number`, `User-Account`, or `Cryptocurrency-Wallet`) by querying OSINT Industries and creating, for each discovered account, a `User-Account` observable linked back to the queried observable (a star-shaped model). It also creates the associated `Email-Addr` / `Url` / `Phone-Number` / `Cryptocurrency-Wallet` observables, data-breach notes, human-readable summary notes, and a self-contained HTML report (cards with profile photos) attached to the enriched observable.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- An OSINT Industries API key

## Configuration variables

Configuration parameters can be provided in either `config.yml` (see `config.yml.sample`), `docker-compose.yml` environment variables, or a `.env` file (see `.env.sample`).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The token of the user who represents the connector. |

### Base connector environment variables

| Parameter       | config.yml | Docker environment variable | Default | Mandatory | Description                                                                 |
| --------------- | ---------- | --------------------------- | ------- | --------- | --------------------------------------------------------------------------- |
| Connector ID    | id         | `CONNECTOR_ID`              | /       | Yes       | A unique `UUIDv4` identifier for this connector instance.                    |
| Connector Name  | name       | `CONNECTOR_NAME`            | OSINT Industries | No | Name of the connector.                                                       |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           | Email-Addr,Phone-Number,User-Account,Cryptocurrency-Wallet | No | The types of observables that trigger the connector. |
| Auto            | auto       | `CONNECTOR_AUTO`            | false   | No        | Enable automatic enrichment. Keep `false` for this quota-based paid source.  |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | error   | No        | Verbosity: `debug`, `info`, `warn`, or `error`.                             |

### Connector extra parameters environment variables

| Parameter | config.yml | Docker environment variable | Default                      | Mandatory | Description                                                                         |
| --------- | ---------- | --------------------------- | ---------------------------- | --------- | ---------------------------------------------------------------------------------- |
| API key   | api_key    | `OSINT_INDUSTRIES_API_KEY`  | /                            | Yes       | API key to authenticate to OSINT Industries.                                       |
| Base URL  | base_url   | `OSINT_INDUSTRIES_BASE_URL` | https://api.osint.industries | No        | Base URL of the OSINT Industries API.                                              |
| TLP level | tlp_level  | `OSINT_INDUSTRIES_TLP_LEVEL`| amber+strict                 | No        | TLP applied to imported objects: `clear`, `green`, `amber`, `amber+strict`, `red`. |
| Premium   | premium    | `OSINT_INDUSTRIES_PREMIUM`  | false                        | No        | Query additional premium modules (consumes more credits).                          |

## Deployment

### Docker Deployment

Build a Docker image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-osint-industries:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`:

```shell
docker compose up -d
```

### Manual Deployment

Create a `config.yml` file based on the provided `config.yml.sample`, then install the requirements and run the connector:

```shell
cd src
pip3 install -r requirements.txt
python3 -m src
```

## Usage

After installation, the connector requires manual triggering by default (`CONNECTOR_AUTO=false`, recommended for this paid, quota-based source). Open an observable of a supported type (`Email-Addr`, `Phone-Number`, `User-Account`, or `Cryptocurrency-Wallet`), click the enrichment (cloud) icon at the top right, and select OSINT Industries.

## Behavior

For the enriched observable, the connector:

- queries OSINT Industries for the selector value;
- creates one `User-Account` per discovered account, uniquely identified as `identity [platform]` so that accounts on different platforms (or different selectors on the same platform) never merge;
- creates the related `Email-Addr`, `Url`, `Phone-Number`, and `Cryptocurrency-Wallet` observables found in each module;
- links every created object back to the enriched observable with a `related-to` relationship (star-shaped model);
- adds a `Note` for each data-breach exposure (e.g. Have I Been Pwned);
- adds a global summary `Note` and per-account detail `Note`s rendered as Markdown tables;
- attaches a self-contained HTML report (one card per platform, with profile photos when available) to the enriched observable, visible under the observable's Data tab.

The author of all created objects is the `OSINT Industries` organization, and all objects carry the configured TLP marking.

## Legal and privacy notice

OSINT Industries returns personal data. This connector must only be used for lawful, authorised investigations with a valid legal basis (e.g. GDPR compliance, legal request, or a proper investigative framework). Apply an appropriate TLP marking and restrict access to the enriched data accordingly.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` to increase log verbosity. Common issues:

- `401` / `402` responses indicate an invalid API key or exhausted quota.
- A `functional_error` on relationship types usually means an unsupported relationship; this connector relies on `related-to`, which is accepted between observables.
- Ensure workers are running on the platform, otherwise sent bundles are not ingested.
