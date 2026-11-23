# OpenCTI SoChain Connector

Table of Contents

- [OpenCTI SoChain Connector](#opencti-sochain-connector)
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

This connector enriches `Cryptocurrency-Wallet` observables that hold a Bitcoin,
Litecoin, Dogecoin or Zcash (transparent) address, using the
[SoChain API](https://sochain.com/docs). It adds the address's balance,
transaction counts and first and last activity, and flags addresses targeted
by address poisoning.

## Installation

### Requirements

- Python >= 3.11
- OpenCTI Platform >= 6.8.12
- [`pycti`](https://pypi.org/project/pycti/) library matching your OpenCTI version
- [`connectors-sdk`](https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk) library matching your OpenCTI version

An API key is optional. Without one, SoChain allows 2,500 lookups a day per IP.
A free account gives 75,000 requests a month, and paid plans more: get a key at
https://sochain.com/dashboard and set `SOCHAIN_API_KEY`.

## Configuration variables

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

| Parameter         | config.yml        | Docker environment variable | Default                      | Description                                                                                     |
|-------------------|-------------------|-----------------------------|------------------------------|-------------------------------------------------------------------------------------------------|
| API base URL      | `api_base_url`    | `SOCHAIN_API_BASE_URL`      | `https://sochain.com/api/v3` | SoChain API v3 base URL.                                                                        |
| API key           | `api_key`         | `SOCHAIN_API_KEY`           | empty                        | Optional, sent as the `API-KEY` header. Get one at https://sochain.com/dashboard.               |
| Check poisoning   | `check_poisoning` | `SOCHAIN_CHECK_POISONING`   | `true`                       | Check the address for address poisoning and add a note listing the look-alike addresses.        |

`CONNECTOR_AUTO` defaults to `false`, so lookups only run when you ask for them.
Turn it on to enrich every new wallet observable; with many observables, use an
API key.

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
docker build . -t opencti/connector-sochain:latest
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
pip3 install -r src/requirements.txt
```

Then, start the connector from `src` directory:

```shell
python3 main.py
```

## Usage

Open a `Cryptocurrency-Wallet` observable in OpenCTI, click the enrichment
button and select SoChain. With `CONNECTOR_AUTO=true`, new wallet observables
are enriched when they are created. The connector also works as a playbook
step.

## Behavior

The network is read from the address format:

| Network  | Address starts with      |
|----------|--------------------------|
| Bitcoin  | `1`, `3`, `bc1`          |
| Litecoin | `L`, `M`, `ltc1`         |
| Dogecoin | `D`, `A`, `9`            |
| Zcash    | `t1`, `t3` (transparent) |

Other values (Ethereum addresses, Zcash shielded addresses, testnet
addresses) are skipped without a lookup. An address starting with `3` is
looked up on Bitcoin.

For a supported address, the connector:

- writes a Markdown summary to the observable's description: confirmed and
  unconfirmed balance, total received, transaction count (sending and
  receiving), and the block and time of its first and last transaction;
- adds an external reference to the address page on sochain.com;
- when `SOCHAIN_CHECK_POISONING` is on and look-alike addresses sent the
  address dust, adds the `address-poisoning` label and a note listing each
  look-alike, the address it imitates and the dust transaction. The note keeps
  the same ID for an address, so a later enrichment updates it.

Amounts are shown as SoChain returns them, in coin units with 8 decimals.

Each enrichment makes up to two API calls: `/address_summary` and, when the
poisoning check is on, `/address_poisoning`. An address SoChain doesn't know
is skipped. A rate limit (HTTP 429) or a refused key (HTTP 401) fails the
work with SoChain's message; in a playbook, the bundle is passed on unchanged.

## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

## Additional information

- API documentation: https://sochain.com/docs
- Plans and limits: https://sochain.com/pricing
