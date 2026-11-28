# OpenCTI OffSeq Mirage Connector

Table of Contents

- [OpenCTI OffSeq Mirage Connector](#opencti-offseq-mirage-connector)
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

[OffSeq](https://offseq.com) runs the Mirage honeypot network and publishes what it captures as the
[Mirage Feed](https://feeds.offseq.com), a free daily STIX 2.1 feed under CC BY 4.0. This connector
imports that feed:

| Content | OpenCTI objects |
|---|---|
| Attacker addresses | `Indicator` (IPv4-Addr) |
| Payload and download URLs seen in exploit traffic | `Indicator` (Url) |
| Payload file hashes | `Indicator` (StixFile, SHA-256) |
| ATT&CK techniques each attacker used | `Attack-Pattern`, `indicates` relationship |
| CVEs an attacker exploited | `Vulnerability` (CISA KEV flag), `related-to` relationship |

An address is listed only after it completed a TCP handshake and sent application data to at least
3 sensors in 2 networks within 7 days. It expires 7 days after its last activity. Known research
scanners and VPN/Tor exits are excluded. Each indicator carries a confidence score (imported as the
OpenCTI score) and a `valid_until` date, so OpenCTI's indicator decay matches the feed.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- No API key or account: the feed is public.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-offseq-mirage:latest
```

Set `OPENCTI_URL`, `OPENCTI_TOKEN` and `CONNECTOR_ID` in `docker-compose.yml`, then:

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

The connector runs on the interval in `CONNECTOR_DURATION_PERIOD` (default six hours). The feed is
rebuilt once a day; a run that finds the same bundle as the previous run sends nothing.

## Behavior

Each run downloads the current bundle and sends it in batches of `OFFSEQ_MIRAGE_BATCH_SIZE` indicators
(default 1000). The `OffSeq` organization author, the TLP marking (default `clear`) and the
techniques and CVEs referenced by a batch are included in every batch.

- `OFFSEQ_MIRAGE_CREATE_OBSERVABLES` (default true) also creates the observable behind each indicator,
  with a `based-on` relationship.
- `OFFSEQ_MIRAGE_IMPORT_RELATIONSHIPS` (default true) imports the techniques and CVEs. Set it to false to
  import indicators only.

All STIX ids are generated deterministically, so repeated imports update the same objects.

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug`. A skipped indicator is logged at WARNING with its feed id and the
reason; the rest of the run continues.

## Additional information

- Feed, formats and listing rules: https://feeds.offseq.com
- Feed source and changelog: https://github.com/offseq/mirage-feed
- Removal requests and questions: support@offseq.com
