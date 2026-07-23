# Malcore Import Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

The Malcore connector imports malware intelligence data from Malcore into OpenCTI, including file observables, indicators, and malware entities.

## Introduction

This connector imports data from [Malcore](https://malcore.io/)

The connector creates the following OpenCTI entity types:

- Observable File (md5, sha1, and sha256),
- Indicator StixFile (sha256),
- Malware.

## Installation

### Requirements

- OpenCTI Platform >= 7.260722.0

### Configuration

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._
