# OpenCTI Palo Alto Cortex XDR Intel Connector

## Table of Contents

- [OpenCTI Palo Alto Cortex XDR Intel Connector](#opencti-palo-alto-cortex-xdr-intel-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Getting the Cortex XDR API base URL](#getting-the-cortex-xdr-api-base-url)
    - [Getting the Cortex XDR API credentials](#getting-the-cortex-xdr-api-credentials)
  - [Configuration variables](#configuration-variables)


## Introduction

Palo Alto Cortex XDR is an extended detection and response (XDR) platform that integrates endpoint,
network, and cloud data to detect, investigate, and respond to threats across the enterprise.

This connector listens to an OpenCTI live stream and synchronizes indicators as Indicators of
Compromise (IOCs) in Palo Alto Cortex XDR.

## Installation

### Requirements

- OpenCTI Platform >= 7.260811.0
- A Palo Alto Cortex XDR tenant with API access enabled
- A Cortex XDR API Key (**Advanced** security level) and its associated Key ID

### Getting the Cortex XDR API base URL

The connector's `api_base_url` is built from your Cortex XDR tenant's FQDN:

1. In the Cortex XDR management console, go to **Settings** -> **Configurations** -> **API Keys**.
2. Note your tenant's FQDN, displayed at the top of the API Keys page (e.g. `xdr.eu.paloaltonetworks.com`).
3. Prefix it with `api-` and `https://` to build the base URL, i.e. `https://api-<fqdn>`.

See [Get Your FQDN](https://cortex-docs.paloaltonetworks.com/xdr-5-api/get-your-fqdn) for details.

### Getting the Cortex XDR API credentials

1. In the Cortex XDR management console, go to **Settings** -> **Configurations** -> **API Keys** -> **New Key**.
2. Select **Advanced** as the security level (**Standard** keys are not supported by this connector).
3. Copy the generated **API Key** (`api_key`) and its **Key ID** (`api_key_id`); the API Key is only shown once
   and cannot be retrieved again.
4. Use these values, together with the base URL above, to sign every request: the Key ID is sent as the
   `x-xdr-auth-id` header, and the Key is used to compute the `Authorization` header.

See [Make Your First API Call](https://cortex-docs.paloaltonetworks.com/xdr-5-api/make-your-first-api-call)
for further details on Cortex XDR API authentication.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding these variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

