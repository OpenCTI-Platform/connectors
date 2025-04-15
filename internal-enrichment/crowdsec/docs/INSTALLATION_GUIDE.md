![CrowdSec Logo](images/logo_crowdsec.png)

# OpenCTI CrowdSec internal enrichment connector

## Installation Guide

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**

- [Requirements](#requirements)
- [Installation](#installation)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->


## Requirements

- OpenCTI Platform >= 5.3.7
- A CrowdSec CTI API key. See [instructions to obtain it](https://docs.crowdsec.net/docs/next/cti_api/getting_started/#getting-an-api-key)


## Installation

Enabling this connector could be done by launching the `main.py` Python process directly after providing the correct configuration in the `config.yml` file or within a Docker environment using the image `opencti/connector-crowdsec:latest`. 

We provide an example of [docker-compose.yml](https://github.com/crowdsecurity/cs-opencti-internal-enrichment-connector/blob/main/docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI.

A list of all available configurations can be found in the [User Guide](./USER_GUIDE.md). You can define them directly in the OpenCTI `docker-compose.yml` file, or in the `config.yml` file  of this connector, or even in a `.env` file used by OpenCTI `docker-compose` process.



Once activated, you should find CrowdSec as a registered connector by following the path `Data/Ingestion/Connectors`.
