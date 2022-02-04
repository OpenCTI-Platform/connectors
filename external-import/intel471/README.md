# OpenCTI Intel 471 Connector

## Description

Intel 471 delivers structured technical and non-technical data and intelligence on cyber threats.

This connector ingests STIX 2.1 objects from the Intel 471's Titan platform.

Intel 471 Website: [https://www.intel471.com](https://www.intel471.com)

## Configuration

### Prerequisites 

Intel 471 account with API credentials.

It is available as part of Intel 471's paid subscriptions. For more information, please contact sales@intel471.com.

### Install

Configuration options can be set either in `docker-compose.yml` or in `config.yml`.

| Docker Env variable   | config variable | Description
| ----------------------|-----------------|------------
| INTEL471_API_USERNAME | api_username    | Titan API username
| INTEL471_API_KEY      | api_key         | Titan API key
| INTEL471_INTERVAL_INDICATORS     | interval_indicators     | Interval for malware indicators in minutes. If not set indicators won't be pulled.
| INTEL471_INITIAL_HISTORY_INDICATORS     | initial_history_indicators     | Interval for malware indicators in minutes. If not set indicators won't be pulled.
| INTEL471_INTERVAL_CVES     | interval_cves     | Ditto.
| INTEL471_INITIAL_HISTORY_CVES     | initial_history_cves     | Ditto.


## Installation

Please refer to [OpenCTI's documentation on connectors](https://www.notion.so/Connectors-4586c588462d4a1fb5e661f2d9837db8).

### Docker

Build a Docker Image using the provided `Dockerfile`. Example: `docker build . -t opencti-intel471:latest`.
Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`
