# OpenCTI Intel 471 Connector

## Description

Intel 471 delivers structured technical and non-technical data and intelligence on cyber threats.

This connector ingests STIX 2.1 objects from the Intel 471's Titan platform.

Intel 471 Website: [https://www.intel471.com](https://www.intel471.com)

At the moment this connector runs two streams:

- `Intel471IndicatorsStream` - fetches malware indicators from `/indicators` API endpoint and produces `Indicator` and `Malware` SDOs related using `Relationship` object.
- `Intel471YARAStream` - fetches YARA rules from `/yara` API endpoint and produces `Indicator` and `Malware` SDOs related using `Relationship` object.
- `Intel471CVEsStream` - fetches CVE reports from `/cve/reports` API endpoint and produces `Vulnerability` SDOs.

Each stream can be enabled/disabled and configured separately. For more details see Configuration section.

## Prerequisites 

Intel 471 account with API credentials.

It is available as part of Intel 471's paid subscriptions. For more information, please contact sales@intel471.com.

## Configuration

Configuration options can be set either as environment variables (also in `docker-compose.yml`) or in `config.yml`.

| Env variable                        | config.yaml variable       | Description
| ------------------------------------|----------------------------|--------------------------------------------------
| INTEL471_API_USERNAME               | api_username               | Titan API username
| INTEL471_API_KEY                    | api_key                    | Titan API key
| INTEL471_INTERVAL_INDICATORS        | interval_indicators        | How often should malware indicators be fetched (in minutes). If not set the stream won't be enabled.
| INTEL471_INITIAL_HISTORY_INDICATORS | initial_history_indicators | Initial date (in epoch milliseconds UTC, e.g. 1643989649000) from which the malware indicators should be fetched on connector's first run or restart. If not set they will be fetched from connector's start date (no historical ones).
| INTEL471_INTERVAL_IOCS              | interval_iocs              | Ditto, but for IOCs (Indicators of compromise).
| INTEL471_INITIAL_HISTORY_IOCS       | initial_history_iocs       | Ditto, but for IOCs.
| INTEL471_INTERVAL_CVES              | interval_cves              | Ditto, but for CVE reports.
| INTEL471_INITIAL_HISTORY_CVES       | initial_history_cves       | Ditto, but for CVE reports.
| INTEL471_INTERVAL_YARA              | interval_yara              | Ditto, but for YARA rules.
| INTEL471_INITIAL_HISTORY_YARA       | initial_history_yara       | Ditto, but for YARA rules.

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other Connector.   
For more information regarding variables please refer to 
the [OpenCTI's documentation on connectors](https://www.notion.so/Connectors-4586c588462d4a1fb5e661f2d9837db8)._

## Installation

For installation process please refer to the [OpenCTI's documentation on connectors](https://www.notion.so/Connectors-4586c588462d4a1fb5e661f2d9837db8).

## Running locally

### Standalone

This connector can run as a standalone python program. It does need to have access to the running OpenCTI API instance
and to the RabbitMQ queue. Provide configuration in `src/config.yaml`, install python [dependencies](src/requirements.txt) and run it by calling [main.py](src/main.py).

### Docker

Build a Docker Image using the provided `Dockerfile`. Example: `docker build . -t connector-intel471:latest`.
Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment.
Then, start the docker container with the provided `docker-compose.yml` or integrate it into the global `docker-compose.yml` file of OpenCTI.

## Usage

Navigate to **Data->Connectors->Intel471** and observe completed works and works in progress. They should start appearing after 
configured intervals (if new data was available in Titan).

To see the indicators created by `Intel471IndicatorsStream` navigate to **Observations->Indicators** and search for `Intel 471`.

To see the CVEs created by `Intel471CVEsStream` navigate to **Arsenal->Vulnerabilities** and search for `Intel 471`.

**Pro-tip**: Creating a new user and API Token for the Connector can help you more easily track which STIX2 objects were created by the Connector.