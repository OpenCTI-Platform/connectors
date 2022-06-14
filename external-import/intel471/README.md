# OpenCTI Intel 471 Connector

## Description

Intel 471 delivers structured technical and non-technical data and intelligence on cyber threats.

This connector ingests STIX 2.1 objects from Intel 471's Titan cybercrime intelligence platform.

Intel 471 Website: [https://www.intel471.com](https://www.intel471.com)

This connector runs four streams at this time:

| Stream                | Operation                                                                                      | Produced objects
|-----------------------|------------------------------------------------------------------------------------------------|--------------------------------------------------
| Intel471IndicatorsStream | Fetches malware indicators from `/indicators` application programming interface (API) endpoint | `Indicator` and `Malware` SDOs related using `Relationship` object; `URL`, `IPv4Address` or `File` Observable related with the `Indicator` SDO using `Relationship` object
| Intel471YARAStream | Fetches YARA rules from `/yara` API endpoint                                                   | `Indicator` and `Malware` SDOs related using `Relationship` object
| Intel471IOCsStream | Fetches indicators of compromise (IoCs) from `/iocs` API endpoint                              | `Indicator` and `Report` SDOs and either `URL` or `DomainName` Observable. Both `Indicator` and Observable objects are related with the `Report` using `Report`'s internal property `object_refs`. Observable and `Indicator` objects also are related using `Relationship` object
| Intel471CVEsStream | Fetches Common Vulnerabilities and Exposures (CVE) reports from `/cve/reports` API endpoint    | `Vulnerability` SDO

Each stream can be enabled or disabled and configured separately (see "Configuration" section for more details).

## Prerequisites 

Intel 471 account with API credentials.

Available as part of Intel 471's paid subscriptions. For more information, please contact sales@intel471.com.

## Configuration

Configuration options can be set as environment variables, and in `docker-compose.yml`, or in `config.yml`.

| Env variable                        | config.yaml variable       | Description
| ------------------------------------|----------------------------|--------------------------------------------------
| INTEL471_API_USERNAME               | api_username               | Titan API username
| INTEL471_API_KEY                    | api_key                    | Titan API key
| INTEL471_INTERVAL_INDICATORS        | interval_indicators        | How often malware indicators should be fetched in minutes. If not set, the stream will not be enabled.
| INTEL471_INITIAL_HISTORY_INDICATORS | initial_history_indicators | Initial date in epoch milliseconds UTC, such as 1643989649000, the malware indicators should be fetched from on the connector's first run. If not set, they will be fetched from the connector's start date. Excludes historical dates.
| INTEL471_INTERVAL_IOCS              | interval_iocs              | Same as INTEL471_INTERVAL_INDICATORS variable, but for IoCs.
| INTEL471_INITIAL_HISTORY_IOCS       | initial_history_iocs       | Same as INTEL471_INITIAL_HISTORY_INDICATORS variable, but for IoCs.
| INTEL471_INTERVAL_CVES              | interval_cves              | Same as INTEL471_INTERVAL_INDICATORS variable, but for CVE reports.
| INTEL471_INITIAL_HISTORY_CVES       | initial_history_cves       | Same as INTEL471_INITIAL_HISTORY_INDICATORS variable, but for CVE reports.
| INTEL471_INTERVAL_YARA              | interval_yara              | Same as INTEL471_INTERVAL_INDICATORS variable, but for YARA rules.
| INTEL471_INITIAL_HISTORY_YARA       | initial_history_yara       | Same as INTEL471_INITIAL_HISTORY_INDICATORS variable, but for YARA rules.

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.   
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://www.notion.so/Connectors-4586c588462d4a1fb5e661f2d9837db8)._

## Installation

For the installation process, please refer to [OpenCTI's documentation on connectors](https://www.notion.so/Connectors-4586c588462d4a1fb5e661f2d9837db8).

## Running locally

### Stand-alone

This connector can run as a stand-alone Python program. It does require access to the running OpenCTI API instance
and the RabbitMQ queue. Provide configuration in `src/config.yaml`, install Python [dependencies](src/requirements.txt) and run it by calling [main.py](src/main.py).

### Docker

Build a Docker Image using the provided `Dockerfile`. Example: `docker build . -t connector-intel471:latest`.
Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment.
Then, start the docker container with the provided `docker-compose.yml` or integrate it into the global `docker-compose.yml` file of OpenCTI.

## Usage

Navigate to **Data->Connectors->Intel471** and observe completed works and works in progress. They should start to appear after 
configured intervals, if new data was available in Titan.

To see the indicators created by `Intel471IndicatorsStream`, `Intel471IOCsStream` and `Intel471YARAStream`, navigate to **Observations->Indicators**.

To see the malware objects created by `Intel471IndicatorsStream` and `Intel471YARAStream`, navigate to **Arsenal->Malwares**.

To see the Reports created by `Intel471IOCsStream`, navigate to **Analysis->Reports**.

To see the CVEs created by `Intel471CVEsStream`, navigate to **Arsenal->Vulnerabilities**.


**Pro-tip**: Creating a new user and API token for the connector can help you more easily track which STIX2 objects were created by the connector.