# CPE Connector

## Introduction

The [NVD](https://nvd.nist.gov/general/brief-history) is the US government's source for standards-based vulnerability
management data and is a product of the [NIST](https://www.nist.gov/) Computer Security Division, Information Technology
Laboratory.

This data enables the automation of vulnerability management, security measurement, and compliance. NVD includes
databases of vulnerability lists, software vulnerabilities, product names, and severity scores.

**CPE (Common Platform Enumeration)** is a structured naming scheme for information technology systems, software, and packages, designed to provide a consistent and uniform way of identifying and describing them.

The CPE repository is maintained by [NIST NVD](https://nvd.nist.gov/products/cpe) and is freely available.

This connector collects CPE data from the NVD, converts to STIX2 and imports them into OpenCTI at a regular intervals.

## Installation

### Requirements

- OpenCTI Platform >= 5.12.9
- NIST NVD API key

### Request an API Key

To import data (CVE and CPE) from the NVD at a higher speed and use the connector, you need to request an API Key:

- [Request an API Key](https://nvd.nist.gov/developers/request-an-api-key)

## Configuration

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter            | config.yml           | Docker environment variable      | Default                              | Mandatory | Description                                                                                                                                 |
|----------------------|----------------------|----------------------------------|--------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------|
| Connector ID         | id                   | `CONNECTOR_ID`                   | /                                    | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                   |
| Connector Type       | type                 | `CONNECTOR_TYPE`                 | EXTERNAL_IMPORT                      | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                                                                               |
| Connector Name       | name                 | `CONNECTOR_NAME`                 | Common Platform Enumeration          | Yes       | Name of the connector.                                                                                                                      |
| Connector Scope      | scope                | `CONNECTOR_SCOPE`                | software                             | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.                                                    |
| Log Level            | log_level            | `CONNECTOR_LOG_LEVEL`            | info                                 | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                      |

Below are the parameters you'll need to set for CPE connector:

| Parameter              | config.yml         | Docker environment variable | Default                                      | Mandatory | Description                                                                                                                                                         |
|------------------------|--------------------|-----------------------------|----------------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CPE Base URL           | base_url           | `CPE_BASE_URL`              | https://services.nvd.nist.gov/rest/json/cpes/2.0 | Yes       | URL for the CPE API.                                                                                                                                                |
| CPE API Key            | api_key            | `NIST_API_KEY`               | /                                            | Yes       | API Key for the CPE API.                                                                                                                                            |
| CPE Interval           | interval           | `CPE_INTERVAL`              | 6h                                            | Yes       | Interval in hours to check and import new CPEs. Must be strictly greater than 1, advice minimum 6 hours                                                   |