# Infoblox Import Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

This connector imports data from the [Infoblox database](https://www.infoblox.com/)

The connector creates the following OpenCTI entities:

- Indicator (URL, Domain Name, and IPv4),
- Observable URL,
- Observable Domain Name,
- Observable IPv4,
- The Infoblox Organization.

## Installation

### Requirements

- OpenCTI Platform >= 6.2.0

### Configuration

| Parameter              | Docker env var                   | Mandatory | Description                                                                       |
|------------------------|----------------------------------|-----------|-----------------------------------------------------------------------------------|
| `opencti_url`          | `OPENCTI_URL`                    | Yes       | The URL of the OpenCTI platform.                                                  |
| `opencti_token`        | `OPENCTI_TOKEN`                  | Yes       | The user token configured in the OpenCTI platform                                 |
| `connector_id`         | `CONNECTOR_ID`                   | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                |
| `connector_name`       | `CONNECTOR_NAME`                 | Yes       | Option `Infoblox`                                                                 |
| `connector_scope`      | `CONNECTOR_SCOPE`                | Yes       | Supported scope: Template Scope (MIME Type or Stix Object)                        |
| `log_level`            | `CONNECTOR_LOG_LEVEL`            | No        | Log output for the connector. Defaults to `INFO`                                  |
| `api_key`              | `INFOBLOX_API_KEY`               | No        | The user api key configured in Infoblox                                           |
| `url`                  | `INFOBLOX_URL`                   | No        | Defaults to `https://csp.infoblox.com/tide/api/data/threats`                      |
| `interval`             | `INFOBLOX_INTERVAL`              | No        | Run interval, in hours. Defaults to `12`                                          |
| `ioc_limit`            | `INFOBLOX_IOC_LIMIT`             | No        | Maximum number of IOCs of each type to be retrieved on each run                   |
| `marking_definition`   | `INFOBLOX_MARKING`               | No        | TLP to be applied to created entities (syntax: "TLP:XXX"). Default to `TLP:AMBER` |
