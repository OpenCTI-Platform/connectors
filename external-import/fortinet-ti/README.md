# Fortinet Import Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

## Description

This connector imports data from the [Fortinet database](https://docs.fortinet.com/document/fortisoar/3.1.3/fortinet-fortiguard-threat-intelligence/785/fortinet-fortiguard-threat-intelligence-v3-1-3)

The connector creates the following OpenCTI entities:

- Indicator (URL, Domain Name, and IPv4),
- Observable URL,
- Observable Domain Name,
- Observable IPv4,
- The Fortinet Organization.

## Additional note

Fortinet have hundreds of thousands of entities without any information on the validity period. It was therefore decided not to retrieve historical data (which could be largely depreciated
). Only new entities are retrieved. This is done by comparing the entities retrieved at the time of the run with those retrieved the day before. Therefore:

- There is no point in setting the `interval` variable other than 24 hours.
- When the connector is first launched, no entity is imported because we don't have the list of entities from the day before. Entities are imported daily starting from the second run (the second day).

## Installation

### Requirements

- OpenCTI Platform >= 6.2.0

### Configuration

| Parameter            | Docker envvar         | Mandatory | Description                                                                       |
|----------------------|-----------------------|-----------|-----------------------------------------------------------------------------------|
| `opencti_url`        | `OPENCTI_URL`         | Yes       | The URL of the OpenCTI platform.                                                  |
| `opencti_token`      | `OPENCTI_TOKEN`       | Yes       | The user token configured in the OpenCTI platform                                 |
| `connector_id`       | `CONNECTOR_ID`        | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                |
| `connector_name`     | `CONNECTOR_NAME`      | Yes       | Option `Fortinet`                                                                 |
| `connector_scope`    | `CONNECTOR_SCOPE`     | Yes       | Supported scope: Template Scope (MIME Type or Stix Object)                        |
| `log_level`          | `CONNECTOR_LOG_LEVEL` | No        | Log output for the connector. Defaults to `INFO`                                  |
| `api_key`            | `FORTINET_API_KEY`    | No        | The user api key configured in Fortinet                                           |
| `url`                | `FORTINET_URL`        | No        | Defaults to `https://premiumapi.fortinet.com/v1/cti/feed/stix2?cc=all`            |
| `interval`           | `FORTINET_INTERVAL`   | No        | Run interval, in hours. Defaults to `24`                                          |
| `ioc_score`          | `FORTINET_IOC_SCORE`  | No        | The score to be set on IOCs. Defaults to `50`                                     |
| `marking_definition` | `FORTINET_MARKING`    | No        | TLP to be applied to created entities (syntax: "TLP:XXX"). Default to `TLP:AMBER` |