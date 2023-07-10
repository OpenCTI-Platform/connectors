# OpenCTI Abuse-SSL Connector

The connector uses the an Abuse-ssl csv file that lists botnet ips detected based on certain ssl signatures

An SSL certificate can be associated with one or more servers (IP address:port combination). SSLBL collects IP addresses that are running with an SSL certificate blacklisted on SSLBL. These are usually botnet Command&Control servers (C&C). SSLBL hence publishes a blacklist containing these IPs which can be used to detect botnet C2 traffic from infected machines towards the internet, leaving your network. The CSV format is useful if you want to process the blacklisted IP addresses further, e.g. loading them into your SIEM or CTI (or both, don't be shy).

## Installation

### Requirements

- OpenCTI Platform >= 5.9.0

### Configuration

| Parameter                    | Docker envvar                | Mandatory | Description                                                                                   |
| ---------------------------- | ---------------------------- | --------- | --------------------------------------------------------------------------------------------- |
| `opencti_url`                | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`              | `OPENCTI_TOKEN`              | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`               | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_type`             | `CONNECTOR_TYPE`             | Yes       |                                                                                               |
| `connector_name`             | `CONNECTOR_NAME`             | Yes       |                                                                                               |
| `connector_scope`            | `CONNECTOR_SCOPE`            | Yes       |                                                                                               |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | Yes       | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`        | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `abusessl_url`               | `ABUSESSL_URL`               | Yes       | the abuse-ssl csv URL                                                                         |
| `abusessl_interval`          | `ABUSEIPDB_LIMIT`            | Yes       | interval in minutes between 2 collections ( don't go below 5 minutes)                         |

### Debugging

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

### Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->
