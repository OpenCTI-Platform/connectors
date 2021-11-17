# OpenCTI IVRE Connector

## About IVRE

[IVRE](https://ivre.rocks) is an
[open-source](https://github.com/ivre/ivre) network recon framework,
which makes it easy to build self-hosted, fully controlled
alternatives to services such as Shodan, ZoomEye, Censys (wide network
scans), Greynoise (scanners monitoring) and/or PassiveDNS.

See [IVRE's web site](https://ivre.rocks/) and [some use
cases](https://doc.ivre.rocks/en/latest/usage/use-cases.html) to learn
more about IVRE.

## Examples

The connector creates relationships between observables, and adds new
observables.

Here are two graphs from fictitious investigations based on data from IVRE:

![Investigation graph from ivre scans results](screenshot-scans.png)
![Investigation graph from ivre passive results](screenshot-passive.png)

## Installation

### Requirements

- OpenCTI Platform
- Access to an IVRE instance (either to the database directly or via the web API)

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                            |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                                       |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                            |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                     |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `INTERNAL_ENRICHMENT` (this is the connector type).                                                                                                            |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | The name of the IVRE connector instance, to identify it if you have multiple IVRE connectors.                                                                          |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scopes: `autonomous-system`, `domain-name`, `ipv4-addr`, `ipv6-addr`, `mac-addr`, `x509-certificate`                                                         |
| `connector_auto`                     | `CONNECTOR_AUTO`                    | Yes          | Must be `true` or `false` to enable or disable auto-enrichment of observables                                                                                          |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                                                                                         |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                          |
| `ivre_db_url`                        | `IVRE_DB_URL`                       | Yes          | The URL of the IVRE database (e.g., `mongodb://host/ivre` or `http://user:password@host/cgi`); defaults to using IVRE's configuration                                  |
| `ivre_db_url_data`                   | `IVRE_DB_URL_DATA`                  | Yes          | The URL of the IVRE database for the data purpose (e.g., `maxmind:///usr/share/ivre/geoip` or `http://user:password@host/cgi`); defaults to using IVRE's configuration |
| `ivre_db_url_passive`                | `IVRE_DB_URL_PASSIVE`               | Yes          | The URL of the IVRE database for the passive purpose (e.g., `mongodb://host/ivre` or `http://user:password@host/cgi`); defaults to using IVRE's configuration          |
| `ivre_db_url_scans`                  | `IVRE_DB_URL_SCANS`                 | Yes          | The URL of the IVRE database for the scans (nmap) purpose (e.g., `mongodb://host/ivre` or `http://user:password@host/cgi`); defaults to using IVRE's configuration     |
| `ivre_max_tlp`                       | `IVRE_MAX_TLP`                      | Yes          | Do not send any data to this IVRE instance if the TLP of the observable is greater than IVRE_MAX_TLP                                                                   |
| `ivre_use_data`                      | `IVRE_USE_DATA`                     | Yes          | Must be `true` or `false` to enable or disable the use of use of data from the data purpose (MaxMind)                                                                  |
| `ivre_use_passive`                   | `IVRE_USE_PASSIVE`                  | Yes          | Must be `true` or `false` to enable or disable the use of use of data from the passive purpose                                                                         |
| `ivre_use_passive_as`                | `IVRE_USE_PASSIVE_AS`               | Yes          | Must be `true` or `false` to enable or disable the use of use of data from the passive purpose for `autonomous-system` observables                                     |
| `ivre_use_passive_domain`            | `IVRE_USE_PASSIVE_DOMAIN`           | Yes          | Must be `true` or `false` to enable or disable the use of use of data from the passive purpose for `domain-name` observables                                           |
| `ivre_use_scans`                     | `IVRE_USE_SCANS`                    | Yes          | Must be `true` or `false` to enable or disable the use of use of data from the scans (nmap) purpose                                                                    |
| `ivre_use_scans_as`                  | `IVRE_USE_SCANS_AS`                 | Yes          | Must be `true` or `false` to enable or disable the use of use of data from the scans (nmap) purpose for `autonomous-system` observables                                |
| `ivre_use_scans_domain`              | `IVRE_USE_SCANS_DOMAIN`             | Yes          | Must be `true` or `false` to enable or disable the use of use of data from the scans (nmap) purpose for `domain-name` observables                                      |
