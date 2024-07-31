# OpenCTI Cybersixgill Connector

- ***What it does*** - The Darkfeed is a unique feed of IOCs which are automatically extracted from Cybersixgill’s comprehensive collection of underground web sources.

- ***How it works*** - The IOC’s include file hashes, IP addresses, domains, and URLs. This also includes items such as compromised domains, domains sold on the dark web, links to malware files hosted on underground file-sharing sites, malware hashes, and malicious c&c IPs. And we’ll be adding more!

- ***Special requirements*** - N/A

- ***Use case description*** - Consumers can automatically integrate the IOCs into their existing security infrastructure. This machine-to-machine setup requires no human involvement to block the threats. Furthermore, the data provide early warning of new and otherwise undetected malware threats. So you know what else may be coming, you can hunt for threats inside your network, and you can better understand emerging malware trends, tactics, techniques, and procedures

## Installation

The OpenCTI Cybersixgill connector is a standalone Python process that must have access to the OpenCTI platform and the
RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform
settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration
in the `config.yml` file or within a Docker with the image `opencti/connector-cybersixgill:5.4.0`. We provide an example
of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the
global `docker-compose.yml` file of OpenCTI.

### Requirements

- OpenCTI Platform >= 6.2.9
- Cybersixgill Client ID and Client Secret

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Default | Description                                                                                           |
| ------------------------------------ | ----------------------------------- | ------------ | ------- | ----------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          |  `NA`   | The URL of the OpenCTI platform.                                                                      |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          |  `NA`   | The default admin token configured in the OpenCTI platform parameters file.                           |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          |  `NA`   | A valid arbitrary `UUIDv4` that must be unique for this connector.                                    |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          |  `NA`   | Supported scope: Cybersixgill Scope (MIME Type or Stix Object)                                        |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | `info`  | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).         |
| `client_id`                          | `CYBERSIXGILL_CLIENT_ID`            | Yes          |  `NA`   | The Cybersixgill API Client ID.                                                                       |
| `client_secret`                      | `CYBERSIXGILL_CLIENT_SECRET`        | Yes          |  `NA`   | The Cybersixgill Client Secret.                                                                       |
| `create_observables`                 | `CYBERSIXGILL_CREATE_OBSERVABLES`   | Yes          | `true`  | If true then observables will be created from the Cybersixgill indicators.                            |
| `create_indicators`                  | `CYBERSIXGILL_CREATE_INDICATORS`    | Yes          | `true`  | If true then indicators will be created from the Cybersixgill indicators.                             |
| `fetch_size`                         | `CYBERSIXGILL_FETCH_SIZE`           | Yes          | `2000`  | The indicators count to be fetched from Cybersixgill API.                                             |
| `enable_relationships`               | `CYBERSIXGILL_ENABLE_RELATIONSHIPS` | Yes          | `true`  | If true then the relationships will be created between SDOs.                                          |
| `interval_sec`                       | `CYBERSIXGILL_INTERVAL_SEC`         | Yes          | `300`   | The import interval in seconds.                                                                       |

### Debugging ###

For assistance, to report a bug or request a feature, please contact us via the following:

***Support Portal***: https://www.cybersixgill.com/contact-us/
***Email***: support@cybersixgill.com

### Additional information

N/A
