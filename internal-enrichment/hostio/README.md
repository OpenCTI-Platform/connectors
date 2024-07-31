# HostIO Connector for OpenCTI
The HostIO Connector is an internal enrichment connector for OpenCTI, designed to enhance cyber threat intelligence by enriching IP addresses and domain names using HostIO's domain data and IPinfo's IP data services. This connector fetches and integrates detailed information about IP addresses and domain names into OpenCTI, allowing analysts to gain deeper insights into cyber threats.

## Installation

### Requirements
- OpenCTI Platform >= 6.2.9
- Access to HostIO and IPinfo APIs

### Configuration
Configuration parameters for the HostIO Connector are set using environment variables. Some parameters are defined in the `docker-compose.yml` file, as they are not typically changed by end users.

#### Connector Configuration (docker-compose.yml)
| Docker envvar       | Mandatory | Description                                   |
|---------------------|-----------|-----------------------------------------------|
| `CONNECTOR_NAME`    | Yes       | Name displayed in OpenCTI, e.g., "HostIO".    |
| `CONNECTOR_SCOPE`   | Yes       | Comma separated list of scope. Supported scope includes: `IPv4-Addr`, `Domain-Name`, and `IPv6-Addr`. |

#### User-Specified Configuration (.env)
| Docker envvar                    | Mandatory | Description                                                 |
|----------------------------------|-----------|-------------------------------------------------------------|
| `OPENCTI_URL`                    | Yes       | URL of OpenCTI instance.                                    |
| `OPENCTI_TOKEN`                  | Yes       | Admin token for OpenCTI.                                    |
| `CONNECTOR_ID`                   | Yes       | Unique UUIDv4 for the connector.                            |
| `CONNECTOR_CONFIDENCE_LEVEL`     | Yes       | Default confidence level (1-4).                             |
| `CONNECTOR_LOG_LEVEL`            | Yes       | Log level (`debug`, `info`, `warn`, `error`).               |
| `CONNECTOR_UPDATE_EXISTING_DATA` | Yes       | Whether to update existing data or not. (e.g., true, false) |

#### HostIO-Specific Parameters
| Docker envvar          | Mandatory | Description                                                                                   |
|------------------------|-----------|-----------------------------------------------------------------------------------------------|
| `HOSTIO_TOKEN`         | Yes       | Token for HostIO or IPInfo API.                                                               |
| `HOSTIO_LIMIT`         | Yes       | Limit for returned results, update to match the page limit for your subscription (default 5). |
| `HOSTIO_LABELS`        | Yes       | Comma-separated list of labels to add to the entities. e.g., "hostio,osint"                   |
| `HOSTIO_MARKING_REFS`  | Yes       | TLP marking references. e.g., TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED                        |

### Additional Information
The HostIO Connector enriches IP and domain entities in OpenCTI by fetching data from HostIO and IPinfo. Users should be aware of API rate limits and ensure proper API keys are configured. This connector aids in providing contextual information about digital assets involved in cybersecurity incidents.

### STIX Objects Creation

The HostIO Connector creates and manages various STIX objects to represent and link cyber threat intelligence data within OpenCTI. The following STIX objects are handled:
- **AutonomousSystem**: Represents network autonomous systems.
- **DomainName**: Used for domain name entities enriched from HostIO.
- **Identity**: Refers to the identities associated with domains or IP addresses.
- **IPv4Address** and **IPv6Address**: Represents IPv4 and IPv6 addresses enriched from IPinfo or created by Host IO.
- **Location**: Geographical location information related to IP addresses.
- **Relationship**: Links between different STIX objects, indicating relationships like `resolves-to` or `located-at`.
- **Note**: Contains additional information based on the Raw results from HostIO and IPInfo.

