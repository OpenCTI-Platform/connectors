# isMalicious Connector

Enriches observables (IPv4, IPv6, Domain) with threat intelligence data from [isMalicious](https://ismalicious.com).

## Description

isMalicious is a threat intelligence platform that aggregates data from multiple sources to identify malicious IPs and domains. This connector queries the isMalicious API to enrich observables with:

- Risk score (0-100) based on multi-source analysis
- Threat category labels (phishing, malware, C2, botnet, ransomware, spam, scam)
- External references linking to detection sources
- Country location entities with sighting relationships

## Configuration variables

Find below the detailed configuration options:

| Parameter           | Docker envvar               | Mandatory | Description                                                    |
| ------------------- | --------------------------- | --------- | -------------------------------------------------------------- |
| OpenCTI URL         | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform                                |
| OpenCTI Token       | `OPENCTI_TOKEN`             | Yes       | The token of the OpenCTI user                                  |
| Connector ID        | `CONNECTOR_ID`              | No        | A unique `UUIDv4` for this connector (default: auto-generated) |
| Connector Name      | `CONNECTOR_NAME`            | No        | Name shown in OpenCTI (default: `isMalicious`)                 |
| Connector Scope     | `CONNECTOR_SCOPE`           | No        | Observable types (default: `IPv4-Addr,IPv6-Addr,Domain-Name`)  |
| Log Level           | `CONNECTOR_LOG_LEVEL`       | No        | Log level: `debug`, `info`, `warn`, `error` (default: `info`)  |
| Auto Mode           | `CONNECTOR_AUTO`            | No        | Enable automatic enrichment (default: `false`)                 |
| isMalicious API URL | `ISMALICIOUS_API_URL`       | No        | API URL (default: `https://ismalicious.com`)                   |
| isMalicious API Key | `ISMALICIOUS_API_KEY`       | Yes       | Your isMalicious API key                                       |
| Max TLP             | `ISMALICIOUS_MAX_TLP`       | No        | Max TLP to process (default: `TLP:AMBER`)                      |
| Enrich IPv4         | `ISMALICIOUS_ENRICH_IPV4`   | No        | Enrich IPv4 addresses (default: `true`)                        |
| Enrich IPv6         | `ISMALICIOUS_ENRICH_IPV6`   | No        | Enrich IPv6 addresses (default: `true`)                        |
| Enrich Domain       | `ISMALICIOUS_ENRICH_DOMAIN` | No        | Enrich domains (default: `true`)                               |
| Min Score           | `ISMALICIOUS_MIN_SCORE`     | No        | Minimum score to report (default: `0`)                         |

## Deployment

### Docker

Build a Docker Image using the provided `Dockerfile`.

```bash
docker build . -t opencti/connector-ismalicious:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment.

```bash
docker compose up -d
```

### Manual

```bash
cd src
pip install -r requirements.txt
python main.py
```

## Enrichment Data

When an observable is enriched, the connector adds:

| Data                | Description                                                                                                          |
| ------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Score               | Risk score (0-100) based on confidence and threat level                                                              |
| Labels              | Threat categories: `malicious`, `phishing`, `malware`, `command-and-control`, `botnet`, `ransomware`, `spam`, `scam` |
| External References | Links to isMalicious report and original detection sources                                                           |
| Description         | Summary of findings including source count and reputation breakdown                                                  |
| Location + Sighting | Geographic information when available                                                                                |

## Supported Observable Types

- `IPv4-Addr` - IPv4 addresses
- `IPv6-Addr` - IPv6 addresses
- `Domain-Name` - Domain names

## Additional Information

- Website: [https://ismalicious.com](https://ismalicious.com)
- API Documentation: [https://ismalicious.com/api](https://ismalicious.com/api)
