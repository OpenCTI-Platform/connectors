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
| isMalicious API URL | `ISMALICIOUS_API_URL`       | No        | API URL (default: `https://api.ismalicious.com`)               |
| isMalicious API Key | `ISMALICIOUS_API_KEY`       | Yes       | API credential from Dashboard → Account → Team Management (sent as `X-API-KEY`) |
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

## API Authentication

The enrichment API expects:

- **Base URL:** `https://api.ismalicious.com`
- **Endpoint:** `GET /check?query=<value>&enrichment=standard`
- **Authentication:** `X-API-KEY: <your-api-key>` header

Example:

```bash
curl -H "X-API-KEY: <your-api-key>" \
  "https://api.ismalicious.com/check?query=8.8.8.8&enrichment=standard"
```

This connector does **not** use Basic Auth or Bearer tokens for the enrichment API.

## TAXII Feed Ingestion (Bulk Import)

This connector is an **internal enrichment** connector only. It enriches individual observables already present in OpenCTI; it does **not** import STIX bundles or indicators from a TAXII feed.

For scheduled bulk ingestion (e.g. every hour), use isMalicious's **TAXII 2.1 feed** via OpenCTI's built-in TAXII connector or the generic TAXII2 external-import connector:

1. In OpenCTI, go to **Data > Ingestion > TAXII Feeds** and add a new feed.
2. Set the Discovery URL to `https://api.ismalicious.com/taxii2/`
3. For authentication, use one of:
   - **Basic Auth**: username `api`, password = your full API credential from the dashboard (same base64 value as the `X-API-KEY` header)
   - **Bearer token**: same credential value as the token
   - **X-API-KEY header** (generic TAXII2 connector only): the base64 credential shown in Dashboard → Account → Team Management
4. Select the collections to import and set the desired polling interval (e.g. `PT1H`).

For the generic TAXII2 external-import connector, see [external-import/taxii2](../../external-import/taxii2/README.md).

The enrichment connector and the TAXII feed complement each other — use both for full coverage.

## Additional Information

- Website: [https://ismalicious.com](https://ismalicious.com)
- API Documentation: [https://ismalicious.com/api](https://ismalicious.com/api)
