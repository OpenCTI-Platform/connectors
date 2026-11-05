# isMalicious Connector

Enriches observables (IPv4, IPv6, Domain) with threat intelligence data from [isMalicious](https://ismalicious.com).

## Description

isMalicious is a threat intelligence platform that aggregates data from multiple sources to identify malicious IPs and domains. This connector queries the isMalicious API to enrich observables with:

- Risk score (0-100) based on multi-source analysis
- Threat category labels (phishing, malware, C2, botnet, ransomware, spam, scam)
- External references linking to detection sources
- Country location entities with sighting relationships

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

The API key is issued from the isMalicious dashboard (Account → Team Management) and sent as the `X-API-KEY` header (see [API Authentication](#api-authentication)).

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
| Score               | Risk score (0-100) returned by the API in `riskScore.score`                                                          |
| Labels              | Threat categories: `malicious`, `phishing`, `malware`, `command-and-control`, `botnet`, `ransomware`, `spam`, `scam` |
| External References | Links to isMalicious report and original detection sources                                                           |
| Description         | Summary of findings: detection count, categories, infrastructure attributes and reputation breakdown                 |
| Location + Sighting | Geographic information when available                                                                                |

Each source listing returned by the API carries a `threatClass`. Only `threat`
listings (the default) count as detections and produce labels. Listings of
class `infrastructure` (cloud ranges, CDNs, Tor exits, DNS resolvers), `policy`
(ads, tracking) or `allowlist` describe what the observable is rather than
accuse it: they are kept as external references (`Listed as: …`) and
summarised in the description as `Infrastructure: cloud, …`.

A missing or invalid `riskScore.score` leaves the existing OpenCTI score
unchanged. The connector does not invent a low score from `malicious=false`
or derive a replacement risk score from detection ratios. With a positive
`ISMALICIOUS_MIN_SCORE`, a response without a score is skipped because the
threshold cannot be evaluated. At the default threshold of zero, its context
is still reported without writing a score. A valid numeric score of zero is
preserved.

`malicious=false` is reported as "not flagged as malicious", not "clean" or
"safe". Missing verdicts are reported as unknown. An absence of detections
is not proof of safety.

## Supported Observable Types

- `IPv4-Addr` - IPv4 addresses
- `IPv6-Addr` - IPv6 addresses
- `Domain-Name` - Domain names

## API Authentication

The enrichment API expects:

- **Base URL:** `https://api.ismalicious.com`
- **Endpoint:** `GET /check?query=<value>&enrichment=standard`
- **Authentication:** `X-API-KEY: <your-api-key>` header
- **User-Agent:** `ismalicious-opencti/<version> (+https://ismalicious.com)`

API keys are issued from the isMalicious dashboard; a free plan with a monthly
lookup quota is available. A rejected key (HTTP 401) or an exhausted quota
(HTTP 429) is reported in the connector logs and the observable is left
unchanged.

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
- Playbooks: the connector can be used in OpenCTI playbooks. An observable it skips (out of scope, TLP too high, enrichment disabled for its type, API failure or score below `ISMALICIOUS_MIN_SCORE`) is passed on unchanged.
