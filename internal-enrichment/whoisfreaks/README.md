# OpenCTI WhoisFreaks Enrichment Connector

An official internal enrichment connector for the **OpenCTI** (Open Cyber Threat Intelligence) platform powered by the **WhoisFreaks API**.

This connector enables security analysts to enrich `Domain-Name`, `IPv4-Addr`, and `IPv6-Addr` observables on demand or via automated OpenCTI playbooks.

---

## Features

- **WHOIS Registration Intelligence**: Fetches live WHOIS records and converts Registrars and Registrants into STIX 2.1 `Identity` SDOs linked via `registered-by` and `owned-by` relationships.
- **DNS Record Mapping**: Parses live DNS responses (A, AAAA, MX, NS, CNAME, TXT) and maps resolutions into the OpenCTI graph using `resolves-to` and `related-to` relationships.
- **Subdomain Discovery**: Maps parent-child domain hierarchies and populates subdomains as related `Domain-Name` observables.
- **SSL/TLS Certificate Metadata**: Extracts X.509 certificate metadata and attaches `X509-Certificate` observables to target domains.
- **IP Geolocation & Reverse DNS**: Translates IPv4/IPv6 observables into STIX `Location` SDOs (`located-at`) and maps reverse DNS domain associations.
- **IP Reputation Context**: Evaluates threat scores and attaches contextual security notes to IP entities.

---

## Configuration Variables

The connector is configured using environment variables (or `.env` / `config.yml`):

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | Yes | - | Base URL of your OpenCTI platform instance (e.g. `http://opencti:4000`). |
| `OPENCTI_TOKEN` | Yes | - | OpenCTI User / Admin API Token for authentication. |
| `CONNECTOR_ID` | Yes | - | A unique UUIDv4 string generated specifically for this connector. |
| `CONNECTOR_NAME` | No | `WhoisFreaks` | Display name of the connector inside the OpenCTI dashboard. |
| `CONNECTOR_TYPE` | No | `INTERNAL_ENRICHMENT` | Connector operational category in OpenCTI. |
| `CONNECTOR_SCOPE` | No | `Domain-Name,IPv4-Addr,IPv6-Addr` | Supported STIX 2.1 entity types. |
| `CONNECTOR_AUTO` | No | `false` | Enable automatic enrichment on observable creation (`true`/`false`). |
| `CONNECTOR_CONFIDENCE_LEVEL` | No | `100` | Confidence score (0-100) assigned to created STIX objects. |
| `CONNECTOR_LOG_LEVEL` | No | `INFO` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `WHOISFREAKS_API_KEY` | Yes | - | Your active WhoisFreaks API key. |

---

## Deployment via Docker Compose

Add the service block below to your OpenCTI stack `docker-compose.yml`:

```yaml
  connector-whoisfreaks:
    image: opencti-connector-whoisfreaks:latest
    container_name: opencti-connector-whoisfreaks
    environment:
      - OPENCTI_URL=http://opencti:4000
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_KEY}
      - CONNECTOR_TYPE=INTERNAL_ENRICHMENT
      - CONNECTOR_NAME=WhoisFreaks
      - CONNECTOR_SCOPE=Domain-Name,IPv4-Addr,IPv6-Addr
      - CONNECTOR_AUTO=false
      - CONNECTOR_CONFIDENCE_LEVEL=100
      - CONNECTOR_LOG_LEVEL=INFO
      - WHOISFREAKS_API_KEY=${WHOISFREAKS_API_KEY}
    depends_on:
      - opencti
    restart: always