# OpenCTI WhoisFreaks Connector

An official internal enrichment connector for **OpenCTI** (Open Cyber Threat Intelligence platform) powered by **WhoisFreaks**.

This connector allows security analysts to enrich `Domain-Name`, `IPv4-Addr`, and `IPv6-Addr` observables on demand or via OpenCTI automated playbooks.

---

## Features

- **Domain WHOIS Intelligence**: Fetches live WHOIS records and converts Registrars, Registrants, and Name Servers into STIX 2.1 `Identity` and `Domain-Name` objects linked via `registered-by`, `owned-by`, and `related-to` relationships.
- **DNS Record Mapping**: Parses live DNS responses (A, AAAA, CNAME, MX, NS) and maps resolutions directly into the OpenCTI knowledge graph using `resolves-to` and `related-to` STIX relationships.
- **SSL/TLS Certificate Association**: Extracts X.509 certificate metadata and attaches certificate observables (`X509-Certificate`) to target domains or IP addresses.
- **IP Geolocation**: Translates IP addresses into STIX `Location` SDOs with country, city, and GPS coordinates linked via `located-at`.
- **Subdomain Discovery**: Maps parent-child domain hierarchies in STIX 2.1.
- **IP Reputation Scoring**: Adds threat analysis scores as STIX `Note` objects for quick analyst context.

---

## Configuration Variables

The connector is configured using environment variables (or `config.yml` for local development):

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENCTI_URL` | Yes | - | Full URL of your OpenCTI platform instance (e.g. `http://opencti:4000`). |
| `OPENCTI_TOKEN` | Yes | - | OpenCTI User / Admin API Token. |
| `CONNECTOR_ID` | Yes | - | Unique UUIDv4 string for this connector instance. |
| `CONNECTOR_TYPE` | No | `INTERNAL_ENRICHMENT` | OpenCTI connector category. |
| `CONNECTOR_NAME` | No | `WhoisFreaks` | Display name in OpenCTI dashboard. |
| `CONNECTOR_SCOPE` | No | `Domain-Name,IPv4-Addr,IPv6-Addr` | Supported STIX 2.1 observable types. |
| `CONNECTOR_AUTO` | No | `false` | Set to `false` for manual enrichment (quota preservation). |
| `CONNECTOR_CONFIDENCE_LEVEL` | No | `100` | Confidence level assigned to generated STIX entities. |
| `CONNECTOR_LOG_LEVEL` | No | `INFO` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |
| `WHOISFREAKS_API_KEY` | Yes | - | Your WhoisFreaks API Key. |

---

## Deployment via Docker Compose

Add the connector service to your existing OpenCTI `docker-compose.yml` file:

```yaml
  connector-whoisfreaks:
    image: opencti-connector-whoisfreaks:latest
    container_name: opencti-connector-whoisfreaks
    environment:
      - OPENCTI_URL=http://opencti:4000
      - OPENCTI_TOKEN=YOUR_OPENCTI_API_TOKEN
      - CONNECTOR_ID=YOUR_GENERATED_UUIDV4
      - CONNECTOR_TYPE=INTERNAL_ENRICHMENT
      - CONNECTOR_NAME=WhoisFreaks
      - CONNECTOR_SCOPE=Domain-Name,IPv4-Addr,IPv6-Addr
      - CONNECTOR_AUTO=false
      - CONNECTOR_CONFIDENCE_LEVEL=100
      - CONNECTOR_LOG_LEVEL=INFO
      - WHOISFREAKS_API_KEY=YOUR_WHOISFREAKS_API_KEY
    depends_on:
      - opencti
    restart: always