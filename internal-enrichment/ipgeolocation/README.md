# OpenCTI IPGeolocation.io Enrichment Connector

Production-quality **internal enrichment** connector that transforms
IPGeolocation.io v3 threat intelligence into semantically rich STIX 2.1
knowledge within OpenCTI.

## Features

### Data Sources

Consumes four IPGeolocation.io v3 APIs in a single enrichment:

| API                | Data                                                     | Credits |
|--------------------|----------------------------------------------------------|---------|
| IP Location API    | Geo, ASN, company, timezone, network, currency, hostname | 1       |
| IP Security API    | Threat score, VPN, proxy, TOR, bot, spam, attacker flags | 2       |
| ASN API            | Routes, peers, upstreams, downstreams, WHOIS, registry   | 1       |
| Abuse Contact API  | Abuse email, phone, organization, address, route         | 1       |

### Enrichment Scope

| Observable Type | Supported |
|-----------------|-----------|
| IPv4-Addr       | ✅         |
| IPv6-Addr       | ✅         |

### STIX Objects Created

| Object Type        | Description                                    |
|--------------------|------------------------------------------------|
| Location (Country) | Country with ISO code, continent, EU membership|
| Location (City)    | City with lat/lon coordinates, postal code     |
| Autonomous System  | ASN number, name, registry, allocation date    |
| Identity (Org)     | ISP/Company/Hosting provider                   |
| Identity (Cloud)   | Cloud infrastructure provider                  |
| Identity (Abuse)   | Abuse contact with email, phone, address       |
| Domain-Name        | Hostname resolved from the IP                  |
| Indicator          | STIX pattern with threat score (configurable)  |
| Note               | Rich markdown analyst summary                  |
| Opinion            | Risk opinion (low→strongly-disagree, etc.)     |
| Relationship       | located-at, belongs-to, resolves-to, etc.      |
| Labels             | vpn, tor, proxy, known-attacker, risk:high...  |

### Differentiators

Unlike basic IP enrichment connectors, this connector provides:

1. **Security Narrative** — instead of raw booleans, generates analyst text
   like *"This address originates from a commercial VPN (Nord VPN) hosted on
   cloud infrastructure and has been flagged as known attacker."*
2. **Risk Explanation** — every score comes with a human-readable explanation
   listing contributing factors and their weights.
3. **Infrastructure Profile** — categorizes the IP as Hosting, ISP, Business,
   Education, Mobile, etc.
4. **Network Context** — ASN peers, upstreams, downstreams, routes, WHOIS.
5. **Abuse Workflow** — clickable abuse contact note with email, phone, and
   recommended reporting target.
6. **Geo Intelligence** — coordinates, accuracy radius, confidence, timezone.
7. **Timeline** — when the IP was last seen as VPN, proxy, when ASN allocated.
8. **Confidence Explanation** — why the enrichment is reliable.
9. **Credit Optimization** — single-call vs dedicated-endpoint modes.

---

## Quick Start

### Docker Compose (recommended)

1. Copy `docker-compose.yml` into your OpenCTI deployment.
2. Set environment variables (or use `.env`):

```env
OPENCTI_ADMIN_TOKEN=your-opencti-token
IPGEOLOCATION_CONNECTOR_ID=a-uuid-v4
IPGEOLOCATION_API_KEY=your-ipgeolocation-key
```

3. Start:

```bash
docker compose up -d connector-ipgeolocation
```

### Manual (Python)

```bash
pip install -r requirements.txt
cp config.yml.sample config.yml
# Edit config.yml with your credentials
python -m src.main
```

---

## Configuration Reference

### Core Settings

| Env Variable                     | YAML Path                      | Default         | Description                        |
|----------------------------------|--------------------------------|-----------------|------------------------------------|
| `OPENCTI_URL`                    | `opencti.url`                  | —               | OpenCTI platform URL               |
| `OPENCTI_TOKEN`                  | `opencti.token`                | —               | API token                          |
| `CONNECTOR_ID`                   | `connector.id`                 | —               | Unique UUIDv4                      |
| `CONNECTOR_NAME`                 | `connector.name`               | IPGeolocation.io| Display name                       |
| `CONNECTOR_SCOPE`                | `connector.scope`              | IPv4-Addr,IPv6-Addr | Observable types              |
| `CONNECTOR_AUTO`                 | `connector.auto`               | false           | Auto-enrich on ingest              |
| `CONNECTOR_CONFIDENCE_LEVEL`     | `connector.confidence_level`   | 80              | Connector confidence (0-100)       |

### API Settings

| Env Variable                         | YAML Path                          | Default | Description                    |
|--------------------------------------|------------------------------------|---------|--------------------------------|
| `IPGEOLOCATION_API_KEY`              | `ipgeolocation.api_key`            | —       | API key                        |
| `IPGEOLOCATION_BASE_URL`             | `ipgeolocation.base_url`           | https://api.ipgeolocation.io | API base |
| `IPGEOLOCATION_TIMEOUT`              | `ipgeolocation.timeout`            | 30      | HTTP timeout (seconds)         |
| `IPGEOLOCATION_MAX_RETRIES`          | `ipgeolocation.max_retries`        | 3       | Max retry attempts             |

### API Modules

| Env Variable                         | Default | Description                         |
|--------------------------------------|---------|-------------------------------------|
| `IPGEOLOCATION_USE_GEO_API`          | true    | Enable geolocation enrichment       |
| `IPGEOLOCATION_USE_SECURITY_API`     | true    | Enable threat detection             |
| `IPGEOLOCATION_USE_ASN_API`          | true    | Enable detailed ASN data            |
| `IPGEOLOCATION_USE_ABUSE_API`        | true    | Enable abuse contact lookup         |

### Credit Optimization

| Env Variable                         | Default | Description                         |
|--------------------------------------|---------|-------------------------------------|
| `IPGEOLOCATION_SINGLE_CALL_MODE`     | true    | Use unified endpoint (fewer calls)  |

**Single-call mode** (`true`): 2 HTTP calls (ipgeo+asn), ~4 credits
**Dedicated mode** (`false`): 4 HTTP calls, ~5 credits

### Feature Toggles

| Env Variable                              | Default | Description                      |
|-------------------------------------------|---------|----------------------------------|
| `IPGEOLOCATION_CREATE_LABELS`             | true    | Attach labels (vpn, tor, etc.)   |
| `IPGEOLOCATION_CREATE_INDICATORS`         | true    | Create STIX indicators           |
| `IPGEOLOCATION_CREATE_RELATIONSHIPS`      | true    | Create STIX relationships        |
| `IPGEOLOCATION_CREATE_NOTES`              | true    | Create markdown analyst notes    |
| `IPGEOLOCATION_CREATE_OPINIONS`           | false   | Create risk opinions             |
| `IPGEOLOCATION_CREATE_SUMMARY`            | true    | Include summary in notes         |

### Thresholds

| Env Variable                              | Default | Description                      |
|-------------------------------------------|---------|----------------------------------|
| `IPGEOLOCATION_MIN_THREAT_SCORE`          | 0       | Skip enrichment below this score |
| `IPGEOLOCATION_INDICATOR_THREAT_THRESHOLD`| 50      | Create indicator only above this |

### TLP

| Env Variable                         | Default   | Description                       |
|--------------------------------------|-----------|-----------------------------------|
| `IPGEOLOCATION_MAX_TLP`              | TLP:AMBER | Max TLP to process                |
| `IPGEOLOCATION_DEFAULT_MARKING`      | TLP:WHITE | Default marking for created objects|

---

## Risk Scoring

The connector uses a weighted additive model. See
[docs/RISK_SCORING.md](docs/RISK_SCORING.md) for the full algorithm.

| Score | Level    | Meaning                                      |
|-------|----------|----------------------------------------------|
| 0-20  | Low      | No significant threat signals                |
| 21-50 | Medium   | Some anonymization or minor flags            |
| 51-80 | High     | Multiple threat signals present              |
| 81+   | Critical | Strong indicators of malicious infrastructure|

---

## Testing

```bash
pip install pytest
pytest tests/ -v
```

---

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full component diagram.

---

## License

Apache 2.0
