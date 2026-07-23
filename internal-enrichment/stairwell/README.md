# OpenCTI Stairwell Connector (Internal Enrichment)

Internal-enrichment connector that calls Stairwell V1 + V2 APIs to enrich file
hashes, domains, IP addresses, and Autonomous Systems with MalEval verdicts,
AI File Triage, DNS history, IP intelligence, and WHOIS.

## Supported observables

| Observable | Stairwell endpoints |
|---|---|
| `StixFile` | `/v1/objects/{hash}/metadata`, `/v1/objects/{hash}:summarize`, `/v202112/variants/{hash}`, `/v1/objects/{hash}/sightings` |
| `Domain-Name` | `/v1/hostnames/{hostname}/metadata`, `/v2/hostnames/{hostname}`, `/v2/hostnames/{hostname}/whitelist-status` |
| `IPv4-Addr` / `IPv6-Addr` | `/v2/ips/{ip}`, `/v2/ips/{ip}/whois`, `/v2/ips/{ip}/hostnames` |
| `Autonomous-System` | `/v2/asns/{asn}/whois` |

## Requirements

- OpenCTI Platform >= 6.8.12
- A Stairwell API token (Bearer auth)

## Configuration

Configuration is loaded via the `connectors-sdk` settings layer: from
`src/config.yml` if present, otherwise from environment variables.
Environment variables override the file.

### OpenCTI

| Parameter | config.yml | Env var | Required | Default | Description |
|---|---|---|---|---|---|
| OpenCTI URL | `opencti.url` | `OPENCTI_URL` | yes | — | OpenCTI platform URL |
| OpenCTI token | `opencti.token` | `OPENCTI_TOKEN` | yes | — | OpenCTI admin token |

### Connector

| Parameter | config.yml | Env var | Required | Default | Description |
|---|---|---|---|---|---|
| Connector ID | `connector.id` | `CONNECTOR_ID` | yes | — | UUIDv4 unique to this instance |
| Connector type | `connector.type` | `CONNECTOR_TYPE` | yes | `INTERNAL_ENRICHMENT` | Must be `INTERNAL_ENRICHMENT` |
| Connector name | `connector.name` | `CONNECTOR_NAME` | yes | `Stairwell` | Display name in OpenCTI |
| Connector scope | `connector.scope` | `CONNECTOR_SCOPE` | yes | `StixFile,Domain-Name,IPv4-Addr,IPv6-Addr,Autonomous-System` | Observable types this connector handles |
| Auto enrich | `connector.auto` | `CONNECTOR_AUTO` | no | `false` | Enrich every newly-created in-scope observable |
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn`, `error` |

### Stairwell

| Parameter | config.yml | Env var | Required | Default | Description |
|---|---|---|---|---|---|
| API token | `stairwell.api_token` | `STAIRWELL_API_TOKEN` | yes | — | Stairwell API token |
| API base URL | `stairwell.api_base_url` | `STAIRWELL_API_BASE_URL` | no | `https://app.stairwell.com` | Override for staging |
| Organization ID | `stairwell.organization_id` | `STAIRWELL_ORGANIZATION_ID` | no | — | Adds rate-limit header |
| User ID | `stairwell.user_id` | `STAIRWELL_USER_ID` | no | — | Adds rate-limit header |
| Default TLP | `stairwell.default_tlp` | `STAIRWELL_DEFAULT_TLP` | no | `amber` | `clear`, `green`, `amber`, `amber+strict`, `red` |
| Max TLP | `stairwell.max_tlp_level` | `STAIRWELL_MAX_TLP_LEVEL` | no | `red` | Max TLP of an observable the connector will enrich |
| Variant limit | `stairwell.variant_limit` | `STAIRWELL_VARIANT_LIMIT` | no | `25` | Max variant SCOs per file enrichment (`0` disables) |
| Resolutions limit | `stairwell.resolutions_limit` | `STAIRWELL_RESOLUTIONS_LIMIT` | no | `50` | Max DNS resolution rows per domain (`0` disables) |
| Sightings limit | `stairwell.sightings_limit` | `STAIRWELL_SIGHTINGS_LIMIT` | no | `100` | Max unique assets per file (`0` disables sightings) |

## Behavior

- **Manual trigger by default.** Set `CONNECTOR_AUTO=true` to enrich every
  newly-created observable in scope. High-volume tenants should keep this off.
- **Score writes are monotonic.** A MalEval verdict only raises
  `x_opencti_score`, never lowers it.
- **Empty results** (hash not in Stairwell corpus) attach a
  `stairwell:not-found` label and an `external_reference` to the Stairwell
  search UI; no Notes are created.
- **Errors** (5xx, network failure, 401) are logged; the source observable is
  left unchanged and no STIX is written.
- **Sightings** for file observables are aggregated per asset: each unique
  Stairwell-managed host that has seen the hash becomes one Sighting SDO
  (`first_seen` / `last_seen` / `count` from the per-asset event window).
- **File metadata** from `/v1/objects/{hash}/metadata` is mapped onto the file
  observable: `name`, `size`, `mime_type`, plus custom Stairwell properties
  (`x_stairwell_magic`, `x_stairwell_imphash`, `x_stairwell_tlsh`,
  `x_stairwell_shannon_entropy`, `x_stairwell_first_seen`,
  `x_stairwell_environments`). Stairwell analyst tags become labels prefixed
  `stairwell:tag:`. **Detonation data is intentionally excluded.**

## Installation

### Via Docker

Build:

```bash
docker build -t opencti/connector-stairwell:latest .
```

Then add the service from `docker-compose.yml` to your OpenCTI deployment.

### Local development

```bash
cd src
pip install -r requirements.txt
cp config.yml.sample config.yml   # edit values
python3 main.py
```

## Tests

```bash
cd src
pip install -r requirements.txt -r tests/test-requirements.txt
PYTHONPATH=. pytest tests/
```
