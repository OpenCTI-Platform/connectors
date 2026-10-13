# OpenCTI Stairwell Connector (Internal Enrichment)

Internal-enrichment connector that calls Stairwell V1 + V2 APIs to enrich file
hashes, domains, IP addresses, and Autonomous Systems with MalEval verdicts,
AI File Triage, DNS history, IP intelligence, and WHOIS.

## Supported observables

| Observable | Stairwell endpoints |
|---|---|
| `StixFile` | `/v1/objects/{hash}/metadata`, `/v1/objects/{hash}:summarize`, `/v202112/variants/{hash}`, `/v1/objects/{hash}/sightings` |
| `Domain-Name` | `/v1/hostnames/{hostname}/metadata`, `/v2/hostnames/{hostname}`, `/v2/hostnames/{hostname}/whitelist-status`, `/v2/hostnames/{hostname}/resolutions` |
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
| Log level | `connector.log_level` | `CONNECTOR_LOG_LEVEL` | no | `error` | `debug`, `info`, `warn`, `error` |

### Stairwell

| Parameter | config.yml | Env var | Required | Default | Description |
|---|---|---|---|---|---|
| API token | `stairwell.api_token` | `STAIRWELL_API_TOKEN` | yes | — | Stairwell API token |
| API base URL | `stairwell.api_base_url` | `STAIRWELL_API_BASE_URL` | no | `https://app.stairwell.com` | Override for staging |
| Organization ID | `stairwell.organization_id` | `STAIRWELL_ORGANIZATION_ID` | no | — | Adds rate-limit header |
| User ID | `stairwell.user_id` | `STAIRWELL_USER_ID` | no | — | Adds rate-limit header |
| Default TLP | `stairwell.default_tlp` | `STAIRWELL_DEFAULT_TLP` | no | `amber` | `clear`, `white`, `green`, `amber`, `amber+strict`, `red` |
| Max TLP | `stairwell.max_tlp_level` | `STAIRWELL_MAX_TLP_LEVEL` | no | `amber` | Highest TLP an observable may carry and still be sent to Stairwell: `clear`, `white`, `green`, `amber`, `amber+strict`, `red` |
| Variant limit | `stairwell.variant_limit` | `STAIRWELL_VARIANT_LIMIT` | no | `25` | Max variant SCOs per file enrichment (`0` disables) |
| Resolutions limit | `stairwell.resolutions_limit` | `STAIRWELL_RESOLUTIONS_LIMIT` | no | `50` | Max DNS resolution rows per domain (`0` disables resolutions and the DNS history Note) |
| Sightings limit | `stairwell.sightings_limit` | `STAIRWELL_SIGHTINGS_LIMIT` | no | `0` | Max unique assets per file; `0` (the default) disables sightings. See **Sightings** below before enabling |

## Behavior

- **Max TLP is enforced before any Stairwell call.** An observable with any
  TLP marking above `STAIRWELL_MAX_TLP_LEVEL` (or a TLP marking pycti does not
  recognise) is refused and the enrichment fails with an error; its value
  never leaves OpenCTI. An observable with no TLP marking at all is treated
  as unrestricted and is enriched whatever this setting is.
- **Untrusted text is escaped before it reaches markdown.** File names, YARA
  rule names, certificate fields, network indicators, WHOIS, DNS answers, and
  asset names come from sources an attacker can influence, and OpenCTI renders
  Notes and descriptions as GitHub Flavored Markdown. Identifiers are written
  as code spans, prose values as escaped text, and WHOIS records as fenced
  blocks; none can add links, images, or table cells. The AI triage summary
  keeps its formatting by design, including headings, lists, and blockquotes
  (so text it quotes from a file can still render as a heading or quote), but
  its links, images, and bare URLs are disabled.
- **Manual trigger by default.** Set `CONNECTOR_AUTO=true` to enrich every
  newly-created observable in scope. High-volume tenants should keep this off.
- **Score writes are monotonic.** A MalEval verdict only raises
  `x_opencti_score`, never lowers it.
- **Empty results** (hash not in Stairwell corpus) attach a
  `stairwell:not-found` label and an `external_reference` to the Stairwell
  search UI; no Notes are created.
- **Errors.** If every Stairwell request for an observable fails (5xx, 401,
  network failure), the enrichment fails with an error and no STIX is
  written. A partial failure still enriches with whatever was retrieved.
- **Scope.** Only entity types listed in `CONNECTOR_SCOPE` (and supported by
  the connector) are sent to Stairwell; anything else is refused.
- **Playbooks.** In a playbook, the bundle sent back always carries the
  objects the step received, with the enrichment added when there is one. An
  out-of-scope entity, a refused TLP, no Stairwell data, or an error hands the
  incoming bundle on unchanged so the playbook continues.
- **Sightings are off by default.** With `STAIRWELL_SIGHTINGS_LIMIT` above
  `0`, file sightings are aggregated per asset: each unique Stairwell-managed
  host that has seen the hash becomes one Sighting SDO (`first_seen` /
  `last_seen` / `count` from the per-asset event window) plus an Identity for
  the host. Enabling this writes your asset names, Stairwell environment ids,
  and sample file paths (which often contain usernames) into OpenCTI, at
  `STAIRWELL_DEFAULT_TLP`, visible to everyone who can read the file
  observable.
- **File metadata** from `/v1/objects/{hash}/metadata` is mapped onto the file
  observable: `name`, `size`, `mime_type`, plus custom Stairwell properties
  (`x_stairwell_magic`, `x_stairwell_imphash`, `x_stairwell_tlsh`,
  `x_stairwell_shannon_entropy`, `x_stairwell_first_seen`,
  `x_stairwell_environments`). Stairwell analyst tags become labels prefixed
  `stairwell:tag:`. **Detonation data is intentionally excluded.**
- **IDs are OpenCTI's canonical ones.** SDOs and relationships use pycti's
  `generate_id()`, and observables use spec-standard IDs, so entities from
  other connectors merge with ours. Notes are keyed by their content, which
  always names the observable. Signing certificates are listed in the
  enrichment summary Note (subject, issuer, validity, signature), not created
  as `x509-certificate` observables: Stairwell provides no fingerprint or
  serial number, so a certificate has no stable STIX ID. Every bundle carries
  the TLP marking definitions it references.

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
# From the connector directory:
pip install -r tests/test-requirements.txt
pytest tests/
```
