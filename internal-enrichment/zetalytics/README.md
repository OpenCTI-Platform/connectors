# Zetalytics DNS Connector for OpenCTI

`zetanalytics_dns` is an OpenCTI internal enrichment connector for the Zetalytics ZoneCruncher API. It enriches domains, hostnames, IPv4 addresses, and IPv6 addresses with passive DNS, live DNS, ASN, subdomain, registration, and nameserver context.

The connector is designed as **one connector package and one container image**, deployed multiple times with different configuration profiles. This allows the same codebase to support analyst-led manual enrichment, controlled playbook enrichment, lightweight automatic enrichment, and deeper investigation workflows without duplicating logic.

---

## What the connector does

The connector takes an observable from OpenCTI, checks whether the observable type and TLP marking are allowed, queries the relevant Zetalytics endpoints, converts the response into STIX 2.1 objects, deduplicates objects and relationships within the run, and sends the enrichment bundle back to OpenCTI.

Supported observable types:

- `Domain-Name`
- `Hostname`
- `IPv4-Addr`
- `IPv6-Addr`

Supported enrichment areas:

- Passive DNS for domains and IPs
- Live DNS lookups
- A, AAAA, CNAME, NS, MX, TXT, and SOA-related records
- Subdomain discovery
- ASN and IP ownership context
- D8S / registration context
- Nameserver glue records
- Optional deeper pivots depending on deployment mode

---

## Package layout

The connector package is named `zetanalytics_dns`.

| File | Purpose |
|---|---|
| `settings.py` | Configuration loading and validation. Defines `_ConnectorConfig` and `_ZetalyticsConfig`. All connector-specific environment variables use the `ZETALYTICS_*` convention, including mode, result limits, endpoint flags, TLP, and confidence. |
| `client.py` | Thin wrapper around the `zetalytics` SDK. Provides one method per endpoint and calculates the lookback date before sending requests. |
| `converter.py` | Converts Zetalytics API responses into STIX 2.1 objects. Deduplicates observables and relationships within each run. Handles A, AAAA, CNAME, NS, MX, TXT, SOA records, passive DNS, ASN context, subdomains, D8S, and NS glue. |
| `connector.py` | Main connector orchestration. Applies TLP and scope guards, dispatches to `_enrich_domain` or `_enrich_ip` depending on observable type, and guards each endpoint call so a single API failure does not abort the whole enrichment run. |
| `__main__.py` | Entry point containing `main()`, consumed by the `zetalytics-dns-connector` console script. |

---

## How it works

At a high level, the connector flow is:

```text
OpenCTI enrichment request
  └─ connector.py receives observable
      ├─ load and validate settings
      ├─ check observable type is in scope
      ├─ check TLP is allowed
      ├─ dispatch to domain or IP enrichment
      ├─ call enabled Zetalytics endpoints
      ├─ convert API responses to STIX 2.1
      ├─ deduplicate objects and relationships
      └─ send STIX bundle back to OpenCTI
```

The connector intentionally guards each endpoint request independently. If one Zetalytics endpoint fails, times out, or returns an unexpected response, the connector logs the failure and continues with the remaining enabled endpoints. This is important for analyst usability because a partial enrichment result is usually better than no enrichment at all.

---

## Enrichment modes

The connector supports multiple operating modes. The mode controls which endpoints are enabled by default, how much data is returned, and whether broad pivots are allowed.

The intended deployment model is:

```text
Same package / same image
  ├─ Zetalytics DNS - Analyst Enrichment
  ├─ Zetalytics DNS - Playbook
  ├─ Zetalytics DNS - Auto Light
  └─ Zetalytics DNS - Deep Investigation
```

Each deployment should have its own `CONNECTOR_ID`, `CONNECTOR_NAME`, OpenCTI token, and `ZETALYTICS_MODE`.

---

## Mode: `manual`

Use this for analyst-driven enrichment from the OpenCTI UI.

This is the main day-to-day mode for threat intelligence analysts who are looking at a specific observable and want richer DNS context around it.

Typical connector name:

```text
Zetalytics DNS - Analyst Enrichment
```

Recommended trigger style:

```text
Manual enrichment only
```

Recommended behaviour:

- Enrich domains and hostnames with passive DNS records.
- Perform live DNS lookups.
- Return recent or active subdomains.
- Add D8S / registration context.
- Add nameserver glue where enabled.
- Avoid raw historical WHOIS unless explicitly enabled.
- Avoid broad pivots such as `ns2domain`, `mx2domain`, or email pivots by default.

Use this mode when:

- An analyst is investigating a suspicious domain, hostname, or IP.
- The analyst needs a useful local graph around the observable.
- Some graph expansion is acceptable and expected.
- The enrichment is deliberately triggered by a human.

Avoid this mode when:

- A playbook will run against many observables.
- The connector is configured for automatic enrichment on object creation.

Example settings:

```yaml
CONNECTOR_NAME: "Zetalytics DNS - Analyst Enrichment"
CONNECTOR_AUTO: "false"
ZETALYTICS_MODE: "manual"
ZETALYTICS_MAX_RESULTS: "300"
ZETALYTICS_MAX_SUBDOMAINS: "500"
ZETALYTICS_LOOKBACK_DAYS: "365"
ZETALYTICS_INCLUDE_LIVE_DNS: "true"
ZETALYTICS_INCLUDE_SUBDOMAINS: "true"
ZETALYTICS_INCLUDE_D8S: "true"
ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: "false"
ZETALYTICS_INCLUDE_NS_GLUE: "true"
ZETALYTICS_INCLUDE_EMAIL_PIVOTS: "false"
```

---

## Mode: `playbook`

Use this for controlled OpenCTI playbook enrichment.

This mode is intentionally more conservative than manual enrichment. It should produce useful context without creating large graph expansions or unpredictable volumes.

Typical connector name:

```text
Zetalytics DNS - Playbook
```

Recommended trigger style:

```text
Triggered by selected OpenCTI playbooks
```

Recommended behaviour:

- Enrich domains and hostnames with bounded passive DNS results.
- Optionally include live DNS.
- Enrich IPs with passive DNS and ASN / routing context.
- Disable subdomain expansion.
- Disable raw WHOIS.
- Disable nameserver, MX, and email pivots.

Use this mode when:

- Enrichment is part of an automated triage workflow.
- A playbook is triggered by tags, confidence, source, PIR match, or case context.
- You need predictable object and relationship counts.
- The enrichment output will be consumed by downstream automations.

Avoid this mode when:

- An analyst wants to perform broad infrastructure discovery.
- Subdomain or nameserver pivots are required.

Example settings:

```yaml
CONNECTOR_NAME: "Zetalytics DNS - Playbook"
CONNECTOR_AUTO: "false"
ZETALYTICS_MODE: "playbook"
ZETALYTICS_MAX_RESULTS: "100"
ZETALYTICS_LOOKBACK_DAYS: "180"
ZETALYTICS_INCLUDE_LIVE_DNS: "true"
ZETALYTICS_INCLUDE_SUBDOMAINS: "false"
ZETALYTICS_INCLUDE_D8S: "false"
ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: "false"
ZETALYTICS_INCLUDE_NS_GLUE: "false"
ZETALYTICS_INCLUDE_EMAIL_PIVOTS: "false"
```

---

## Mode: `light`

Use this for restricted automatic enrichment.

This mode is optional and should only be enabled after testing expected volume. It is intentionally small because automatic enrichment may run frequently.

Typical connector name:

```text
Zetalytics DNS - Auto Light
```

Recommended trigger style:

```text
Automatic enrichment on object creation
```

Recommended behaviour:

- Return a very small number of recent passive DNS results.
- Use a shorter lookback window.
- Disable live DNS unless explicitly required.
- Disable subdomains, D8S, WHOIS, NS glue, MX pivots, and email pivots.

Use this mode when:

- You want immediate lightweight context on new observables.
- You can tolerate the connector running automatically.
- Result limits are very low.
- You have already tested expected data volumes.

Avoid this mode when:

- The platform ingests large volumes of observables.
- API quota or OpenCTI storage growth is a concern.
- Broad enrichment context is required.

Example settings:

```yaml
CONNECTOR_NAME: "Zetalytics DNS - Auto Light"
CONNECTOR_AUTO: "true"
ZETALYTICS_MODE: "light"
ZETALYTICS_MAX_RESULTS: "25"
ZETALYTICS_LOOKBACK_DAYS: "90"
ZETALYTICS_TSFIELD: "last_seen"
ZETALYTICS_INCLUDE_LIVE_DNS: "false"
ZETALYTICS_INCLUDE_SUBDOMAINS: "false"
ZETALYTICS_INCLUDE_D8S: "false"
ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: "false"
ZETALYTICS_INCLUDE_NS_GLUE: "false"
ZETALYTICS_INCLUDE_EMAIL_PIVOTS: "false"
```

---

## Mode: `deep`

Use this for controlled manual deep-dive investigations.

This mode is intended for experienced analysts who need broader infrastructure pivots. It should not be used for automatic enrichment.

Typical connector name:

```text
Zetalytics DNS - Deep Investigation
```

Recommended trigger style:

```text
Manual only
```

Recommended behaviour:

- Include richer passive DNS results.
- Include live DNS.
- Include subdomains.
- Include D8S and optionally historical WHOIS.
- Include NS glue and nameserver pivots where needed.
- Optionally include MX and registration email pivots if approved.

Use this mode when:

- An analyst is performing infrastructure clustering.
- Nameserver, MX, or registration pivots are needed.
- The analyst expects a larger graph expansion.
- The investigation justifies the extra API usage and OpenCTI object volume.

Avoid this mode when:

- Running playbooks.
- Enabling automatic enrichment.
- Enriching large batches of observables.

Example settings:

```yaml
CONNECTOR_NAME: "Zetalytics DNS - Deep Investigation"
CONNECTOR_AUTO: "false"
ZETALYTICS_MODE: "deep"
ZETALYTICS_MAX_RESULTS: "500"
ZETALYTICS_MAX_SUBDOMAINS: "1000"
ZETALYTICS_LOOKBACK_DAYS: "1825"
ZETALYTICS_INCLUDE_LIVE_DNS: "true"
ZETALYTICS_INCLUDE_SUBDOMAINS: "true"
ZETALYTICS_INCLUDE_D8S: "true"
ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: "true"
ZETALYTICS_INCLUDE_NS_GLUE: "true"
ZETALYTICS_INCLUDE_EMAIL_PIVOTS: "false"
```

---

## Endpoint behaviour

The connector uses different Zetalytics endpoints depending on observable type and enabled configuration.

### Domain and hostname enrichment

Typical endpoints:

- `domain2rrtypes`
- `liveDNS`
- `subdomains`
- `domain2d8s`
- `domain2nsglue`
- optional `domain2whois`

Domain and hostname enrichment can produce:

- Related IPv4 and IPv6 observables
- CNAME targets
- Nameservers
- MX infrastructure
- TXT record notes or properties
- SOA-related email context where enabled
- Subdomains
- Registration context

### IP enrichment

Typical endpoints:

- `ip`
- `ip2pwhois`
- optional `ip2nsglue`

IP enrichment can produce:

- Domains and hostnames historically resolving to the IP
- ASN context
- Routing prefix context
- Organisation or network context
- PTR / nameserver context where available

---

## STIX conversion

The connector converts Zetalytics responses into STIX 2.1 objects suitable for OpenCTI ingestion.

Common mappings:

| Zetalytics data | STIX / OpenCTI representation |
|---|---|
| Domain or hostname | `Domain-Name` or `Hostname` observable |
| IPv4 address | `IPv4-Addr` observable |
| IPv6 address | `IPv6-Addr` observable |
| A / AAAA record | DNS `resolves-to` relationship |
| CNAME target | Related domain / hostname relationship |
| NS record | Related nameserver observable |
| MX record | Related mail exchanger observable |
| TXT record | Note, description, or custom property |
| ASN context | `Autonomous-System` object where appropriate |
| D8S / registration context | Notes, relationships, or contextual objects depending on mapping |

The converter deduplicates observables and relationships within each enrichment run. It does not create placeholder objects when no data is returned.

---

## TLP and scope guards

The connector applies scope and TLP checks before calling Zetalytics.

This prevents enrichment from running when:

- The observable type is unsupported.
- The observable type is outside the configured connector scope.
- The object's TLP marking is more restrictive than the configured maximum.

This behaviour helps avoid sending sensitive observables to an external enrichment source when the marking does not allow it.

---

## Configuration

All connector-specific environment variables use the `ZETALYTICS_*` prefix.

Common OpenCTI settings:

```yaml
OPENCTI_URL: "https://opencti.example.internal"
OPENCTI_TOKEN: "<connector-token>"
CONNECTOR_ID: "<stable-uuid>"
CONNECTOR_NAME: "Zetalytics DNS - Analyst Enrichment"
CONNECTOR_SCOPE: "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr"
CONNECTOR_AUTO: "false"
CONNECTOR_LOG_LEVEL: "info"
```

Common Zetalytics settings:

```yaml
ZETALYTICS_TOKEN: "<zetalytics-token>"
ZETALYTICS_REQUEST_TIMEOUT: "60"       # optional (default: 30) — HTTP timeout in seconds per API call
ZETALYTICS_MODE: "manual"
ZETALYTICS_MAX_RESULTS: "300"
ZETALYTICS_MAX_SUBDOMAINS: "500"
ZETALYTICS_MAX_WHOIS_RESULTS: "5"
ZETALYTICS_LOOKBACK_DAYS: "365"
ZETALYTICS_TSFIELD: "all"
ZETALYTICS_MAX_TLP: "TLP:AMBER"
ZETALYTICS_CONFIDENCE: "60"
ZETALYTICS_INCLUDE_PORTAL_LINK: "true" # optional (default: true) — adds a ZoneCruncher link to each enriched observable. WARNING: the API token is visible in the URL.
```

Endpoint flags:

```yaml
ZETALYTICS_INCLUDE_LIVE_DNS: "true"
ZETALYTICS_INCLUDE_SUBDOMAINS: "true"
ZETALYTICS_INCLUDE_D8S: "true"
ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: "false"
ZETALYTICS_INCLUDE_NS_GLUE: "true"
ZETALYTICS_INCLUDE_NS2DOMAIN: "false"
ZETALYTICS_INCLUDE_MX2DOMAIN: "false"
ZETALYTICS_INCLUDE_EMAIL_PIVOTS: "false"
```

---

## Build and deployment

### Python package

The connector uses `pyproject.toml` rather than `requirements.txt`.

The console script is declared as:

```text
zetalytics-dns-connector
```

The console script calls:

```python
zetanalytics_dns.__main__:main
```

### Dockerfile

The connector ships a single, standard `python:3.12-alpine`-based Dockerfile that installs the
package from `pyproject.toml` (including the `connectors-sdk` dependency, resolved via git).

### Example build command

```bash
docker build -t zetalytics-dns-connector:latest .
```

---

## Example deployment pattern

Run the same image multiple times with different connector identities and modes.

```yaml
services:
  connector-zetalytics-analyst:
    image: zetalytics-dns-connector:latest
    environment:
      OPENCTI_URL: "https://opencti.example.internal"
      OPENCTI_TOKEN: "<connector-token>"
      ZETALYTICS_TOKEN: "<zetalytics-token>"
      CONNECTOR_ID: "00000000-0000-4000-8000-000000000101"
      CONNECTOR_NAME: "Zetalytics DNS - Analyst Enrichment"
      CONNECTOR_AUTO: "false"
      ZETALYTICS_MODE: "manual"
      ZETALYTICS_MAX_RESULTS: "300"
      ZETALYTICS_MAX_SUBDOMAINS: "500"
      ZETALYTICS_LOOKBACK_DAYS: "365"
      ZETALYTICS_INCLUDE_LIVE_DNS: "true"
      ZETALYTICS_INCLUDE_SUBDOMAINS: "true"
      ZETALYTICS_INCLUDE_D8S: "true"
      ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: "false"
      ZETALYTICS_INCLUDE_NS_GLUE: "true"
      ZETALYTICS_INCLUDE_EMAIL_PIVOTS: "false"
      ZETALYTICS_INCLUDE_PORTAL_LINK: "true"

  connector-zetalytics-playbook:
    image: zetalytics-dns-connector:latest
    environment:
      OPENCTI_URL: "https://opencti.example.internal"
      OPENCTI_TOKEN: "<connector-token>"
      ZETALYTICS_TOKEN: "<zetalytics-token>"
      CONNECTOR_ID: "00000000-0000-4000-8000-000000000102"
      CONNECTOR_NAME: "Zetalytics DNS - Playbook"
      CONNECTOR_AUTO: "false"
      ZETALYTICS_MODE: "playbook"
      ZETALYTICS_MAX_RESULTS: "100"
      ZETALYTICS_LOOKBACK_DAYS: "180"
      ZETALYTICS_INCLUDE_LIVE_DNS: "true"
      ZETALYTICS_INCLUDE_SUBDOMAINS: "false"
      ZETALYTICS_INCLUDE_D8S: "false"
      ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: "false"
      ZETALYTICS_INCLUDE_NS_GLUE: "false"
      ZETALYTICS_INCLUDE_EMAIL_PIVOTS: "false"
      ZETALYTICS_INCLUDE_PORTAL_LINK: "false"

  connector-zetalytics-deep-investigation:
    image: zetalytics-dns-connector:latest
    environment:
      OPENCTI_URL: "https://opencti.example.internal"
      OPENCTI_TOKEN: "<connector-token>"
      ZETALYTICS_TOKEN: "<zetalytics-token>"
      CONNECTOR_ID: "00000000-0000-4000-8000-000000000103"
      CONNECTOR_NAME: "Zetalytics DNS - Deep Investigation"
      CONNECTOR_AUTO: "false"
      ZETALYTICS_MODE: "deep"
      ZETALYTICS_MAX_RESULTS: "500"
      ZETALYTICS_MAX_SUBDOMAINS: "1000"
      ZETALYTICS_LOOKBACK_DAYS: "1825"
      ZETALYTICS_INCLUDE_LIVE_DNS: "true"
      ZETALYTICS_INCLUDE_SUBDOMAINS: "true"
      ZETALYTICS_INCLUDE_D8S: "true"
      ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: "true"
      ZETALYTICS_INCLUDE_NS_GLUE: "true"
      ZETALYTICS_INCLUDE_EMAIL_PIVOTS: "false"
      ZETALYTICS_INCLUDE_PORTAL_LINK: "true"

  connector-zetalytics-auto-light:
    image: zetalytics-dns-connector:latest
    environment:
      OPENCTI_URL: "https://opencti.example.internal"
      OPENCTI_TOKEN: "<connector-token>"
      ZETALYTICS_TOKEN: "<zetalytics-token>"
      CONNECTOR_ID: "00000000-0000-4000-8000-000000000104"
      CONNECTOR_NAME: "Zetalytics DNS - Auto Light"
      CONNECTOR_AUTO: "true"
      ZETALYTICS_MODE: "light"
      ZETALYTICS_MAX_RESULTS: "25"
      ZETALYTICS_LOOKBACK_DAYS: "90"
      ZETALYTICS_TSFIELD: "last_seen"
      ZETALYTICS_INCLUDE_LIVE_DNS: "false"
      ZETALYTICS_INCLUDE_SUBDOMAINS: "false"
      ZETALYTICS_INCLUDE_D8S: "false"
      ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: "false"
      ZETALYTICS_INCLUDE_NS_GLUE: "false"
      ZETALYTICS_INCLUDE_EMAIL_PIVOTS: "false"
```

---

## Testing

The test suite is split across top-level connector tests and package-specific tests.

| Test file | Coverage |
|---|---|
| `test_main.py` | Settings loading, helper initialisation, connector initialisation, TLP skip behaviour, unsupported type skip behaviour. |
| `tests_connector/test_settings.py` | Valid and invalid configs, mode defaults, and `to_helper_config`. |
| `tests_connector/test_converter.py` | Converter helper functions and all `from_*` converter methods. |
| `tests_connector/test_client.py` | Verifies each client method calls the correct SDK endpoint with the correct parameters. |

Run tests with:

```bash
pytest
```

Run with coverage:

```bash
pytest --cov=zetanalytics_dns --cov-report=term-missing
```

---

## Operational guidance

Recommended initial rollout:

1. Deploy `Zetalytics DNS - Analyst Enrichment` for manual enrichment.
2. Deploy `Zetalytics DNS - Playbook` for selected playbooks.
3. Add `Zetalytics DNS - Auto Light` only after reviewing API usage, OpenCTI object volume, and analyst value.
4. Keep `Zetalytics DNS - Deep Investigation` manual-only and restricted to users who understand the graph expansion impact.

Recommended defaults:

- Keep `CONNECTOR_AUTO=false` unless using the `light` mode deployment.
- Keep `ZETALYTICS_INCLUDE_HISTORICAL_WHOIS=false` by default.
- Keep `ZETALYTICS_INCLUDE_EMAIL_PIVOTS=false` by default.
- Keep broad pivots such as `ns2domain` and `mx2domain` disabled unless using deep investigation mode.
- Use separate OpenCTI connector users/tokens per deployment where possible.
- Monitor returned object counts, relationship counts, and API failures.

---

## Failure handling

Endpoint calls are individually guarded. A failure in one endpoint should not fail the entire enrichment run.

Expected behaviour:

- Log the failing endpoint and observable.
- Continue with remaining enabled endpoints.
- Return any successfully converted STIX objects.
- Do not create placeholder observables for failed or empty endpoint responses.

This makes the connector more resilient during partial API outages or endpoint-specific response issues.

---

## Security notes

- Store `ZETALYTICS_TOKEN` as a secret.
- Do not commit real OpenCTI or Zetalytics tokens.
- Do not log tokens.
- Respect TLP and connector scope checks before sending observables to Zetalytics.
- Treat registration email pivots and WHOIS-derived data carefully, especially in automated workflows.

---

## Recommended first release scope

For the first production-ready version, prioritise:

- Settings loading and validation
- Zetalytics client wrapper
- Domain enrichment using `domain2rrtypes` and `liveDNS`
- IP enrichment using `ip` and `ip2pwhois`
- STIX conversion and deduplication
- TLP and scope guards
- Manual and playbook deployment profiles
- Unit tests for settings, client calls, converter methods, and connector skip logic

Add deeper pivots after the core enrichment behaviour is stable and the output volume is understood.
