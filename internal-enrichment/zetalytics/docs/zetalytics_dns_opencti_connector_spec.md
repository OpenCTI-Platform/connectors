# Zetalytics DNS Connector for OpenCTI

## 1. Overview

This specification describes a Python-based OpenCTI internal enrichment connector for the Zetalytics ZoneCruncher API. The connector is aimed at threat intelligence analysts enriching domains, hostnames, IPv4 addresses, and IPv6 addresses with passive DNS, live DNS, WHOIS/D8S, ASN, nameserver, MX, subdomain, and infrastructure pivot data.

The intended design is **one connector codebase and one connector image**, deployed multiple times with different configuration profiles. This allows the same API client, STIX mapping, error handling, and deduplication logic to be reused while providing different operational behaviours for analyst-led enrichment, playbook enrichment, and optional lightweight automatic enrichment.

The Python package `zetalytics-api` should be used as the API wrapper where possible.

Example client initialisation:

```python
from zetalytics import Zetalytics

zeta = Zetalytics(token="<ZETALYTICS_TOKEN>")
```

---

## 2. Connector purpose

The connector should enrich OpenCTI observables using Zetalytics DNS and infrastructure intelligence.

Primary analyst use cases:

- Enrich an IP address with historical passive DNS resolutions.
- Enrich a domain or hostname with passive DNS records.
- Identify current DNS state using live DNS lookups.
- Pivot from a suspicious domain to subdomains, nameservers, MX infrastructure, and related IPs.
- Pivot from an IP address to associated domains and ASN/routing context.
- Add registration context using D8S or WHOIS data where appropriate.
- Support controlled enrichment in OpenCTI playbooks without creating excessive graph noise.

The connector should be treated as an **enrichment and pivoting tool**, not a bulk ingestion source.

---

## 3. Recommended OpenCTI connector type

```yaml
CONNECTOR_TYPE: INTERNAL_ENRICHMENT
CONNECTOR_SCOPE: Domain-Name,Hostname,IPv4-Addr,IPv6-Addr
CONNECTOR_AUTO: false
```

Optional future scope:

```yaml
CONNECTOR_SCOPE: Domain-Name,Hostname,IPv4-Addr,IPv6-Addr,Email-Addr
```

The connector should emit STIX 2.1 bundles back into OpenCTI. Enrichment should add context to existing observables rather than importing unrelated bulk data.

---

## 4. One connector, multiple deployments

### 4.1 Design principle

The connector should be built once and deployed multiple times with different configuration profiles.

Example deployments:

```text
zetalytics-dns-analyst-enrichment
zetalytics-dns-playbook
zetalytics-dns-auto-light
zetalytics-dns-deep-investigation
```

Each deployment should have:

- A unique `CONNECTOR_ID`.
- A unique `CONNECTOR_NAME`.
- Its own OpenCTI connector token where possible.
- Its own mode-specific configuration.
- The same Docker image.
- The same codebase.
- The same Zetalytics client wrapper and STIX mapping logic.

### 4.2 Why this matters

Manual enrichment and automated enrichment have different risk profiles.

Manual enrichment can tolerate richer output because an analyst has intentionally triggered it. Playbook enrichment should be deterministic and bounded. Automatic enrichment must be conservative because it may run at scale without analyst review.

---

## 5. Deployment profiles

## 5.1 Analyst/manual enrichment

Purpose: analyst-triggered enrichment from an observable.

Recommended endpoint set:

For domains and hostnames:

- `domain2rrtypes`
- `liveDNS`
- `subdomains`
- `domain2d8s`
- Optional: `domain2nsglue`
- Optional: `domain-zone-activity`
- Optional: `domain2whois`, capped and disabled by default

For IP addresses:

- `ip`
- `ip2pwhois`
- Optional: `ip2nsglue`

Suggested behaviour:

```yaml
CONNECTOR_NAME: Zetalytics DNS - Analyst Enrichment
CONNECTOR_AUTO: false
ZETALYTICS_MODE: manual
ZETALYTICS_MAX_RESULTS: 300
ZETALYTICS_MAX_SUBDOMAINS: 500
ZETALYTICS_LOOKBACK_DAYS: 365
ZETALYTICS_INCLUDE_LIVE_DNS: true
ZETALYTICS_INCLUDE_SUBDOMAINS: true
ZETALYTICS_INCLUDE_D8S: true
ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: false
ZETALYTICS_INCLUDE_NS_GLUE: true
ZETALYTICS_INCLUDE_EMAIL_PIVOTS: false
```

---

## 5.2 Playbook-specific enrichment

Purpose: controlled enrichment from OpenCTI playbooks.

Recommended endpoint set:

For domains and hostnames:

- `domain2rrtypes`
- `liveDNS`, optional but recommended

For IP addresses:

- `ip`
- `ip2pwhois`

Avoid by default:

- `subdomains`
- `ns2domain`
- `mx2domain`
- `domain2whois`
- email pivots
- broad nameserver pivots

Suggested behaviour:

```yaml
CONNECTOR_NAME: Zetalytics DNS - Playbook
CONNECTOR_AUTO: false
ZETALYTICS_MODE: playbook
ZETALYTICS_MAX_RESULTS: 100
ZETALYTICS_LOOKBACK_DAYS: 180
ZETALYTICS_INCLUDE_LIVE_DNS: true
ZETALYTICS_INCLUDE_SUBDOMAINS: false
ZETALYTICS_INCLUDE_D8S: false
ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: false
ZETALYTICS_INCLUDE_NS_GLUE: false
ZETALYTICS_INCLUDE_EMAIL_PIVOTS: false
```

---

## 5.3 Lightweight automatic enrichment

Purpose: optional immediate context when observables arrive in OpenCTI.

This must be restrictive because it runs automatically.

Recommended endpoint set:

For domains and hostnames:

- `domain2rrtypes`, with very low limits

For IP addresses:

- `ip`, with very low limits
- Optional: `ip2pwhois`, only if volume is acceptable

Avoid always:

- `subdomains`
- `domain2whois`
- `domain2d8s`
- `ns2domain`
- `mx2domain`
- nameserver glue pivots
- email pivots

Suggested behaviour:

```yaml
CONNECTOR_NAME: Zetalytics DNS - Auto Light
CONNECTOR_AUTO: true
ZETALYTICS_MODE: light
ZETALYTICS_MAX_RESULTS: 25
ZETALYTICS_LOOKBACK_DAYS: 90
ZETALYTICS_TSFIELD: last_seen
ZETALYTICS_INCLUDE_LIVE_DNS: false
ZETALYTICS_INCLUDE_SUBDOMAINS: false
ZETALYTICS_INCLUDE_D8S: false
ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: false
ZETALYTICS_INCLUDE_NS_GLUE: false
ZETALYTICS_INCLUDE_EMAIL_PIVOTS: false
```

---

## 5.4 Deep investigation enrichment

Purpose: controlled manual enrichment for experienced analysts when a broader pivot is required.

Recommended endpoint set:

- `domain2rrtypes`
- `liveDNS`
- `subdomains`
- `domain2d8s`
- `domain2whois`
- `domain2nsglue`
- `ip2nsglue`
- `ns2domain`
- `mx2domain`
- optional email pivots

This profile should never be enabled for global automatic enrichment.

---

## 6. Mode handling in code

Suggested modes:

```python
class ZetalyticsMode:
    LIGHT = "light"
    PLAYBOOK = "playbook"
    MANUAL = "manual"
    DEEP = "deep"
```

Suggested dispatch pattern:

```python
if mode == "light":
    run_light_enrichment()
elif mode == "playbook":
    run_playbook_enrichment()
elif mode == "manual":
    run_manual_enrichment()
elif mode == "deep":
    run_deep_enrichment()
else:
    raise ValueError(f"Unsupported Zetalytics mode: {mode}")
```

Mode should set sensible defaults. Explicit endpoint flags should override mode defaults.

---

## 7. API endpoint implementation priorities

## 7.1 Tier 1: MVP endpoints

### `ip`

Purpose: Search passive DNS by IP, CIDR, or range, including IPv6.

Use for:

- IPv4 enrichment
- IPv6 enrichment
- IP-to-domain pivoting
- historical hosting context

Suggested call:

```python
query = {
    "q": observable_value,
    "size": config.max_results,
    "start": lookback_start,
    "tsfield": config.tsfield,
}
results = zeta.ip(**query)
```

### `domain2rrtypes`

Purpose: Search passive DNS by qname and return multiple RR types in a single request.

Recommended RR types:

```text
a,aaaa,cname,ns,mx,txt,ptr,soa_email
```

Suggested call:

```python
query = {
    "q": observable_value,
    "rrtypes": "a,aaaa,cname,ns,mx,txt,soa_email",
    "size": config.max_results,
    "toBaseDomain": False,
    "noSubdomains": False,
    "start": lookback_start,
    "tsfield": config.tsfield,
}
results = zeta.domain2rrtypes(**query)
```

### `subdomains`

Purpose: Search passive DNS by domain for a list of subdomains from any record type.

Recommended only for manual or deep enrichment.

```python
query = {
    "q": observable_value,
    "active": 90,
    "VVV": True,
    "sort": "last",
}
results = zeta.subdomains(**query)
```

### `liveDNS`

Purpose: Perform a live DNS lookup for a domain.

```python
results = zeta.liveDNS(q=observable_value)
```

### `ip2pwhois`

Purpose: Enrich an IP address with WHOIS, PTR nameserver, AS path, ASN, routing prefix, organisation, network, and country context.

```python
results = zeta.ip2pwhois(q=observable_value)
```

---

## 7.2 Tier 2: Optional pivots

- `domain2d8s`: structured registration context.
- `domain2whois`: historical raw WHOIS, disabled by default.
- `domain2nsglue`: nameserver glue records by domain.
- `ip2nsglue`: nameserver glue records by IP/CIDR/range.
- `ns2domain`: domains served by nameserver, deep mode only.
- `mx2domain`: domains served by MX domain, deep mode only.
- `email_address`, `email_domain`, `email_user`: registration email pivots, disabled by default.

---

## 7.3 Tier 3: Record-specific fallback endpoints

These are lower priority because `domain2rrtypes` covers most passive DNS enrichment needs:

- `domain2ip`
- `domain2aaaa`
- `domain2cname`
- `domain2mx`
- `domain2ns`
- `domain2txt`
- `domain2ptr`
- `cname2qname`

---

## 8. STIX and OpenCTI mapping

## 8.1 Observable mapping

| Zetalytics field | Meaning | OpenCTI / STIX object |
|---|---|---|
| `qname` | Observed DNS name / hostname | `Domain-Name` or `Hostname` |
| `domain` | Base domain or public suffix | `Domain-Name` |
| `value` with type `ip` | IPv4 address | `IPv4-Addr` |
| `value` with type `aaaa` | IPv6 address | `IPv6-Addr` |
| `value` with type `cname` / `name` | Related DNS name | `Domain-Name` or `Hostname` |
| `value` with type `soa_email` | SOA email address | `Email-Addr`, optional |
| `geoip.country_iso_code` | IP country | Note, custom property, or location metadata |
| `date` / `first_seen` / `first_ts` | First observed date | Relationship metadata |
| `last_seen` / `last_ts` | Last observed date | Relationship metadata |

## 8.2 Relationship mapping

Recommended relationships:

```text
Domain-Name --resolves-to--> IPv4-Addr
Domain-Name --resolves-to--> IPv6-Addr
Hostname    --resolves-to--> IPv4-Addr
Hostname    --resolves-to--> IPv6-Addr
Domain-Name --related-to--> Domain-Name / Hostname
Domain-Name --related-to--> Email-Addr
IPv4-Addr   --related-to--> Autonomous-System
IPv6-Addr   --related-to--> Autonomous-System
```

If custom relationship types are supported, consider:

```text
has-nameserver
has-mail-exchanger
has-cname
has-soa-email
hosted-on
observed-in-passive-dns
```

---

## 9. Data volume controls

Recommended defaults:

```yaml
ZETALYTICS_MAX_RESULTS: 300
ZETALYTICS_MAX_SUBDOMAINS: 300
ZETALYTICS_MAX_NS_PIVOT_RESULTS: 100
ZETALYTICS_MAX_WHOIS_RESULTS: 5
ZETALYTICS_LOOKBACK_DAYS: 365
ZETALYTICS_TSFIELD: all
```

Recommended deduplication:

- Deduplicate observables by normalised value.
- Deduplicate relationships by source, target, relationship type, RR type, first seen, and last seen.
- Avoid creating duplicate relationships for identical passive DNS records.
- Avoid creating indicators by default unless there is a clear scoring or detection model.

---

## 10. Normalisation rules

### Domains and hostnames

- Lowercase all domain names.
- Strip trailing dots.
- Preserve punycode values.
- Store UTF-8 converted values where returned by Zetalytics.

### IP addresses

- Validate using Python `ipaddress`.
- Use `IPv4-Addr` for IPv4 values.
- Use `IPv6-Addr` for IPv6 values.
- Skip malformed IP values rather than attempting to correct them.

### Dates

- Convert date-only values such as `2023-11-10` to ISO datetime format.
- Use UTC consistently.
- Preserve original first seen and last seen values in relationship metadata or descriptions.

### TXT records

- Do not create a separate observable for every TXT value by default.
- Store TXT values as a Note, description, or custom property.
- Consider filtering common SPF, DKIM, and DMARC values unless needed by analysts.

---

## 11. Python implementation notes

### 11.1 Zetalytics client wrapper

```python
from zetalytics import Zetalytics


class ZetalyticsClient:
    def __init__(self, token: str):
        self.client = Zetalytics(token=token)

    def passive_dns_for_ip(self, value: str, size: int, start: str | None, tsfield: str):
        query = {"q": value, "size": size, "tsfield": tsfield}
        if start:
            query["start"] = start
        return self.client.ip(**query)

    def passive_dns_for_domain(self, value: str, rrtypes: str, size: int, start: str | None, tsfield: str):
        query = {"q": value, "rrtypes": rrtypes, "size": size, "tsfield": tsfield}
        if start:
            query["start"] = start
        return self.client.domain2rrtypes(**query)

    def live_dns(self, value: str):
        return self.client.liveDNS(q=value)

    def subdomains(self, value: str, active: int = 90):
        return self.client.subdomains(q=value, active=active, VVV=True, sort="last")

    def ip_context(self, value: str):
        return self.client.ip2pwhois(q=value)
```

### 11.2 Connector flow

```text
Receive OpenCTI enrichment event
 ├─ Identify observable type and value
 ├─ Normalise and validate observable
 ├─ Load deployment mode and endpoint flags
 ├─ Call relevant Zetalytics endpoints
 ├─ Transform results into STIX objects
 ├─ Deduplicate objects and relationships
 ├─ Create STIX bundle
 └─ Send bundle back to OpenCTI
```

---

## 12. Security and secret handling

Required secrets:

```yaml
OPENCTI_TOKEN: ${OPENCTI_TOKEN}
ZETALYTICS_TOKEN: ${ZETALYTICS_TOKEN}
```

Recommendations:

- Use a dedicated OpenCTI connector user and token for each deployment.
- Store the Zetalytics token in Docker secrets, Kubernetes secrets, or an approved secret-management mechanism.
- Do not hard-code the token in Docker Compose, Helm values, or the connector source code.
- Avoid logging the API token.

---

## 13. Sample YAML configuration files

The following samples show how the same connector image can be deployed multiple times with different behaviour.

### 13.1 Analyst/manual enrichment YAML

```yaml
# config/zetalytics-analyst-enrichment.yml
opencti:
  url: "${OPENCTI_URL}"
  token: "${OPENCTI_TOKEN_ZETALYTICS_ANALYST}"

connector:
  id: "00000000-0000-4000-8000-000000000101"
  name: "Zetalytics DNS - Analyst Enrichment"
  type: "INTERNAL_ENRICHMENT"
  scope: "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr"
  auto: false
  log_level: "info"
  queue_threshold: 500

zetalytics:
  token: "${ZETALYTICS_TOKEN}"
  mode: "manual"
  result_limits:
    max_results: 300
    max_subdomains: 500
    max_whois_results: 5
    max_ns_pivot_results: 100
  time_window:
    lookback_days: 365
    tsfield: "all"
  endpoints:
    live_dns: true
    subdomains: true
    d8s: true
    historical_whois: false
    ns_glue: true
    zone_activity: false
    ns2domain: false
    mx2domain: false
    email_pivots: false
  stix:
    create_indicators: false
    create_infrastructure: true
    create_observations: true
    confidence: 60
    marking_definition: "TLP:AMBER"
  safeguards:
    deduplicate_observables: true
    deduplicate_relationships: true
    skip_invalid_values: true
    create_note_when_no_results: false
```

### 13.2 Playbook YAML

```yaml
# config/zetalytics-playbook.yml
opencti:
  url: "${OPENCTI_URL}"
  token: "${OPENCTI_TOKEN_ZETALYTICS_PLAYBOOK}"

connector:
  id: "00000000-0000-4000-8000-000000000102"
  name: "Zetalytics DNS - Playbook"
  type: "INTERNAL_ENRICHMENT"
  scope: "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr"
  auto: false
  log_level: "info"
  queue_threshold: 500

zetalytics:
  token: "${ZETALYTICS_TOKEN}"
  mode: "playbook"
  result_limits:
    max_results: 100
    max_subdomains: 0
    max_whois_results: 0
    max_ns_pivot_results: 0
  time_window:
    lookback_days: 180
    tsfield: "all"
  endpoints:
    live_dns: true
    subdomains: false
    d8s: false
    historical_whois: false
    ns_glue: false
    zone_activity: false
    ns2domain: false
    mx2domain: false
    email_pivots: false
  stix:
    create_indicators: false
    create_infrastructure: false
    create_observations: true
    confidence: 50
    marking_definition: "TLP:AMBER"
  safeguards:
    deduplicate_observables: true
    deduplicate_relationships: true
    skip_invalid_values: true
    create_note_when_no_results: false
```

### 13.3 Auto-light YAML

```yaml
# config/zetalytics-auto-light.yml
opencti:
  url: "${OPENCTI_URL}"
  token: "${OPENCTI_TOKEN_ZETALYTICS_AUTO_LIGHT}"

connector:
  id: "00000000-0000-4000-8000-000000000103"
  name: "Zetalytics DNS - Auto Light"
  type: "INTERNAL_ENRICHMENT"
  scope: "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr"
  auto: true
  log_level: "info"
  queue_threshold: 500

zetalytics:
  token: "${ZETALYTICS_TOKEN}"
  mode: "light"
  result_limits:
    max_results: 25
    max_subdomains: 0
    max_whois_results: 0
    max_ns_pivot_results: 0
  time_window:
    lookback_days: 90
    tsfield: "last_seen"
  endpoints:
    live_dns: false
    subdomains: false
    d8s: false
    historical_whois: false
    ns_glue: false
    zone_activity: false
    ns2domain: false
    mx2domain: false
    email_pivots: false
  stix:
    create_indicators: false
    create_infrastructure: false
    create_observations: true
    confidence: 40
    marking_definition: "TLP:AMBER"
  safeguards:
    deduplicate_observables: true
    deduplicate_relationships: true
    skip_invalid_values: true
    create_note_when_no_results: false
```

### 13.4 Deep investigation YAML

```yaml
# config/zetalytics-deep-investigation.yml
opencti:
  url: "${OPENCTI_URL}"
  token: "${OPENCTI_TOKEN_ZETALYTICS_DEEP}"

connector:
  id: "00000000-0000-4000-8000-000000000104"
  name: "Zetalytics DNS - Deep Investigation"
  type: "INTERNAL_ENRICHMENT"
  scope: "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr,Email-Addr"
  auto: false
  log_level: "info"
  queue_threshold: 500

zetalytics:
  token: "${ZETALYTICS_TOKEN}"
  mode: "deep"
  result_limits:
    max_results: 500
    max_subdomains: 1000
    max_whois_results: 10
    max_ns_pivot_results: 250
    max_mx_pivot_results: 250
    max_email_pivot_results: 100
  time_window:
    lookback_days: 730
    tsfield: "all"
  endpoints:
    live_dns: true
    subdomains: true
    d8s: true
    historical_whois: true
    ns_glue: true
    zone_activity: true
    ns2domain: true
    mx2domain: true
    email_pivots: false
  stix:
    create_indicators: false
    create_infrastructure: true
    create_observations: true
    confidence: 60
    marking_definition: "TLP:AMBER"
  safeguards:
    deduplicate_observables: true
    deduplicate_relationships: true
    skip_invalid_values: true
    create_note_when_no_results: false
    require_manual_trigger: true
```

### 13.5 Docker Compose example

```yaml
# docker-compose.zetalytics.yml
services:
  connector-zetalytics-analyst:
    image: opencti/connector-zetalytics-dns:latest
    container_name: connector-zetalytics-analyst
    restart: unless-stopped
    environment:
      OPENCTI_URL: "${OPENCTI_URL}"
      OPENCTI_TOKEN: "${OPENCTI_TOKEN_ZETALYTICS_ANALYST}"
      CONNECTOR_ID: "00000000-0000-4000-8000-000000000101"
      CONNECTOR_NAME: "Zetalytics DNS - Analyst Enrichment"
      CONNECTOR_TYPE: "INTERNAL_ENRICHMENT"
      CONNECTOR_SCOPE: "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr"
      CONNECTOR_AUTO: "false"
      CONNECTOR_LOG_LEVEL: "info"
      ZETALYTICS_TOKEN: "${ZETALYTICS_TOKEN}"
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

  connector-zetalytics-playbook:
    image: opencti/connector-zetalytics-dns:latest
    container_name: connector-zetalytics-playbook
    restart: unless-stopped
    environment:
      OPENCTI_URL: "${OPENCTI_URL}"
      OPENCTI_TOKEN: "${OPENCTI_TOKEN_ZETALYTICS_PLAYBOOK}"
      CONNECTOR_ID: "00000000-0000-4000-8000-000000000102"
      CONNECTOR_NAME: "Zetalytics DNS - Playbook"
      CONNECTOR_TYPE: "INTERNAL_ENRICHMENT"
      CONNECTOR_SCOPE: "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr"
      CONNECTOR_AUTO: "false"
      CONNECTOR_LOG_LEVEL: "info"
      ZETALYTICS_TOKEN: "${ZETALYTICS_TOKEN}"
      ZETALYTICS_MODE: "playbook"
      ZETALYTICS_MAX_RESULTS: "100"
      ZETALYTICS_LOOKBACK_DAYS: "180"
      ZETALYTICS_INCLUDE_LIVE_DNS: "true"
      ZETALYTICS_INCLUDE_SUBDOMAINS: "false"
      ZETALYTICS_INCLUDE_D8S: "false"
      ZETALYTICS_INCLUDE_HISTORICAL_WHOIS: "false"
      ZETALYTICS_INCLUDE_NS_GLUE: "false"
      ZETALYTICS_INCLUDE_EMAIL_PIVOTS: "false"

  connector-zetalytics-auto-light:
    image: opencti/connector-zetalytics-dns:latest
    container_name: connector-zetalytics-auto-light
    restart: unless-stopped
    environment:
      OPENCTI_URL: "${OPENCTI_URL}"
      OPENCTI_TOKEN: "${OPENCTI_TOKEN_ZETALYTICS_AUTO_LIGHT}"
      CONNECTOR_ID: "00000000-0000-4000-8000-000000000103"
      CONNECTOR_NAME: "Zetalytics DNS - Auto Light"
      CONNECTOR_TYPE: "INTERNAL_ENRICHMENT"
      CONNECTOR_SCOPE: "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr"
      CONNECTOR_AUTO: "true"
      CONNECTOR_LOG_LEVEL: "info"
      ZETALYTICS_TOKEN: "${ZETALYTICS_TOKEN}"
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

### 13.6 Kubernetes playbook deployment example

```yaml
# k8s/connector-zetalytics-playbook-deployment.yml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: connector-zetalytics-playbook
  labels:
    app: connector-zetalytics-playbook
spec:
  replicas: 1
  selector:
    matchLabels:
      app: connector-zetalytics-playbook
  template:
    metadata:
      labels:
        app: connector-zetalytics-playbook
    spec:
      containers:
        - name: connector-zetalytics-playbook
          image: opencti/connector-zetalytics-dns:latest
          imagePullPolicy: IfNotPresent
          env:
            - name: OPENCTI_URL
              value: "https://opencti.example.internal"
            - name: OPENCTI_TOKEN
              valueFrom:
                secretKeyRef:
                  name: opencti-connector-tokens
                  key: zetalytics-playbook-token
            - name: ZETALYTICS_TOKEN
              valueFrom:
                secretKeyRef:
                  name: zetalytics-api
                  key: token
            - name: CONNECTOR_ID
              value: "00000000-0000-4000-8000-000000000102"
            - name: CONNECTOR_NAME
              value: "Zetalytics DNS - Playbook"
            - name: CONNECTOR_TYPE
              value: "INTERNAL_ENRICHMENT"
            - name: CONNECTOR_SCOPE
              value: "Domain-Name,Hostname,IPv4-Addr,IPv6-Addr"
            - name: CONNECTOR_AUTO
              value: "false"
            - name: CONNECTOR_LOG_LEVEL
              value: "info"
            - name: ZETALYTICS_MODE
              value: "playbook"
            - name: ZETALYTICS_MAX_RESULTS
              value: "100"
            - name: ZETALYTICS_LOOKBACK_DAYS
              value: "180"
            - name: ZETALYTICS_TSFIELD
              value: "all"
            - name: ZETALYTICS_INCLUDE_LIVE_DNS
              value: "true"
            - name: ZETALYTICS_INCLUDE_SUBDOMAINS
              value: "false"
            - name: ZETALYTICS_INCLUDE_D8S
              value: "false"
            - name: ZETALYTICS_INCLUDE_HISTORICAL_WHOIS
              value: "false"
            - name: ZETALYTICS_INCLUDE_NS_GLUE
              value: "false"
            - name: ZETALYTICS_INCLUDE_EMAIL_PIVOTS
              value: "false"
```

---

## 14. Recommended MVP delivery plan

### Phase 1: Core connector

- OpenCTI enrichment connector skeleton.
- Configuration loader.
- Zetalytics client wrapper.
- Mode handling.
- Domain and IP input validation.

### Phase 2: Core enrichment

Implement:

- `domain2rrtypes`
- `liveDNS`
- `ip`
- `ip2pwhois`

### Phase 3: Analyst enrichment additions

Implement:

- `subdomains`
- `domain2d8s`
- optional `domain2nsglue`
- optional `ip2nsglue`

### Phase 4: Deep investigation mode

Implement optional pivots:

- `domain2whois`
- `ns2domain`
- `mx2domain`
- `email_address`
- `email_domain`
- `email_user`

These should remain disabled by default.

---

## 15. Final recommendation

Build a single Zetalytics DNS enrichment connector and deploy it with multiple profiles.

Recommended initial rollout:

```text
1. Zetalytics DNS - Analyst Enrichment
2. Zetalytics DNS - Playbook
```

Add the automatic lightweight deployment later only after measuring result volume and analyst value.

The result should be a connector that gives analysts strong DNS pivoting capability without turning every enrichment into a large uncontrolled graph expansion.
