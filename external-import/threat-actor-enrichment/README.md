# OpenCTI Threat Actor Enrichment Connector

Periodically enriches `threat-actor-group` entities by computing their real `last_seen` date from related indicators and reports.

## Problem

OpenCTI treats `last_seen` on threat actors as a static STIX property. When new indicators or reports are linked to a threat actor's malware, the actor's `last_seen` is not updated. Active groups can show `last_seen` months or years behind their actual activity.

## How it works

Runs on a configurable interval (default: 24 hours). For each `threat-actor-group`, the connector talks to OpenCTI exclusively through `pycti`'s API client (`helper.api.*`) — there is no direct Elasticsearch access — so reads and writes inherit the platform's access-control model, GraphQL filter semantics, TLS / proxy settings and audit logging:

1. Lists every `Threat-Actor-Group` via `helper.api.threat_actor_group.list(getAll=True)`.
2. For each actor, lists the `uses` relationships pointing at `Malware` (`helper.api.stix_core_relationship.list(fromId=..., relationship_type="uses", toTypes=["Malware"])`) and collects the related malware ids.
3. Finds the latest indicator activity via `helper.api.indicator.list(filters=regardingOf(malware_ids, "indicates"), orderBy="valid_from", first=1)`. Falls back to the indicator's `created_at` when `valid_from` is missing or sentinel.
4. Finds the latest report activity via `helper.api.report.list(filters=objects(malware_ids), orderBy="published", first=1)`.
5. Updates `last_seen` via `helper.api.stix_domain_object.update_field(...)` when either the computed date is newer than the current value, **or** the current value is missing, an epoch-zero/far-future sentinel, or otherwise unparseable (the connector also self-heals historical bad data on the next run).

## Configuration

| Parameter  | Environment variable                  | Default | Description       |
|------------|---------------------------------------|---------|-------------------|
| `interval` | `THREAT_ACTOR_ENRICHMENT_INTERVAL`    | `24`    | Hours between runs |

The connector also reads the standard `OPENCTI_URL`, `OPENCTI_TOKEN`, `CONNECTOR_ID`, `CONNECTOR_TYPE`, `CONNECTOR_NAME`, `CONNECTOR_SCOPE` and `CONNECTOR_LOG_LEVEL` variables shared by every external-import connector.

## Deployment

Add to your OpenCTI `docker-compose.yml`:

```yaml
connector-threat-actor-enrichment:
  image: opencti/connector-threat-actor-enrichment:latest
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    - CONNECTOR_ID=${CONNECTOR_THREAT_ACTOR_ENRICHMENT_ID}
    - CONNECTOR_TYPE=EXTERNAL_IMPORT
    - CONNECTOR_NAME=Threat Actor Enrichment
    - CONNECTOR_SCOPE=threat-actor-group
    - CONNECTOR_LOG_LEVEL=info
    - THREAT_ACTOR_ENRICHMENT_INTERVAL=24
  restart: always
  depends_on:
    opencti:
      condition: service_healthy
```
