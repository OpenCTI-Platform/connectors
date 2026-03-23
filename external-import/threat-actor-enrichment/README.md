# OpenCTI Threat Actor Enrichment Connector

Periodically enriches threat actor group entities by computing their real `last_seen` date from related indicators and reports.

## Problem

OpenCTI treats `last_seen` on threat actors as a static STIX property. When new indicators or reports are linked to a threat actor's malware, the actor's `last_seen` is not updated. Active groups can show `last_seen` months or years behind their actual activity.

## How it works

Runs on a configurable interval (default: 24 hours). For each `threat-actor-group`:

1. Queries Elasticsearch for malware IDs linked via `rel_uses` relationships
2. Finds the latest `valid_from` from **indicators** that indicate the linked malware
3. Finds the latest `published` date from **reports** referencing the linked malware
4. If the computed date is newer than the current `last_seen`, updates via the OpenCTI GraphQL API

Reads use Elasticsearch for fast aggregations. Writes go through the OpenCTI API for proper cache invalidation, stream events, and audit logging.

## Configuration

| Parameter | Environment variable | Default | Description |
|---|---|---|---|
| `es_host` | `THREAT_ACTOR_ENRICHMENT_ES_HOST` | — | Elasticsearch URL |
| `es_user` | `THREAT_ACTOR_ENRICHMENT_ES_USER` | `""` | Elasticsearch username |
| `es_password` | `THREAT_ACTOR_ENRICHMENT_ES_PASSWORD` | `""` | Elasticsearch password |
| `es_verify_ssl` | `THREAT_ACTOR_ENRICHMENT_ES_VERIFY_SSL` | `false` | Verify ES SSL certificate |
| `sdo_index` | `THREAT_ACTOR_ENRICHMENT_SDO_INDEX` | `opencti_stix_domain_objects-*` | SDO index pattern |
| `interval` | `THREAT_ACTOR_ENRICHMENT_INTERVAL` | `24` | Hours between runs |

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
    - THREAT_ACTOR_ENRICHMENT_ES_HOST=http://elasticsearch:9200
    - THREAT_ACTOR_ENRICHMENT_INTERVAL=24
  restart: always
  depends_on:
    opencti:
      condition: service_healthy
```
