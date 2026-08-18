# OpenCTI Dark Web Informer Connector

## Introduction

Dark Web Informer monitors dark web forums, ransomware leak sites, and cybercrime
channels, publishing alerts on data leaks, breaches, and threat-actor activity.

This external-import connector ingests Dark Web Informer intelligence into OpenCTI
in **passthrough mode**: it fetches the prebuilt STIX 2.1 bundles that Dark Web
Informer publishes and forwards them without any client-side conversion. The only
objects the connector adds are provenance ones — a "Dark Web Informer" organization
author and a TLP marking — attached to the ingested objects that do not already
declare their own. Because the bundles are already valid STIX 2.1 carrying
deterministic IDs, OpenCTI deduplicates and merges on re-ingest.

## Requirements

- OpenCTI Platform >= 6.8.12
- Python 3.11 or 3.12
- A Dark Web Informer API key (`X-API-Key`)

## Configuration

Configuration is provided via environment variables, `config.yml`, or
`docker-compose.yml`. The connector uses `connectors-sdk` Pydantic settings.

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

### OpenCTI

| Parameter | Docker env var  | Mandatory | Description                                 |
|-----------|-----------------|-----------|---------------------------------------------|
| URL       | `OPENCTI_URL`   | Yes       | URL of the OpenCTI platform.                |
| Token     | `OPENCTI_TOKEN` | Yes       | Token of a user with the right permissions. |

### Connector

| Parameter       | Docker env var              | Default            | Description                                                                                                                                                                                                                                                              |
|-----------------|-----------------------------|--------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ID              | `CONNECTOR_ID`              | —                  | Unique UUIDv4 for this instance.                                                                                                                                                                                                                                         |
| Name            | `CONNECTOR_NAME`            | Dark Web Informer  | Connector name.                                                                                                                                                                                                                                                          |
| Scope           | `CONNECTOR_SCOPE`           | dark-web-informer  | Connector scope.                                                                                                                                                                                                                                                         |
| Log Level       | `CONNECTOR_LOG_LEVEL`       | error              | debug, info, warn, error.                                                                                                                                                                                                                                                |
| Duration Period | `CONNECTOR_DURATION_PERIOD` | PT6H               | ISO-8601 period between runs. Dark Web Informer regenerates its STIX exports every 30 minutes, so polling faster than hourly provides no benefit; hourly or slower is recommended. OpenCTI deduplicates on deterministic STIX IDs, so overlapping runs merge rather than duplicate. |

### Dark Web Informer

| Parameter            | Docker env var                        | Default                          | Description                                                                                  |
|----------------------|---------------------------------------|----------------------------------|----------------------------------------------------------------------------------------------|
| Base URL             | `DARK_WEB_INFORMER_BASE_URL`          | https://api.darkwebinformer.com  | API base URL.                                                                                |
| API Key              | `DARK_WEB_INFORMER_API_KEY`           | —                                | Sent as the `X-API-Key` header. **Required.**                                                |
| Sources              | `DARK_WEB_INFORMER_SOURCES`           | feed,ransomware,iocs             | Which prebuilt STIX bundles to ingest: `feed`, `ransomware`, `iocs` (or `all`).              |
| Use preview endpoint | `DARK_WEB_INFORMER_USE_PREVIEW_ENDPOINT` | false                         | Use the smaller on-demand `/api/stix.json` preview instead of the full bulk bundles (useful for testing). |
| Preview limit        | `DARK_WEB_INFORMER_PREVIEW_LIMIT`     | 5000                             | Object limit when `use_preview_endpoint` is true (max 5000).                                 |
| TLP level            | `DARK_WEB_INFORMER_TLP_LEVEL`         | amber+strict                     | TLP marking applied to ingested objects that do not already carry one. One of `clear`, `white`, `green`, `amber`, `amber+strict`, `red`. |

## Deployment

### Docker

```shell
docker compose up -d --build
```

### Manual

```shell
cd src
pip install -r requirements.txt
cp ../config.yml.sample ../config.yml   # then edit
python main.py
```

## Behavior

The connector runs every `duration_period`. On each run it fetches, for each
configured source, the corresponding prebuilt STIX 2.1 bundle and forwards it to
OpenCTI, adding only the author and TLP marking described below.

| Source     | Endpoint                          | Content                                          |
|------------|-----------------------------------|--------------------------------------------------|
| feed       | `/api/stix/export_feed.json`      | Threat-feed alerts as native STIX 2.1            |
| ransomware | `/api/stix/export_ransomware.json`| Ransomware victim intelligence as native STIX 2.1|
| iocs       | `/api/stix/export_iocs.json`      | Indicators of compromise as native STIX 2.1      |
| all        | `/api/stix/export.json`           | Combined bundle of all of the above              |

When `use_preview_endpoint` is true, the connector instead calls
`/api/stix.json?source=...&limit=...` to retrieve a smaller on-demand bundle,
which is convenient for testing without transferring the full export.

The bundles are forwarded with `helper.send_stix2_bundle`, using
`cleanup_inconsistent_bundle=True` so a dangling reference in a third-party bundle
drops the offending object instead of failing the whole import. Dark Web Informer's
bundles already include its own identity and a copyright marking, and use
deterministic STIX IDs, so repeated full-snapshot ingestion merges rather than
duplicates objects in the platform.

**Provenance.** No STIX is rewritten on the connector side, but a "Dark Web
Informer" organization author and a `tlp_level` marking are prepended to each
bundle and referenced by the objects that carry neither. Objects that already
declare a `created_by_ref` or `object_marking_refs` keep Dark Web Informer's own
values. Observables receive `x_opencti_created_by_ref` instead, since STIX 2.1
SCOs cannot carry `created_by_ref`.

A work is only registered once a non-empty bundle is available, so a run that
finds nothing does not leave an empty job in OpenCTI.

**Authentication.** Each request carries `X-API-Key` and a single-use `X-Nonce`
(`<10-digit epoch>:<>=6 chars [A-Za-z0-9_-]>`, 120 s window). No client-side HMAC.

**Rate limits (default tier).** 5 req/min per key, 150 calls per UTC day. On HTTP
429 the client honors `Retry-After`, otherwise `RateLimit-Reset`. Because the STIX
exports regenerate every 30 minutes and the bundles are large, run the connector
hourly or slower.

## Development

```shell
# from the repository root
black external-import/dark-web-informer
isort --profile black external-import/dark-web-informer
cd shared/pylint_plugins/check_stix_plugin
PYTHONPATH=. python -m pylint ../../../external-import/dark-web-informer --load-plugins linter_stix_id_generator
flake8 --ignore=E,W external-import/dark-web-informer
make connector_config_schema
```
