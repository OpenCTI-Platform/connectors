# OpenCTI Splunk Connector

The OpenCTI Splunk connector imports security knowledge from Splunk and Splunk Enterprise Security.

## Introduction

This external import connector supports three dataset families with independent enablement and intervals:

- **Indicators**: Splunk saved searches and correlation searches are imported as OpenCTI Indicators with `pattern_type="spl"`.
- **Identities**: Splunk Enterprise Security assets and identities are imported as OpenCTI Identity and Infrastructure entities.
- **Incidents**: Splunk Enterprise Security findings and alerts are imported as OpenCTI Incidents with related Sighting objects.

OpenCTI case creation is not included in this version.

## Requirements

- OpenCTI Platform >= 6.8.13
- Python >= 3.11
- Splunk management API access, usually on port 8089
- A Splunk bearer token with permission to read saved searches, execute configured custom searches, and read Splunk Enterprise Security assets, identities, and findings when those datasets are enabled

### Splunk Cloud Platform

For Splunk Cloud Platform deployments, the connector uses the Splunk REST API on the management port. Configure `SPLUNK_BASE_URL` as:

```text
https://<deployment-name>.splunkcloud.com:8089
```

Splunk Cloud REST API access might need to be enabled before the connector can reach this URL. Use the Splunk Admin Config Service (ACS) search API allowlist or open a Splunk Support case to allow REST API access from the connector's source IP range. The default saved-search inventory endpoint is `/servicesNS/-/-/saved/searches`, which is supported by Splunk's namespace REST API pattern, but the token must have permission to read saved searches and any enabled Splunk Enterprise Security resources.

## Configuration Variables

### OpenCTI

| Parameter | Docker environment variable | Mandatory | Description |
| --- | --- | --- | --- |
| OpenCTI URL | `OPENCTI_URL` | Yes | URL of the OpenCTI platform. |
| OpenCTI Token | `OPENCTI_TOKEN` | Yes | OpenCTI API token. |

### Base Connector

| Parameter | Docker environment variable | Default | Mandatory | Description |
| --- | --- | --- | --- | --- |
| Connector ID | `CONNECTOR_ID` |  | Yes | Unique UUIDv4 connector instance ID. |
| Connector Name | `CONNECTOR_NAME` | `Splunk` | No | Connector name. |
| Connector Scope | `CONNECTOR_SCOPE` | `indicator,identity,incident` | No | OpenCTI entity scopes. |
| Log Level | `CONNECTOR_LOG_LEVEL` | `info` | No | Logging level. |
| Duration Period | `CONNECTOR_DURATION_PERIOD` | `PT5M` | No | Base scheduler period. Dataset-specific intervals are checked on each run. |

### Splunk

| Parameter | Docker environment variable | Default | Mandatory | Description |
| --- | --- | --- | --- | --- |
| Base URL | `SPLUNK_BASE_URL` |  | Yes | Splunk management API URL, for example `https://splunk.example.com:8089`. |
| Bearer Token | `SPLUNK_TOKEN` |  | Yes | Splunk bearer token. |
| Verify SSL | `SPLUNK_VERIFY_SSL` | `true` | No | Verify Splunk TLS certificates. |
| Timeout | `SPLUNK_TIMEOUT_SECONDS` | `60` | No | HTTP request and search completion timeout. |
| Owner | `SPLUNK_OWNER` | `-` | No | Splunk namespace owner for saved-search enumeration. |
| App | `SPLUNK_APP` | `-` | No | Splunk namespace app for saved-search enumeration. |
| Scopes | `SPLUNK_SCOPES` | `indicator,identity,incident` | No | Entity scopes to expose: `indicator`, `identity`, `incident`. |
| Import Indicators | `SPLUNK_IMPORT_INDICATORS` | `true` | No | Enable saved-search import. |
| Import Identities | `SPLUNK_IMPORT_IDENTITIES` | `true` | No | Enable assets and identities import. |
| Import Incidents | `SPLUNK_IMPORT_INCIDENTS` | `true` | No | Enable findings and alerts import. |
| Indicators Interval | `SPLUNK_INDICATORS_INTERVAL` | `PT1H` | No | Saved-search import interval. |
| Identities Interval | `SPLUNK_IDENTITIES_INTERVAL` | `P1D` | No | Asset/identity import interval. |
| Incidents Interval | `SPLUNK_INCIDENTS_INTERVAL` | `PT15M` | No | Findings import interval. |
| Incidents Lookback | `SPLUNK_INCIDENTS_LOOKBACK` | `P1D` | No | First-run lookback window for findings. |
| Indicators Search | `SPLUNK_INDICATORS_SEARCH` |  | No | Optional custom SPL returning saved-search-like rows. |
| Identities Search | `SPLUNK_IDENTITIES_SEARCH` |  | No | Optional custom SPL returning asset/identity rows. |
| Incidents Search | `SPLUNK_INCIDENTS_SEARCH` |  | No | Optional custom SPL returning finding rows. |
| Include Disabled | `SPLUNK_INCLUDE_DISABLED` | `false` | No | Include disabled saved searches. |
| Search Parameter Note Type | `SPLUNK_NOTE_TYPE_SEARCH_PARAMETERS` | `Search Parameters` | No | OpenCTI note type for saved-search parameter notes. |
| ES API Prefix | `SPLUNK_ES_API_PREFIX` | `/servicesNS/nobody/missioncontrol/public/v2` | No | Splunk ES public API prefix. |
| TLP | `SPLUNK_TLP_LEVEL` | `amber` | No | TLP marking for imported objects. |
| Confidence | `SPLUNK_CONFIDENCE` | `60` | No | Default confidence/score. |
| Batch Size | `SPLUNK_BATCH_SIZE` | `500` | No | STIX objects per bundle. |
| Max Records | `SPLUNK_MAX_RECORDS_PER_RUN` | `10000` | No | Source record cap per dataset run. Use `0` to disable. |

## Behavior

### Indicators

When `SPLUNK_INDICATORS_SEARCH` is empty, the connector enumerates saved searches through Splunk REST endpoints. Each saved search becomes an OpenCTI Indicator with the SPL query as its pattern and `spl` as its pattern type. Search settings such as earliest/latest time, cron schedule, dispatch options, alert settings, owner/app, ACL, and disabled status are stored in a linked Note whose note type defaults to `Search Parameters`.

MITRE ATT&CK technique IDs found in saved-search metadata are imported as Attack Patterns and linked to the indicator with `indicates` relationships.

### Identities

When `SPLUNK_IDENTITIES_SEARCH` is empty, the connector reads Splunk Enterprise Security asset and identity APIs. Identity rows become OpenCTI Individual identities. Asset rows become Infrastructure entities, with related owner identities when owner/user fields are available.

### Incidents and Sightings

When `SPLUNK_INCIDENTS_SEARCH` is empty, the connector reads Splunk Enterprise Security findings. Each finding becomes an Incident and a related Sighting. Finding IDs, SIDs, drilldown URLs, and source search metadata are preserved as external references where available.

### Custom Search Rows

Custom searches should return normalized field names where possible:

- Indicators: `name`, `search`, `description`, `cron_schedule`, `dispatch.earliest_time`, `dispatch.latest_time`, `mitre_attack_id`.
- Identities/assets: `record_type` (`asset` or `identity`), `identity`, `user`, `email`, `asset`, `host`, `hostname`, `ip`, `owner`, `aliases`.
- Incidents: `title`, `description`, `severity`, `urgency`, `_time`, `last_seen`, `sid`, `finding_id`, `drilldown_url`, `search_name`, `mitre_attack_id`.

## Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-splunk:latest .
```

Start with Docker Compose:

```bash
docker compose up -d
```

For local development:

```bash
cd external-import/splunk/src
pip install -r requirements.txt
python main.py
```

## Debugging

Set `CONNECTOR_LOG_LEVEL=debug` for detailed connector logs. State is tracked per dataset under `indicators`, `identities`, and `incidents`; state is only advanced after successful STIX bundle submission.
