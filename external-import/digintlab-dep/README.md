# Double Extortion (DigIntLab DEP) Connector

| Status    | Date | Comment |
| --------- | ---- | ------- |
| Community | -    | -       |

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration](#configuration)
  - [Configuration Variables](#configuration-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Behavior](#behavior)
  - [Data Flow](#data-flow)
  - [Entity Mapping](#entity-mapping)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

The Double Extortion connector ingests ransomware and data leak announcements published on the [DoubleExtortion Platform](https://doubleextortion.com/) by DigIntLab and converts them into STIX 2.1 entities inside OpenCTI.

The platform tracks ransomware groups' activities, including victim announcements, leak site publications, and related metadata. This connector enables automated ingestion of this intelligence for threat monitoring and incident tracking.

### Features

- Authenticates against AWS Cognito identity provider
- Models double extortion announcements as either **Reports** or **Incidents**
- Creates **Organization** identities for victims
- Generates optional **Indicators** for victim domains and leak hash identifiers
- Supports multiple datasets (for example `ext`, `sanctions`)
- Maintains connector state for incremental updates
- Replays an overlap window on each run to avoid missing late-arriving records
- Uses deterministic primary object IDs based on the DEP `hashid` so updates merge cleanly
- Validates and normalizes DEP payload fields before STIX object creation
- Optionally skips records with empty or placeholder victim names (`n/a`, `none`)
- Optionally creates sector class identities and links victims to sectors
- Optionally creates intrusion sets from actor names
- Optionally creates country locations and links victims to countries
- Applies `TLP:AMBER` to all generated STIX objects and relationships
- Creates OpenCTI work entries for each run and sends bundles with inconsistent-object cleanup enabled

---

## Installation

### Requirements

- OpenCTI Platform >= 6.8.13
- Double Extortion Platform account with:
  - Username and password
  - API key
  - AWS Cognito client ID

---

## Configuration

### Configuration Variables

#### OpenCTI Parameters

| Parameter     | Docker envvar   | Mandatory | Description                     |
| ------------- | --------------- | --------- | ------------------------------- |
| OpenCTI URL   | `OPENCTI_URL`   | Yes       | The URL of the OpenCTI platform |
| OpenCTI Token | `OPENCTI_TOKEN` | Yes       | API token for OpenCTI           |

#### Base Connector Parameters

| Parameter       | Docker envvar            | Mandatory | Default                              | Description                                                   |
| --------------- | ------------------------ | --------- | ------------------------------------ | ------------------------------------------------------------- |
| Connector ID    | `CONNECTOR_ID`           | Yes       | -                                    | A unique `UUIDv4` for this connector                          |
| Connector Name  | `CONNECTOR_NAME`         | Yes       | -                                    | Name displayed in OpenCTI                                     |
| Connector Scope | `CONNECTOR_SCOPE`        | Yes       | `report,incident,identity,indicator` | Supported object scopes; include both `report` and `incident` |
| Log Level       | `CONNECTOR_LOG_LEVEL`    | No        | `info`                               | Log level: `debug`, `info`, `warn`, or `error`                |
| Run Interval    | `CONNECTOR_RUN_INTERVAL` | No        | `3600`                               | Interval in seconds between executions                        |

#### Connector Extra Parameters

| Parameter                | Docker envvar                  | Mandatory | Default                                                   | Description                                                                                 |
| ------------------------ | ------------------------------ | --------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Username                 | `DEP_USERNAME`                 | Yes       | -                                                         | Double Extortion Platform username                                                          |
| Password                 | `DEP_PASSWORD`                 | Yes       | -                                                         | Double Extortion Platform password                                                          |
| API Key                  | `DEP_API_KEY`                  | Yes       | -                                                         | API key issued by the platform                                                              |
| Client ID                | `DEP_CLIENT_ID`                | Yes       | -                                                         | AWS Cognito App Client ID                                                                   |
| Login Endpoint           | `DEP_LOGIN_ENDPOINT`           | No        | `https://cognito-idp.eu-west-1.amazonaws.com/`            | Cognito login endpoint                                                                      |
| API Endpoint             | `DEP_API_ENDPOINT`             | No        | `https://api.eu-ep1.doubleextortion.com/v1/dbtr/privlist` | REST endpoint for announcements                                                             |
| Lookback Days            | `DEP_LOOKBACK_DAYS`            | No        | `7`                                                       | Days to look back on the first run                                                          |
| Overlap Hours            | `DEP_OVERLAP_HOURS`            | No        | `72`                                                      | Hours subtracted from `last_run` to replay recent data                                      |
| Extended Results         | `DEP_EXTENDED_RESULTS`         | No        | `true`                                                    | Request extended leak information                                                           |
| Dataset                  | `DEP_DSET`                     | No        | `ext`                                                     | Dataset to query (`ext`, `sanctions`, etc.)                                                 |
| Enable Site Indicator    | `DEP_ENABLE_SITE_INDICATOR`    | No        | `true`                                                    | Create a domain indicator when a victim domain or site is available                         |
| Enable Hash Indicator    | `DEP_ENABLE_HASH_INDICATOR`    | No        | `true`                                                    | Create a hash indicator when the DEP `hashid` matches a supported hash type                 |
| Skip Empty Victim        | `DEP_SKIP_EMPTY_VICTIM`        | No        | `true`                                                    | Skip records where victim is empty or placeholder (`n/a`, `none`)                           |
| Create Sector Identities | `DEP_CREATE_SECTOR_IDENTITIES` | No        | `true`                                                    | Create sector `identity_class=class` entities and link victims via `part-of`                |
| Create Intrusion Sets    | `DEP_CREATE_INTRUSION_SETS`    | No        | `true`                                                    | Create `Intrusion-Set` entities from actor names; linked to incidents only in incident mode |
| Create Country Locations | `DEP_CREATE_COUNTRY_LOCATIONS` | No        | `true`                                                    | Create country `Location` entities and link victims via `located-at`                        |
| Primary Object           | `DEP_PRIMARY_OBJECT`           | No        | `report`                                                  | Primary STIX object created per announcement: `report` or `incident`                        |
| Confidence               | `DEP_CONFIDENCE`               | No        | `70`                                                      | Confidence level for created objects                                                        |

---

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti-connector-dep .
```

Use the following `docker-compose.yml`:

```yaml
services:
  connector-dep:
    image: opencti-connector-dep:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_DEP_ID}
      - CONNECTOR_NAME=Double Extortion
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_RUN_INTERVAL=3600
      - DEP_USERNAME=${DEP_USERNAME}
      - DEP_PASSWORD=${DEP_PASSWORD}
      - DEP_API_KEY=${DEP_API_KEY}
      - DEP_CLIENT_ID=${DEP_CLIENT_ID}
      - DEP_LOOKBACK_DAYS=7
      - DEP_OVERLAP_HOURS=72
      - DEP_EXTENDED_RESULTS=true
      - DEP_DSET=ext
      - DEP_ENABLE_SITE_INDICATOR=true
      - DEP_ENABLE_HASH_INDICATOR=true
      - DEP_SKIP_EMPTY_VICTIM=true
      - DEP_CREATE_SECTOR_IDENTITIES=true
      - DEP_CREATE_INTRUSION_SETS=true
      - DEP_CREATE_COUNTRY_LOCATIONS=true
      - DEP_PRIMARY_OBJECT=report
    restart: always
    depends_on:
      - opencti
```

### Manual Deployment

1. Clone the repository and navigate to the connector directory.
2. Install dependencies: `pip install -r src/requirements.txt`
3. Configure `src/config.yml` using `src/config.yml.sample`.
4. Run: `python src/main.py`

(The Dockerfile copies the contents of `src/` to the container working
directory, so inside Docker the file layout is flat — but for a manual
local run the same commands have to point at `src/`.)

---

## Behavior

### Data Flow

```mermaid
graph TB
    subgraph DEP Platform
        API[DEP API]
    end

    subgraph Processing
        Connector[DEP Connector]
    end

    Connector -->|Fetch announcements (API key + IdToken)| API
    API -->|Leak records| Connector

    subgraph OpenCTI
        Connector --> Primary[Primary Object - Report or Incident]
        Connector --> Victim[Identity - Victim Org]
        Connector --> Sector[Identity - Sector Class]
        Connector --> Actor[Intrusion Set]
        Connector --> Country[Location - Country]
        Connector --> DomainInd[Indicator - Domain]
        Connector --> HashInd[Indicator - Hash]
    end

    Primary -->|contains or targets| Victim
    Victim -->|part-of| Sector
    Primary -->|contains or attributed-to| Actor
    Victim --> Country
    Actor --> Sector
    Actor --> Country
    Sector --> Country
    DomainInd -->|related-to in report mode| Victim
    DomainInd -->|indicates in incident mode| Primary
    HashInd -->|related-to in report mode| Victim
    HashInd -->|indicates in incident mode| Primary
```

### Entity Mapping

| DEP Data          | OpenCTI Entity          | Notes                                                                                                                                     |
| ----------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Announcement      | Report or Incident      | Controlled by `DEP_PRIMARY_OBJECT`; reports are the default, incidents use `incident_type=cybercrime` and `first_seen`                    |
| Victim Name       | Identity (Organization) | Organization identity with revenue description                                                                                            |
| Victim Sector     | Identity (Class)        | Optional; created when `create_sector_identities=true`                                                                                    |
| Threat Actor      | Intrusion Set           | Optional; created when `create_intrusion_sets=true` and actor value is not generic                                                        |
| Victim Country    | Location                | Optional; created when `create_country_locations=true`                                                                                    |
| Victim Domain     | Indicator               | STIX pattern: `[domain-name:value = '...']`                                                                                               |
| Hash ID           | Indicator               | STIX pattern based on hash type (MD5, SHA-1, SHA-256)                                                                                     |
| Announcement Link | External Reference      | Link to DEP announcement page                                                                                                             |
| Victim Site       | External Reference      | Link to victim's website                                                                                                                  |
| -                 | Relationship            | `targets`, `part-of`, `attributed-to`, `located-at`, `related-to`, `indicates`; report mode also embeds created objects via `object_refs` |

### Primary Object Modes

#### Report Mode

- Default mode (`DEP_PRIMARY_OBJECT=report`)
- Creates one `Report` per announcement with `report_types=["threat-report"]`
- The report contains the victim, optional entities, and indicators via `object_refs`
- Indicators are additionally linked to the victim with `related-to`
- No `Incident` object is created in this mode

#### Incident Mode

- Enabled with `DEP_PRIMARY_OBJECT=incident`
- Creates one `Incident` per announcement with deterministic ID, `incident_type=cybercrime`, and `first_seen`
- Links the incident to the victim with `targets`
- Links indicators to the incident with `indicates`
- Links intrusion sets to the incident with `attributed-to`

### Processing Details

1. **Authentication**
   - Authenticates with AWS Cognito using username and password
   - Retrieves an ID token for API authorization
   - Uses the API key for additional authentication

2. **Data Fetching**
   - Fetches announcements within the configured date range
   - Uses `lookback_days` on the first run
   - On subsequent runs, uses `last_run - overlap_hours` to replay recent records
   - Supports extended results for additional leak metadata
   - Validates payload records and skips malformed entries with warning logs

3. **Primary Object Creation**
   - Creates either a report or an incident named `DEP announcement - {victim_name}`
   - Auto-decodes URL-encoded announcement descriptions
   - Uses the announcement date as `published` for reports or `first_seen` for incidents
   - Uses deterministic UUIDv5 IDs derived from the DEP `hashid`
   - Adds labels: `DigIntLab` plus `dep:announcement-type:{value}` from `annDataTypes`
   - Stores optional source fields as custom properties: `dep_actor`, `dep_country`
   - Creates an external reference pointing to the DEP announcement or victim site

4. **Victim Identity**
   - Name: victim organization name
   - Identity class: `organization`
   - Description includes reported revenue
   - If sector identities are disabled, the sector is added to the victim description
   - External references include the DEP announcement and victim site when available

5. **Sector Identity Creation**
   - Enabled when `create_sector_identities=true`
   - Creates `Identity` objects with `identity_class=class`
   - Sector names are normalized before creation

6. **Intrusion Set Creation**
   - Enabled when `create_intrusion_sets=true`
   - Creates deterministic `Intrusion-Set` IDs from actor names
   - Skips low-quality generic actor values such as `unknown`, `anonymous`, or `threat actor`

7. **Country Location Creation**
   - Enabled when `create_country_locations=true`
   - Creates deterministic `Location` IDs from country names
   - Uses `x_opencti_location_type=Country`

8. **Indicator Creation**
   - **Domain indicator** when `enable_site_indicator=true`
     - Pattern: `[domain-name:value = '{victim_domain}']`
     - Normalizes `victimDomain` or `site` through URL parsing and lowercasing
   - **Hash indicator** when `enable_hash_indicator=true`
     - Auto-detects hash type by length: MD5=32, SHA-1=40, SHA-256=64
     - Pattern: `[file:hashes.'{type}' = '{hash}']`
     - Unsupported hash lengths do not create an indicator

9. **Relationships**
   - `targets`: Incident -> Victim Organization in incident mode
   - `part-of`: Victim Organization -> Sector Identity when sector identities are enabled
   - `attributed-to`: Incident -> Intrusion Set in incident mode when intrusion sets are enabled
   - `located-at`: Victim Organization -> Country Location when country locations are enabled
   - `targets`: Intrusion Set -> Sector Identity when both are present
   - `targets`: Intrusion Set -> Country Location when both are present
   - `related-to`: Sector Identity -> Country Location when both are present
   - `related-to`: Domain or hash indicator -> Victim Organization in report mode
   - `indicates`: Domain or hash indicator -> Incident in incident mode

10. **Marking and Delivery**

- All generated objects and relationships are marked `TLP:AMBER`
- The marking-definition SDO is included in every emitted bundle so the platform's `cleanup_inconsistent_bundle` pass cannot strip the markings as dangling references
- Each connector cycle is tracked as an OpenCTI work item; the Work record is closed with `in_error=True` whenever the cycle hit a fetch failure or any per-item processing error
- Bundles are sent with inconsistent-bundle cleanup enabled. The legacy `update=` kwarg is no longer plumbed through (the helper-side knob was deprecated and removed under the connector-linter `VC506` rule); the connector now defers entirely to the platform's default update behaviour

11. **Record Filtering**

- When `skip_empty_victim=true`, records with victim values `""`, `n/a`, or `none` are ignored

### State Management

| State Key  | Description                          |
| ---------- | ------------------------------------ |
| `last_run` | ISO timestamp of last successful run |

The connector always reprocesses a recent overlap window (`DEP_OVERLAP_HOURS`) from `last_run` to reduce the chance of missing delayed updates.

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug`. Common issues:

- **Authentication failures**: Verify DEP credentials and client ID
- **API errors**: Check API endpoint and key validity
- **Missing data**: Ensure `extended_results` is enabled for full metadata
- **Unexpected object type**: Verify `DEP_PRIMARY_OBJECT` is either `report` or `incident`

### Development Notes

- URL-encoded descriptions are automatically decoded
- Common malformed announcement links (`https//...`) are auto-repaired to valid URLs
- Optional text fields (`sector`, `actor`, `country`) are normalized; placeholders like `n/a` and `none` are treated as empty
- Delete connector state in OpenCTI to re-ingest older records

---

## Additional Information

### Datasets

| Dataset     | Description                             |
| ----------- | --------------------------------------- |
| `ext`       | Standard double extortion announcements |
| `sanctions` | Sanctions-related data                  |

### License

This project is released under the [MIT License](LICENSE).

### Contact

- **Platform**: https://doubleextortion.com/
- **Provider**: DigIntLab
