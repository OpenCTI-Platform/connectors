# Google Threat Intelligence Connector

| Status            | Date | Comment |
|-------------------|------|---------|
| Filigran Verified | -    | -       |

---

Google Threat Intelligence provides unparalleled visibility into threats, enabling the delivery of detailed and timely intelligence to security teams worldwide. By protecting billions of users and detecting millions of phishing attempts, Google has a comprehensive view of the threat landscape.

This connector ingests **reports, campaigns, threat actors, malware families, software toolkits, vulnerabilities, and IOCs** from the GTI API directly into OpenCTI as structured STIX 2.1 objects.


> 🔑 This connector requires a Google Threat Intel API key to function. You can obtain one by signing up for the Google Threat Intel service.
> Reports are only available to users with the Google Threat Intelligence (Google TI) Enterprise or Enterprise Plus licenses.
>
### Table of Contents

- [Introduction](#introduction)
- [Data collections](#data-collections)
  - [1. Reports](#1-reports)
  - [2. Campaigns](#2-campaigns)
  - [3. Threat Actors](#3-threat-actors)
  - [4. Malware Families](#4-malware-families)
  - [5. Vulnerabilities](#5-vulnerabilities)
  - [6. Software Toolkits](#6-software-toolkits)
  - [7. Indicators / IOCs](#7-indicators--iocs)
- [Data mapping](#data-mapping)
  - [Intrusion-Set](#intrusion-set)
  - [Malware](#malware)
  - [Tool](#tool)
  - [Campaign](#campaign-gti-campaign)
  - [Vulnerability](#vulnerability-gti-vulnerability)
  - [Report](#report-gti-report)
  - [Indicator](#indicator)

- [Important API Quota Limitations](#important-api-quota-limitations)
- [Important Data Limitations](#important-data-limitations)
- [Installation](#installation)
  - [Requirements](#requirements)
  - [Quick start](#quick-start)
  - [Configurations Variables](#configurations-variables)
  - [Development](#development)


## Introduction

The **Google Threat Intelligence (GTI) Feeds Connector** ingests threat intelligence from the
[Google Threat Intelligence API](https://gtidocs.virustotal.com/reference/reports) into OpenCTI.

| Collection        | Config toggle                  | Enabled by default | Main OpenCTI entity | Related OpenCTI entity(s) produced                                                                                                 |
|-------------------|--------------------------------|--------------------|---------------------|------------------------------------------------------------------------------------------------------------------------------------|
| Reports           | `GTI_IMPORT_REPORTS`           | ✅ Yes              | Report              | Location, Sector, Malware, Tool, Intrusion-Set, Attack-Pattern, Vulnerability, Indicator, Observable (Domain, File, IP, URL), Note |
| Campaigns         | `GTI_IMPORT_CAMPAIGNS`         | ❌ No               | Campaign            | Location, Sector, Intrusion-Set, Malware, Attack-Pattern, Vulnerabilities, Tool                                                    |
| Threat Actors     | `GTI_IMPORT_THREAT_ACTORS`     | ❌ No               | Intrusion-Set       | Location, Sector, Attack-Pattern, Malware, Vulnerabilities, Tool                                                                   |
| Malware Families  | `GTI_IMPORT_MALWARE_FAMILIES`  | ❌ No               | Malware             | Location, Sector, Intrusion-Set, Attack-Pattern, Vulnerabilities                                                                   |
| Software Toolkits | `GTI_IMPORT_SOFTWARE_TOOLKITS` | ❌ No               | Tool                | Location, Sector, Malware, Attack-Pattern                                                                                          |
| Vulnerabilities   | `GTI_IMPORT_VULNERABILITIES`   | ❌ No               | Vulnerability       | Malware, Intrusion-Set, Attack-Pattern, Note, Observable (Software)                                                                |
| Indicators (IOC)  | `GTI_IMPORT_INDICATORS`        | ❌ No               | Indicator           | Observable (File, IPv4, IPv6, URL, Domain), Malware, Tool                                                                          |

## Data collections

### 1. Reports

Fetches Google TI **[Reports](https://gtidocs.virustotal.com/reference/report-object)** from the [GTI Collections API](https://gtidocs.virustotal.com/reference/list-collections)

#### How it works

The connector calls **`GET /collections`** with a filter on `collection_type:report` and `last_modification_date` to retrieve only reports modified since the last successful execution (the date is persisted in the connector state (`report_next_cursor_start_date`). On first run, it is calculated from `GTI_REPORT_IMPORT_START_DATE`).

For each report returned, the connector fetches all related sub-entities by calling **`GET /collections/{report_id}/{subentity_type}`** for each of the following types: `malware_families`, `threat_actors`, `attack_techniques`, `vulnerabilities`, `campaigns`, `domains`, `files`, `urls`, `ip_addresses`, and `software_toolkits`.

All sub-entities are then converted to STIX 2.1 objects and linked to the parent Report via `object_refs`, so that the final Report in OpenCTI contains references to all its related entities (threat actors, malware, IOCs, etc.).

Additionally, `Location`, `Sector`, and `Organization` objects are extracted directly from the report's own attributes (targeted countries, industries, organizations) — they do not require separate sub-entity API calls.

If `GTI_REPORT_DOWNLOAD_PDF` is enabled, the connector additionally downloads the report's PDF (via `GET /collections/{report_id}/download_report`) and attaches it to the Report object.

#### Sub-entities mapping

| Sub-entity type       | OpenCTI entity produced                    |
|-----------------------|--------------------------------------------|
| `malware_families`    | Malware                                    |
| `threat_actors`       | Intrusion-Set                              |
| `software_toolkits`   | Tool                                       |
| `attack_techniques`   | Attack-Pattern                             |
| `vulnerabilities`     | Vulnerability                              |
| `campaigns`           | Campaign                                   |
| `domains`             | Domain-Name observable + Indicator         |
| `files`               | File observable + Indicator                |
| `urls`                | URL observable + Indicator                 |
| `ip_addresses`        | IPv4-Addr/IPv6-Addr observable + Indicator |

#### Configurable filters

| Variable                   | Description                           | Example values                                                                                                                                                                      |
|----------------------------|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `GTI_REPORT_TYPES`         | Filter by report type                 | `All` or `Actor Profile`, `Malware Profile`, `Threat Activity Alert`, etc. [See available values](https://gtidocs.virustotal.com/docs/threat-intelligence-objects-modifiers-values) |
| `GTI_REPORT_ORIGINS`       | Filter by origin                      | `All` or `google threat intelligence`, `crowdsourced`. [See available values](https://gtidocs.virustotal.com/docs/threat-intelligence-objects-modifiers-values)                     |
| `GTI_REPORT_EXTRA_FILTERS` | Additional GTI query filters          | `name:phishing`. [See available filters](https://gtidocs.virustotal.com/docs/reports-search-modifiers)                                                                              |
| `GTI_REPORT_DOWNLOAD_PDF`  | Download and attach PDF to the report | `true` / `false`                                                                                                                                                                    |
| `GTI_REPORT_SUBENTITIES`   | Comma-separated list of sub-entity types to fetch and link for each report. An empty value disables sub-entity fetching entirely, which can help reduce API quota usage. | `malware_families`, `threat_actors`, `attack_techniques`, `vulnerabilities`, `campaigns`, `domains`, `files`, `urls`, `ip_addresses`, `software_toolkits` |

### 2. Campaigns

Fetches Google TI **[Campaigns](https://gtidocs.virustotal.com/reference/campaign-object)** from the [GTI Collections API](https://gtidocs.virustotal.com/reference/list-collections).

#### How it works

The connector calls **`GET /collections`** with a filter on `collection_type:campaign` and `last_modification_date` to retrieve only campaigns modified since the last successful execution. The date is persisted in the connector state as `campaign_next_cursor_start_date`; on first run, it is calculated from `GTI_CAMPAIGN_IMPORT_START_DATE`.

For each campaign returned, the connector fetches related sub-entities by calling **`GET /collections/{campaign_id}/{subentity_type}`** for: `malware_families`, `threat_actors`, `attack_techniques`, `vulnerabilities`, and `software_toolkits`.

All sub-entities are converted to STIX 2.1 objects and linked to the parent Campaign entity.

> **Note:** Relationships between a campaign and reports are not fetched here. These links are established when the `reports` collection is imported — reports fetch `campaigns` as one of their sub-entities, which creates the link in OpenCTI.

#### Sub-entities mapping

| Sub-entity type       | OpenCTI entity produced |
|-----------------------|-------------------------|
| `malware_families`    | Malware                 |
| `threat_actors`       | Intrusion-Set           |
| `attack_techniques`   | Attack-Pattern          |
| `vulnerabilities`     | Vulnerability           |
| `software_toolkits`   | Tool                    |


#### Configurable filters

| Variable                      | Description                  | Example values                                                                                                                         |
|-------------------------------|------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `GTI_CAMPAIGN_ORIGINS`        | Filter by origin             | `google threat intelligence`. [See available values](https://gtidocs.virustotal.com/docs/threat-intelligence-objects-modifiers-values) |
| `GTI_CAMPAIGN_EXTRA_FILTERS`  | Additional GTI query filters | [See available filters](https://gtidocs.virustotal.com/reference/list-collections#allowed-filters-by-object-collection_type)           |
| `GTI_CAMPAIGN_SUBENTITIES`    | Comma-separated list of sub-entity types to fetch and link for each campaign. An empty value disables sub-entity fetching entirely, which can help reduce API quota usage. | `malware_families`, `attack_techniques`, `vulnerabilities`, `threat_actors`, `domains`, `files`, `urls`, `ip_addresses`, `software_toolkits`, `reports` |

### 3. Threat Actors

Fetches Google TI **[Threat Actors](https://gtidocs.virustotal.com/reference/threat-actor-object)** from the [GTI Collections API](https://gtidocs.virustotal.com/reference/list-collections).

#### How it works

The connector calls **`GET /collections`** with a filter on `collection_type:threat-actor` and `last_modification_date` to retrieve only threat actors modified since the last successful execution.
The date is persisted in the connector state as `threat_actor_next_cursor_start_date`; on first run, it is calculated from `GTI_THREAT_ACTOR_IMPORT_START_DATE`.

For each threat actor returned, the connector fetches related sub-entities by calling **`GET /collections/{threat_actor_id}/{subentity_type}`** for: `malware_families`, `attack_techniques`, `vulnerabilities`, and `software_toolkits`.

All sub-entities are converted to STIX 2.1 objects and linked to the parent Intrusion-Set entity.

Additionally, `Location` and `Identity` (targeted countries, sectors) are extracted directly from the threat actor's own attributes.

> **Note:** Relationships between a threat actor and other entities such as campaigns or reports are not fetched here. These links are established when the `reports` or `campaigns` collections are imported — they fetch `threat_actors` as one of their sub-entities, which creates the link in OpenCTI.

#### Sub-entities mapping

| Sub-entity type       | OpenCTI entity produced |
|-----------------------|-------------------------|
| `malware_families`    | Malware                 |
| `attack_techniques`   | Attack-Pattern          | 
| `vulnerabilities`     | Vulnerability           |
| `software_toolkits`   | Tool                    |

#### Configurable filters

| Variable                           | Description                                                                      | Default value                      | Example values                                                                                                                                             |
|------------------------------------|----------------------------------------------------------------------------------|------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `GTI_THREAT_ACTOR_ORIGINS`         | Filter by origin                                                                 | `["google threat intelligence"]`   | `All` or `google threat intelligence`, `partner`. [See available values](https://gtidocs.virustotal.com/docs/threat-intelligence-objects-modifiers-values) |
| `GTI_THREAT_ACTOR_EXTRA_FILTERS`   | Optional list of additional filters to add to query when fetching threat actors  | `[]`                               | [See available filters](https://gtidocs.virustotal.com/reference/list-collections#allowed-filters-by-object-collection_type)                               |
| `GTI_ENABLE_THREAT_ACTOR_ALIASES`  | Whether to enable importing threat actor aliases from GTI                        | `false`                            | `true` / `false`. [See details and recommendations in the "Important Data Limitations" section above](#important-data-limitations)                         |
| `GTI_THREAT_ACTOR_SUBENTITIES`     | Comma-separated list of sub-entity types to fetch and link for each threat actor. An empty value disables sub-entity fetching entirely, which can help reduce API quota usage. | `["malware_families", "attack_techniques", "vulnerabilities", "software_toolkits"]` | `malware_families`, `attack_techniques`, `vulnerabilities`, `campaigns`, `reports`, `domains`, `files`, `urls`, `ip_addresses`, `software_toolkits` |

### 4. Malware Families

Fetches Google TI **[Malware Families](https://gtidocs.virustotal.com/reference/malware-family-object)** from the [GTI Collections API](https://gtidocs.virustotal.com/reference/list-collections).

#### How it works

The connector calls **`GET /collections`** with a filter on `collection_type:malware-family` and `last_modification_date` to retrieve only malware families modified since the last successful execution.
The date is persisted in the connector state as `malware_family_next_cursor_start_date`; on first run, it is calculated from `GTI_MALWARE_FAMILY_IMPORT_START_DATE`.

For each malware family returned, the connector fetches related sub-entities by calling **`GET /collections/{malware_family_id}/{subentity_type}`** for: `threat_actors`, `attack_techniques`, and `vulnerabilities`.
> **Note:** When fetching malware families, only relationships to `threat_actors`, `attack_techniques`, and `vulnerabilities` are retrieved directly.
> Relationships to other entities (e.g. reports or campaigns) are established indirectly: when the `reports` or `campaigns` collections are imported, they fetch `malware_families` as one of their sub-entities, which creates the link in OpenCTI.
> Therefore, to get a complete picture of a malware family's relationships, it is recommended to also enable the relevant collections.

All sub-entities are converted to STIX 2.1 objects and linked to the parent Malware entity, so that the final Malware in OpenCTI contains references to its related threat actors and techniques.

#### Sub-entities mapping

| Sub-entity type     | OpenCTI entity produced |
|---------------------|-------------------------|
| `threat_actors`     | Intrusion-Set           |
| `attack_techniques` | Attack-Pattern          |
| `vulnerabilities`   | Vulnerability           |

#### Configurable filters

| Variable                           | Description                                                                        | Default value                    | Supported values                                                                                                                                           |
|------------------------------------|------------------------------------------------------------------------------------|----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `GTI_MALWARE_FAMILY_ORIGINS`       | Filter by origin                                                                   | `["google threat intelligence"]` | `All` or `google threat intelligence`, `partner`. [See available values](https://gtidocs.virustotal.com/docs/threat-intelligence-objects-modifiers-values) |
| `GTI_MALWARE_FAMILY_EXTRA_FILTERS` | Optional list of additional filters to add to query when fetching malware families | `[]`                             | [See available filters](https://gtidocs.virustotal.com/reference/list-collections#allowed-filters-by-object-collection_type)                               |
| `GTI_ENABLE_MALWARE_ALIASES`       | Whether to enable importing malware family aliases from GTI                        | `false`                          | `true` / `false`. [See details and recommendations in the "Important Data Limitations" section above](#important-data-limitations)                         |
| `GTI_MALWARE_FAMILY_SUBENTITIES`   | Comma-separated list of sub-entity types to fetch and link for each malware family. An empty value disables sub-entity fetching entirely, which can help reduce API quota usage. | `["threat_actors", "attack_techniques", "vulnerabilities"]` | `threat_actors`, `attack_techniques`, `vulnerabilities`, `campaigns`, `reports`, `domains`, `files`, `urls`, `ip_addresses` |

### 5. Vulnerabilities

Fetches Google TI **[Vulnerabilities](https://gtidocs.virustotal.com/reference/vulnerability-object)** from the [GTI Collections API](https://gtidocs.virustotal.com/reference/list-collections).

#### How it works

The connector calls **`GET /collections`** with a filter on `collection_type:vulnerability` and `last_modification_date` to retrieve only vulnerabilities modified since the last successful execution.
The date is persisted in the connector state as `vulnerability_next_cursor_start_date`; on first run, it is calculated from `GTI_VULNERABILITY_IMPORT_START_DATE`.

For each vulnerability returned, the connector fetches related sub-entities by calling **`GET /collections/{vulnerability_id}/{subentity_type}`** for: `malware_families`, `attack_techniques`, and `threat_actors`.

All sub-entities are converted to STIX 2.1 objects and linked to the parent Vulnerability entity.

> **Note:** Relationships between a vulnerability and other entities such as reports or campaigns are not fetched here. These links are established when the `reports` or `campaigns` collections are imported — they fetch `vulnerabilities` as one of their sub-entities, which creates the link in OpenCTI.

#### Sub-entities mapping

| Sub-entity type     | OpenCTI entity produced |
|---------------------|-------------------------|
| `malware_families`  | Malware                 |
| `attack_techniques` | Attack-Pattern          |
| `threat_actors`     | Intrusion-Set           |


#### Configurable filters

| Variable                           | Description                                                                        | Default value                    | Supported values                                                                                                             |
|------------------------------------|------------------------------------------------------------------------------------|----------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| `GTI_VULNERABILITY_ORIGINS`        | Filter by origin                                                                   | `["google threat intelligence"]` | [See available values](https://gtidocs.virustotal.com/docs/threat-intelligence-objects-modifiers-values)                     |
| `GTI_VULNERABILITY_EXTRA_FILTERS`  | Optional list of additional filters to add to query when fetching vulnerabilities  | `[]`                             | [See available filters](https://gtidocs.virustotal.com/reference/list-collections#allowed-filters-by-object-collection_type) |
| `GTI_VULNERABILITY_SUBENTITIES`    | Comma-separated list of sub-entity types to fetch and link for each vulnerability. An empty value disables sub-entity fetching entirely, which can help reduce API quota usage. | `["malware_families", "attack_techniques", "threat_actors"]` | `malware_families`, `attack_techniques`, `threat_actors`, `campaigns`, `reports`, `domains`, `files`, `urls`, `ip_addresses` |

### 6. Software Toolkits

Fetches Google TI **[Software Toolkits](https://gtidocs.virustotal.com/reference/software-toolkit-object)** from the [GTI Collections API](https://gtidocs.virustotal.com/reference/list-collections).

#### How it works

The connector calls **`GET /collections`** with a filter on `collection_type:software-toolkit` and `last_modification_date` to retrieve only software toolkits modified since the last successful execution.
The date is persisted in the connector state as `software_toolkit_next_cursor_start_date`; on first run, it is calculated from `GTI_SOFTWARE_TOOLKIT_IMPORT_START_DATE`.

For each software toolkit returned, the connector fetches related sub-entities by calling **`GET /collections/{software_toolkit_id}/{subentity_type}`** for: `malware_families` and `attack_techniques`.

All sub-entities are converted to STIX 2.1 objects and linked to the parent Tool entity.

Additionally, `Location` and `Identity` (targeted countries, sectors) are extracted directly from the software toolkit's own attributes.

> **Note:** Relationships between a software toolkit and other entities such as reports or campaigns are not fetched here. These links are established when the `reports` or `campaigns` collections are imported — they fetch `software_toolkits` as one of their sub-entities, which creates the link in OpenCTI.

#### Sub-entities mapping

| Sub-entity type     | OpenCTI entity produced |
|---------------------|-------------------------|
| `malware_families`  | Malware                 |
| `attack_techniques` | Attack-Pattern          |

#### Configurable filters

| Variable                                | Description                                                                           | Default value                    | Supported values                                                                                                                                           |
|-----------------------------------------|---------------------------------------------------------------------------------------|----------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `GTI_SOFTWARE_TOOLKIT_ORIGINS`          | Filter by origin                                                                      | `["google threat intelligence"]` | `All` or `google threat intelligence`, `partner`. [See available values](https://gtidocs.virustotal.com/docs/threat-intelligence-objects-modifiers-values) |
| `GTI_SOFTWARE_TOOLKIT_EXTRA_FILTERS`    | Optional list of additional filters to add to query when fetching software toolkits   | `[]`                             | [See available filters](https://gtidocs.virustotal.com/reference/list-collections#allowed-filters-by-object-collection_type)                               |
| `GTI_SOFTWARE_TOOLKIT_SUBENTITIES`      | Comma-separated list of sub-entity types to fetch and link for each software toolkit. An empty value disables sub-entity fetching entirely, which can help reduce API quota usage. | `["malware_families", "attack_techniques"]` | `malware_families`, `attack_techniques` |

### 7. Indicators / IOCs

Fetches **Indicators** via the GTI **IOC Delta feed API**. The IOC Delta feed is a feed that generates minute-based packages of updated IOCs, which are then combined into a larger hourly package.

#### How it works

Unlike the other collections which use the `/collections` search endpoint, the IOC collection uses a **completely different mechanism**: binary delta packages delivered per hour (`YYYYMMDDHH` package IDs).

**What it produces in OpenCTI per IOC type:**

| IOC type | STIX Observable                          | STIX Indicator | Relationship |
|----------|------------------------------------------|----------------|--------------|
| `file`   | `File` (with MD5, SHA-1, SHA-256 hashes) | `Indicator`    | `based-on`   |
| `ip`     | `IPv4-Addr` or `IPv6-Addr`               | `Indicator`    | `based-on`   |
| `url`    | `URL`                                    | `Indicator`    | `based-on`   |
| `domain` | `Domain-Name`                            | `Indicator`    | `based-on`   |

#### Sub-entities mapping

| Sub-entity type       | OpenCTI entity produced |
|-----------------------|-------------------------|
| `malware_families`    | Malware                 |
| `attack_techniques`   | Attack-Pattern          |
| `threat_actors`       | Intrusion-Set           |
| `software_toolkits`   | Tool                    |

#### Configurable filters

| Variable                          | Description                                                                       | Default value                     | Supported values                                                                                                             |
|-----------------------------------|-----------------------------------------------------------------------------------|-----------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| `GTI_INDICATOR_TYPES`             | List of IOC types to import                                                       | `["file", "ip", "url", "domain"]` | `["file", "ip", "url", "domain"]`                                                                                            |
| `GTI_INDICATOR_MIN_SCORE`         | Minimum GTI score an indicator must have to be imported via Delta Sync            | `50`                               | Integer between `0` and `100`, or unset/`100` to disable the filter                                                          |
| `GTI_INDICATOR_REQUIRE_MALWARE_FAMILY` | Only import indicators associated with at least one Malware Family           | `false`                            | `true` / `false`                                                                                                             |
| `GTI_INDICATOR_REQUIRE_THREAT_ACTOR`   | Only import indicators associated with at least one Threat Actor             | `false`                            | `true` / `false`                                                                                                             |

---

## Data mapping

This section describes how GTI entities are mapped to OpenCTI STIX 2.1 objects.

> **Note on data depth:** Each entity type can be produced in two ways:
> - **As the main entity** of its dedicated collection (e.g., enabling the "Threat Actors" collection) — this provides the **full mapping** including all fields and relationships described below.
> - **As a sub-entity** of another collection (e.g., a threat actor referenced by a campaign) — in this case, only **first-level attributes** are populated (typically: `name`, `description`, `created_by_ref`, and first-level relationships such as `targeted_region` or `targeted_industry`). Sub-entity relationships (e.g., malware used by a threat actor) are **not** fetched.
>
> To get the complete data for an entity type, enable its dedicated collection.

### Intrusion-Set

> 📖 GTI Threat Actor documentation: https://gtidocs.virustotal.com/reference/threat-actor-object

#### Attribute mapping

These fields are mapped directly onto the STIX Intrusion-Set object.

| GTI Threat Actor Field   | STIX Field                                     | Notes                                                                                                              |
|--------------------------|------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| `name`                   | `name`                                         | The main display name                                                                                              |
| `description`            | `description`                                  | Full text description of the actor                                                                                 |
| `motivations`            | `primary_motivation` + `secondary_motivations` | First motivation → `primary_motivation`, remaining → `secondary_motivations` (e.g., `financial-gain`, `espionage`) |
| `first_seen_details`     | `first_seen`                                   | ISO 8601 timestamp (from `first_seen_details[0].value`)                                                            |
| `last_seen_details`      | `last_seen`                                    | ISO 8601 timestamp (from `last_seen_details[0].value`)                                                             |
| `alt_names_details`      | `aliases`                                      | From `alt_names_details[].value`. Requires `GTI_ENABLE_THREAT_ACTOR_ALIASES` to be enabled                         |
| `tags_details`           | `labels`                                       | From `tags_details[].value`                                                                                        |
| `creation_date`          | `created`                                      | UTC timestamp of object creation                                                                                   |
| `last_modification_date` | `modified`                                     | UTC timestamp of last update                                                                                       |
| `origin`                 | `created_by_ref`                               | UUID pointing to the Identity (e.g., Google Threat Intelligence)                                                   |
| `id`                     | `external_references`                          | Link to the GTI page for this threat actor                                                                         |

#### Relationship mapping from first-level attributes

These are **direct attributes** of the GTI Threat Actor object, but they are modeled as **separate entities + relationships** in OpenCTI because STIX represents them as distinct objects.

> ℹ️ These relationships are always produced when a Threat Actor is ingested, **even as a sub-entity of another collection** (e.g., via Campaigns), because the data is part of the Threat Actor's own definition.

| GTI Concept           | STIX Source Object | STIX Relationship  | STIX Target Object |
|-----------------------|--------------------|--------------------|--------------------|
| `targeted_industries` | Intrusion-Set      | `targets`          | Identity (Sector)  |
| `targeted_regions`    | Intrusion-Set      | `targets`          | Location           |
| `source_regions`      | Intrusion-Set      | `originates-from`  | Location           |

#### Relationship mapping from sub-entities (requires dedicated collection)

These relationships are **only produced when the Threat Actors collection is enabled**, as they require fetching additional sub-entities via dedicated API calls.

| GTI Concept                      | STIX Source Object | STIX Relationship | STIX Target Object            |
|----------------------------------|--------------------|-------------------|-------------------------------|
| `malware_families`               | Intrusion-Set      | `uses`            | Malware                       |
| `software_toolkits`              | Intrusion-Set      | `uses`            | Tool                          |
| `attack_techniques`              | Intrusion-Set      | `uses`            | Attack-Pattern                |
| `vulnerabilities`                | Intrusion-Set      | `targets`         | Vulnerability                 |

---

### Malware

> 📖 GTI Malware Family documentation: https://gtidocs.virustotal.com/reference/malware-family-object

#### Attribute mapping

These fields are mapped directly onto the STIX Malware object.

| GTI Malware Family Field | STIX Field              | Notes                                                                                       |
|--------------------------|-------------------------|---------------------------------------------------------------------------------------------|
| `name`                   | `name`                  | The main display name                                                                       |
| `description`            | `description`           | Full text description of the malware family                                                 |
| `malware_roles`          | `malware_types`         | From `malware_roles[].value`                                                                |
| `first_seen_details`     | `first_seen`            | From `first_seen_details[0].value`                                                          |
| `last_seen_details`      | `last_seen`             | From `last_seen_details[0].value`                                                           |
| `alt_names_details`      | `aliases`               | From `alt_names_details[].value`. Requires `GTI_ENABLE_MALWARE_ALIASES` to be enabled       |
| `tags_details`           | `labels`                | From `tags_details[].value`                                                                 |
| `capabilities`           | `capabilities`          | From `capabilities[].value`                                                                 |
| `creation_date`          | `created`               | UTC timestamp of object creation                                                            |
| `last_modification_date` | `modified`              | UTC timestamp of last update                                                                |
| `origin`                 | `created_by_ref`        | UUID pointing to the Identity (e.g., Google Threat Intelligence)                            |
| `id`                     | `external_references`   | Link to the GTI page for this malware family                                                |
| —                        | `is_family`             | Always set to `true`                                                                        |

#### Relationship mapping from first-level attributes

These are **direct attributes** of the GTI Malware Family object, but they are modeled as **separate entities + relationships** in OpenCTI because STIX represents them as distinct objects.

> ℹ️ These relationships are always produced when a Malware Family is ingested, **even as a sub-entity of another collection** (e.g., via Reports or Campaigns), because the data is part of the Malware Family's own definition.

| GTI Concept              | STIX Source Object | STIX Relationship  | STIX Target Object |
|--------------------------|--------------------|--------------------|--------------------|
| `targeted_industries`    | Malware            | `targets`          | Identity (Sector)  |
| `targeted_regions`       | Malware            | `targets`          | Location           |
| `source_regions`         | Malware            | `originates-from`  | Location           |

#### Relationship mapping from sub-entities (requires dedicated collection)

These relationships are **only produced when the Malware Families collection is enabled**, as they require fetching additional sub-entities via dedicated API calls.

| GTI Concept              | STIX Source Object | STIX Relationship | STIX Target Object |
|--------------------------|--------------------|-------------------|--------------------|
| `threat_actors`          | Intrusion-Set      | `uses`            | Malware            |
| `attack_techniques`      | Malware            | `uses`            | Attack-Pattern     |
| `vulnerabilities`        | Malware            | `targets`         | Vulnerability      |

---

### Tool

> 📖 GTI Software Toolkit documentation: https://gtidocs.virustotal.com/reference/software-toolkit-object

#### Attribute mapping

These fields are mapped directly onto the STIX Tool object.

| GTI Software Toolkit Field | STIX Field            | Notes                                                                   |
|----------------------------|-----------------------|-------------------------------------------------------------------------|
| `name`                     | `name`                | The main display name                                                   |
| `description`              | `description`         | Full text description of the software toolkit                           |
| `malware_roles`            | `tool_types`          | From `malware_roles[].value`                                            |
| `alt_names_details`        | `aliases`             | From `alt_names_details[].value`                                        |
| `creation_date`            | `created`             | UTC timestamp of object creation                                        |
| `origin`                   | `created_by_ref`      | UUID pointing to the Identity (e.g., Google Threat Intelligence)        |
| `id`                       | `external_references` | Link to the GTI page for this software toolkit                          |

#### Relationship mapping from first-level attributes

These are **direct attributes** of the GTI Software Toolkit object, but they are modeled as **separate entities + relationships** in OpenCTI because STIX represents them as distinct objects.

> ℹ️ These relationships are always produced when a Software Toolkit is ingested, **even as a sub-entity of another collection** (e.g., via Reports or Campaigns), because the data is part of the Software Toolkit's own definition.

| GTI Concept              | STIX Source Object | STIX Relationship  | STIX Target Object |
|--------------------------|--------------------|--------------------|--------------------|
| `targeted_industries`    | Tool               | `targets`          | Identity (Sector)  |
| `targeted_regions`       | Tool               | `targets`          | Location           |
| `source_regions`         | Tool               | `originates-from`  | Location           |

#### Relationship mapping from sub-entities (requires dedicated collection)

These relationships are **only produced when the Software Toolkits collection is enabled**, as they require fetching additional sub-entities via dedicated API calls.

| GTI Concept              | STIX Source Object | STIX Relationship | STIX Target Object |
|--------------------------|--------------------|-------------------|--------------------|
| `malware_families`       | Tool               | `related-to`      | Malware            |
| `attack_techniques`      | Tool               | `uses`            | Attack-Pattern     |

---

### Campaign (GTI: Campaign)

> 📖 GTI Campaign documentation: https://gtidocs.virustotal.com/reference/campaign-object

#### Attribute mapping

| GTI Campaign Field       | STIX Field            | Notes                                                                   |
|--------------------------|-----------------------|-------------------------------------------------------------------------|
| `name`                   | `name`                | The main display name                                                   |
| `description`            | `description`         | Full text description of the campaign                                   |
| `alt_names_details`      | `aliases`             | From `alt_names_details[].value`                                        |
| `first_seen_details`     | `first_seen`          | Earliest activity date from `first_seen_details[].value`                |
| `last_seen_details`      | `last_seen`           | Latest activity date from `last_seen_details[].value`                   |
| `motivations`            | `objective`           | All `motivations[].value` joined with ", "                              |
| `tags_details`           | `labels`              | From `tags_details[].value`                                             |
| `creation_date`          | `created`             | UTC timestamp of object creation                                        |
| `last_modification_date` | `modified`            | UTC timestamp of last modification                                      |
| `id`                     | `external_references` | Link to the GTI page for this campaign                                  |

#### Relationship mapping from first-level attributes

These are **direct attributes** of the GTI Campaign object, but they are modeled as **separate entities + relationships** in OpenCTI because STIX represents them as distinct objects.

> ℹ️ These relationships are always produced when a Campaign is ingested, **even as a sub-entity of another collection** (e.g., via Threat Actors or Malware), because the data is part of the Campaign's own definition.

| GTI Concept           | STIX Source Object | STIX Relationship  | STIX Target Object |
|-----------------------|--------------------|--------------------|--------------------|
| `targeted_industries` | Campaign           | `targets`          | Identity (Sector)  |
| `targeted_regions`    | Campaign           | `targets`          | Location           |
| `source_regions`      | Campaign           | `originates-from`  | Location           |

#### Relationship mapping from sub-entities (requires dedicated collection)

These relationships are **only produced when the Campaigns collection is enabled**, as they require fetching additional sub-entities via dedicated API calls.

| GTI Concept              | STIX Source Object | STIX Relationship   | STIX Target Object |
|--------------------------|--------------------|---------------------|--------------------|
| `threat_actors`          | Campaign           | `attributed-to`     | Intrusion-Set      |
| `malware_families`       | Campaign           | `uses`              | Malware            |
| `software_toolkits`      | Campaign           | `uses`              | Tool               |
| `attack_techniques`      | Campaign           | `uses`              | Attack-Pattern     |
| `vulnerabilities`        | Campaign           | `targets`           | Vulnerability      |

---

### Vulnerability (GTI: Vulnerability)

> 📖 GTI Vulnerability documentation: https://gtidocs.virustotal.com/reference/vulnerability-object

#### Attribute mapping

| GTI Vulnerability Field                 | STIX Field                           | Notes                                            |
|-----------------------------------------|--------------------------------------|--------------------------------------------------|
| `name`                                  | `name`                               | The CVE identifier (e.g., CVE-2024-1234)         |
| `description`                           | `description`                        | Full text description of the vulnerability       |
| `creation_date`                         | `created`                            | UTC timestamp of object creation                 |
| `last_modification_date`                | `modified`                           | UTC timestamp of last modification               |
| `cvss.cvssv3_x.base_score`              | `x_opencti_base_score`               | CVSS v3.x base score                             |
| `cvss.cvssv3_x.vector`                  | `x_opencti_cvss_vector_string`       | CVSS v3.x vector string (normalized to 3.1)      |
| `cvss.cvssv3_x.temporal_score`          | `x_opencti_cvss_temporal_score`      | CVSS v3.x temporal score                         |
| `cvss.cvssv2_0.base_score`              | `x_opencti_cvss_v2_base_score`       | CVSS v2.0 base score                             |
| `cvss.cvssv2_0.vector`                  | `x_opencti_cvss_v2_vector_string`    | CVSS v2.0 vector string                          |
| `cvss.cvssv2_0.temporal_score`          | `x_opencti_cvss_v2_temporal_score`   | CVSS v2.0 temporal score                         |
| `cvss.cvssv4_x.score`                   | `x_opencti_cvss_v4_base_score`       | CVSS v4.x score                                  |
| `cvss.cvssv4_x.vector`                  | `x_opencti_cvss_v4_vector_string`    | CVSS v4.x vector string                          |
| `cvss.cvssv4_x.threat.exploit_maturity` | `x_opencti_cvss_v4_exploit_maturity` | CVSS v4.x exploit maturity                       |
| `epss.score`                            | `x_opencti_epss_score`               | EPSS probability of exploitation in next 30 days |
| `epss.percentile`                       | `x_opencti_epss_percentile`          | EPSS percentile                                  |
| `cwe.id`                                | `x_opencti_cwe`                      | CWE identifier                                   |
| `tags_details`                          | `labels`                             | From `tags_details[].value`                      |
| `sources`                               | `external_references`                | Source URLs and GTI VirusTotal link              |

#### First-level entities produced (composite mapping)

These entities are **always produced** when a Vulnerability is ingested, as they are part of the composite vulnerability conversion.

| GTI Concept              | STIX Source Object | STIX Relationship | STIX Target Object | Notes                                                    |
|--------------------------|--------------------|-------------------|--------------------|----------------------------------------------------------|
| `cpes`                   | Software           | `has`             | Vulnerability      | Software objects created from CPE data                   |
| `workarounds`            | Note               | —                 | —                  | Notes with label "workaround", linked via `object_refs`  |
| `executive_summary`      | Note               | —                 | —                  | Note with abstract "{CVE} - Executive Summary"           |
| `analysis`               | Note               | —                 | —                  | Note with abstract "{CVE} - Analysis"                    |

#### Relationship mapping from sub-entities (requires dedicated collection)

These relationships are **only produced when the Vulnerabilities collection is enabled**, as they require fetching additional sub-entities via dedicated API calls.

| GTI Concept              | STIX Source Object | STIX Relationship | STIX Target Object |
|--------------------------|--------------------|-------------------|--------------------|
| `threat_actors`          | Intrusion-Set      | `targets`         | Vulnerability      |
| `malware_families`       | Malware            | `targets`         | Vulnerability      |
| `attack_techniques`      | Vulnerability      | `related-to`      | Attack-Pattern     |

---

### Report (GTI: Report)

> 📖 GTI Report documentation: https://gtidocs.virustotal.com/reference/report-object

#### Attribute mapping

| GTI Report Field         | STIX Field              | Notes                                                         |
|--------------------------|-------------------------|---------------------------------------------------------------|
| `name`                   | `name`                  | Title of the report                                           |
| `autogenerated_summary`  | `description`           | ML-generated summary used as STIX description                 |
| `content`                | `x_opencti_content`     | Full report content, converted from Markdown to HTML          |
| `report_type`            | `report_types`          | Type of report (e.g., News, Actor Profile, OSINT)             |
| `creation_date`          | `created` / `published` | UTC timestamp of report creation, also used as published date |
| `last_modification_date` | `modified`              | UTC timestamp of last modification                            |
| `intended_effects`       | `labels`                | Intended effects of the threat                                |
| `threat_scape`           | `labels`                | Topic areas covered by the report                             |
| `motivations`            | `labels`                | From `motivations[].value`                                    |
| `link`                   | `external_references`   | URL to the original source report                             |
| `id`                     | `external_references`   | Link to the GTI VirusTotal page for this report               |
| `author`                 | `created_by_ref`        | Report author mapped to an Identity (Organization)            |

#### First-level entities produced (composite mapping)

These entities are **always produced** when a Report is ingested, as they are part of the composite report conversion.

| GTI Concept                  | STIX Object Produced    | Notes                                                             |
|------------------------------|-------------------------|-------------------------------------------------------------------|
| `targeted_regions_hierarchy` | Location                | Countries from targeted regions, added to Report's `object_refs`  |
| `targeted_industries_tree`   | Identity (Sector)       | Sectors from targeted industries, added to Report's `object_refs` |
| `author`                     | Identity (Organization) | Author identity, used as `created_by_ref`                         |
| `analyst_comment`            | Note                    | Analyst comment attached to the report via `object_refs`          |

#### Relationship mapping from sub-entities (requires dedicated collection)

These relationships are **only produced when the Reports collection is enabled**, as they require fetching additional sub-entities via dedicated API calls. All sub-entities are added to the Report's `object_refs`.

| GTI Concept         | STIX Source Object | STIX Relationship | STIX Target Object |
|---------------------|--------------------|-------------------|--------------------|
| `malware_families`  | Malware            | `object_refs`     | Report             |
| `campaigns`         | Campaign           | `object_refs`     | Report             |
| `software_toolkits` | Tool               | `object_refs`     | Report             |
| `vulnerabilities`   | Vulnerability      | `object_refs`     | Report             |
| `attack_techniques` | Attack-Pattern     | `object_refs`     | Report             |
| `domains`           | Domain-Name        | `object_refs`     | Report             |
| `files`             | File               | `object_refs`     | Report             |
| `urls`              | Url                | `object_refs`     | Report             |
| `ip_addresses`      | IPv4-Addr          | `object_refs`     | Report             |

---

### Indicator

#### Attribute mapping

For each IOC type, an **Indicator** is created with `create_observables=True`, which also generates the associated STIX Observable automatically.

| GTI IOC type | STIX Pattern                                                                                | Main Observable Type |
|--------------|---------------------------------------------------------------------------------------------|----------------------|
| `url`        | `[url:value = '...']`                                                                       | URL                  |
| `ip`         | `[ipv4-addr:value = '...']` or `[ipv6-addr:value = '...']`                                  | IPv4-Addr/IPv6-Addr  |
| `file`       | `[file:hashes.'SHA-256' = '...' OR file:hashes.MD5 = '...' OR file:hashes.'SHA-1' = '...']` | File                 |
| `domain`     | `[domain-name:value = '...']`                                                               | Domain-Name          |

**Common Indicator attributes:**

| GTI IOC Field                                  | STIX Field            | Notes                                           |
|------------------------------------------------|-----------------------|-------------------------------------------------|
| `attributes.creation_date`                     | `valid_from`          | UTC timestamp when the IOC was first seen       |
| `attributes.gti_assessment.threat_score.value` | `x_opencti_score`     | GTI threat score                                |
| `id`                                           | `external_references` | Link to the GTI page for this IOC               |

#### Relationship mapping

Relationships are extracted directly from the IOC delta feed data (no additional API calls needed). All relationships use the `indicates` type.

| GTI Concept              | STIX Source Object | STIX Relationship | STIX Target Object |
|--------------------------|--------------------|-------------------|--------------------|
| `malware_families`       | Indicator          | `indicates`       | Malware            |
| `threat_actors`          | Indicator          | `indicates`       | Intrusion-Set      |
| `software_toolkits`      | Indicator          | `indicates`       | Tool               |
| `attack_techniques`      | Indicator          | `indicates`       | Attack-Pattern     |

---

## **IMPORTANT API QUOTA LIMITATIONS**

> **CRITICAL:** Retrieving large volumes of historical threat intelligence data may trigger Google TI API quota limitations, which will **temporarily pause** the connector's data retrieval and ingestion processes.

The connector's ingestion state management system is specifically designed to handle these quota limitations gracefully:

- **State Persistence:** The connector tracks the `update_date` of the last successfully ingested entity, ensuring no data loss occurs during quota-induced pauses.
- **Automatic Resume:** When API quota limits reset and the service becomes available again, the connector will automatically resume data retrieval from exactly where it stopped.
- **Seamless Recovery:** No manual intervention or data re-synchronization is required, the connector will continue processing from the last recorded state.

## **IMPORTANT DATA LIMITATIONS**

> **IMPORTANT NOTE on Threat Actor/Malware Aliases:** The Google Threat Intelligence (GTI) platform aggregates data from both **curated** and **open-source** reports.
Because the open-source data often uses **overlapping or conflicting aliases** for the same threat actors and malware, the **OpenCTI connector does not currently fetch these aliases from GTI.**

- This means that the connector will not create relationships between threat actors and malware based on aliases, but instead will create new entries for each alias.
- This limitation affects the completeness of threat actor and malware entity relationships and may impact threat correlation capabilities.  
  Please be aware of this constraint when using the imported data for analysis and reporting.

> **NOTE:** The connector now provides configuration options `GTI_ENABLE_MALWARE_ALIASES` and `GTI_ENABLE_THREAT_ACTOR_ALIASES` (both default to `false`) that allow you to override this behavior and enable alias importing. However, **we strongly recommend keeping these disabled by default** as mentioned above. Enabling aliases is at your own discretion and responsibility.


---

## Installation

### Requirements
- OpenCTI Platform version **6.5.1** or higher

- OpenCTI Platform version **6.7.7** or higher
- Docker & Docker Compose (for containerized deployment)
- Valid GTI API credentials (token)

---

### Quick start

Here’s a high-level overview to get the connector up and running:

1. **Set environment variables**:
    - inside `docker-compose.yml`
2. **Pull and run the connector** using Docker:
```bash
        docker compose up -d
```

---

### Configurations Variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

### Development

#### Contributing

Please refer to [CONTRIBUTING.md](CONTRIBUTING.md).

#### Running the Connector Locally

The connector is designed to be run in a Docker container. However, if you want to run it locally for development purposes, you can do so by following these steps:

1/ Clone the connector's repository:
```bash
    git clone <repository-url>
```

2/ Navigate to the connector directory
```bash
    cd external-import/google-ti-feeds
```

3/ Ensure you are using a Python 3.12 version

4/ Install the required dependencies:
```bash
pip install -e .[dev,test]
```

5a/ Set the required variables:
In your shell:
```bash
        export OPENCTI_URL=<your_opencti_url>
        ...
```
OR sourcing a `.env` file:
```bash
        source .env
```
OR creating a "config.yml" file at the root of the project:
```yaml
       opencti:
           url: <your_opencti_url>
       ...
```

6/ Run the connector:
```bash
       GoogleTIFeeds
```
or ignore 5b and run it with the environment variable:
```bash
      GoogleTIFeeds
```
or by launching the main.py:
```bash
      python connector/__main__.py
```
or by launching the module:
```bash
      python -m connector
```

#### Commit

Note: Your commits must be signed using a GPG key. Otherwise, your Pull Request will be rejected.

#### Linting and formatting

Added to the connectors linting and formatting rules, this connector is developed and checked using ruff and mypy to ensure the code is type-checked and linted.

The dedicated configurations are set in the `pyproject.toml` file.
You can run the following commands to check the code:

```bash
   python -m isort .
   python -m black . --check
   python -m ruff check .
   python -m mypy .
   python -m pip_audit .
```

#### Testing

To run the tests, you can use the following command:
```bash
    python -m pytest -svv
```
