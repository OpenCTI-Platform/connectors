# PGL Yoyo Connector

## Table of Contents

- [PGL Yoyo Connector](#pgl-yoyo-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
      - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Additional information](#additional-information)

## Introduction

This connector imports the Peter Lowe (PGL / yoyo.org) blocklists into OpenCTI and transforms entries into STIX 2.1 Indicators for IPv4 addresses and domain names. Lines are sanitized (comments/whitespace removed) and validated before emission to keep data clean and consistent.

## Installation

### Requirements

- OpenCTI Platform >= 6...
- Matching `pycti` version to your OpenCTI deployment (see Docker notes below)

### Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

#### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter       | config.yml | Docker environment variable   | Default         | Mandatory | Description                                                                               |
|-----------------|------------|-------------------------------|-----------------|-----------|-------------------------------------------------------------------------------------------|
| Connector ID    | id         | `CONNECTOR_ID`                | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                 |
| Connector Type  | type       | `CONNECTOR_TYPE`              | EXTERNAL_IMPORT | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                             |
| Connector Name  | name       | `CONNECTOR_NAME`              |                 | Yes       | Name of the connector.                                                                    |
| Connector Scope | scope      | `CONNECTOR_SCOPE`             |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.  |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`         | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.    |
| Confidence      | confidence_level | `CONNECTOR_CONFIDENCE_LEVEL` | 50          | No        | Confidence applied to created entities.                                                   |
| Update Existing | update_existing_data | `CONNECTOR_UPDATE_EXISTING` | true   | No        | Update existing objects instead of creating duplicates.                                   |
| Interval (s)    | interval   | `CONNECTOR_DURATION_PERIOD`   | 43200           | No        | Run interval in seconds (12h by default).                                                 |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter              | config.yml               | Docker environment variable | Default                                                       | Mandatory | Description                                                                                      |
|------------------------|--------------------------|-----------------------------|---------------------------------------------------------------|-----------|--------------------------------------------------------------------------------------------------|
| Identity ID            | `pgl.identity_id`        | `PGL_IDENTITY_ID`           | —                                                             | No        | Optional fixed STIX identity ID to use. If not set, a stable UUIDv5 is derived from the name.    |
| Identity Name          | `pgl.identity_name`      | `PGL_IDENTITY_NAME`         | Peter Lowe (PGL Blocklist)                                    | No        | Name used for the STIX `identity` set as `created_by_ref`.                                       |
| Identity Class         | `pgl.identity_class`     | `PGL_IDENTITY_CLASS`        | organization                                                  | No        | STIX identity class.                                                                             |
| Identity Description   | `pgl.identity_description` | `PGL_IDENTITY_DESCRIPTION` | Curated ad/tracking blocklist maintained by Peter G. Lowe.    | No        | Description shown on the producer identity.                                                      |
| Report Per Run         | `pgl.report_per_run`     | `PGL_REPORT_PER_RUN`        | true                                                          | No        | Whether to create a report entity per run (if supported in your deployment).                     |
| Bundle Mode            | `pgl.bundle_mode`        | `PGL_BUNDLE_MODE`           | true                                                          | No        | Emit a single STIX bundle per run.                                                               |
| Feeds                  | `pgl.feeds`              | —                           | —                                                             | Yes       | List of feeds to import (name, url, type, labels). Configure in `config.yml` (see example below). |

> Note: PGL configuration keys can also be overridden by environment variables using their uppercase form as shown above.

## Usage

After installation, the connector runs on a schedule defined by `interval`. To trigger an immediate refresh:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI UI, select this connector and click the refresh button to reset its state and force a new ingestion.

## Behavior

- Parses plain‑text feeds defined in `pgl.feeds` and emits STIX 2.1 Indicators for IPv4 addresses and domain names.
- Uses canonical STIX patterns:
  - IPv4: `[ipv4-addr:value = 'x.x.x.x']`
  - Domain: `[domain-name:value = 'example.com']`
- Each Indicator includes `created_by_ref` (the connector identity) and optional `labels` from the feed configuration.
- Input sanitization: inline comments after `#` are removed; leading/trailing whitespace is stripped; only the first token per line is considered.
- Validation: IPv4 via `ipaddress.IPv4Address`; domain names via IDNA conversion and per‑label checks (length, allowed characters, no leading/trailing hyphens, multiple labels).
- Caching: no persistent cache is used by default. Feeds are fetched directly. Conditional requests are supported internally but not persisted between runs.
- Operations: bundles are sent with `update=True`. If nothing changed, OpenCTI may show 0 operations. To attribute operations to a specific work item, pass the `work_id` from `initiate_work()` when sending the bundle (depends on your deployment helper usage).

## Additional information

Feeds structure example (configure in `config.yml`):

```yaml
pgl:
  feeds:
    - name: "PGL - Trackers (Hostnames)"
      url: "https://pgl.yoyo.org/as/serverlist.php?hostformat=plain;showtrackers=on;nomunge=on"
      type: "Domain-Name"   # or "IPv4-Addr"
      labels: ["OSINT", "Blocklist", "AdTech", "Tracker"]
```

Connector ID (required): OpenCTI requires a unique `CONNECTOR_ID` (UUID v4).

PowerShell:

```powershell
[guid]::NewGuid().ToString()
```

Python:

```python
import uuid
print(uuid.uuid4())
```

Set the value in your environment/compose under `CONNECTOR_ID`:

```yaml
environment:
  CONNECTOR_ID: "<your-uuid-here>"
```
