# OpenCTI PolySwarm Feed Connector

This external-import connector imports [PolySwarm](https://polyswarm.io/)'s curated malware file-hash feed into OpenCTI. It runs on a schedule, pulls new data from PolySwarm, and creates STIX 2.1 objects in your platform.

## Table of Contents

- [Introduction](#introduction)
- [Data Handling: What Leaves Your Environment](#data-handling-what-leaves-your-environment)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Behavior](#behavior)
  - [Feed collections](#feed-collections)
  - [Objects created per sample](#objects-created-per-sample)
  - [Live hunting hits](#live-hunting-hits)
  - [Indicator lifetime](#indicator-lifetime)
  - [State and resuming](#state-and-resuming)
  - [Volume](#volume)
- [Troubleshooting](#troubleshooting)

## Introduction

The connector reads PolySwarm's STIX 2.1 feed over TAXII and, optionally, the hits from your own PolySwarm live hunts.

What it imports:

- **The 14-day trust group feed** (the `trustgroup` collection), on by default.
- **The ransomware and freemium collections**, which you can add with `POLYSWARM_FEED_COLLECTIONS`.
- **Live hunting hits** from the live hunts in your own PolySwarm account. This is off by default (`POLYSWARM_HUNTING_ENABLED=false`).

All indicators are file hashes (MD5, SHA-1, SHA-256). The connector does not create network indicators (domains, IP addresses, URLs).

## Data Handling: What Leaves Your Environment

The connector only pulls data.

- **Nothing from OpenCTI is sent to PolySwarm.** No observables, entities, reports, markings or users are uploaded, and the connector never submits files for scanning.
- **Where requests go.** Outbound calls go to the PolySwarm API URL only (`POLYSWARM_API_URL`, default `https://api.polyswarm.network`).
- **What is sent with each request.** Your PolySwarm account number and API key, for authentication, plus the paging and time-range parameters needed to ask for new data.

## Installation

### Requirements

- OpenCTI Platform >= 6.8.12
- A PolySwarm account with access to the feed collections you want to import
- Your PolySwarm account number and API key
- Network access from the connector to the PolySwarm API URL

## Configuration variables

Configuration can be given in `config.yml` (copy `config.yml.sample`) or as environment variables. Environment variables take precedence.

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                  |
|---------------|------------|-----------------------------|-----------|----------------------------------------------|
| OpenCTI URL   | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.             |
| OpenCTI Token | `token`    | `OPENCTI_TOKEN`             | Yes       | The token of the user the connector runs as. |

### Base connector environment variables

| Parameter       | config.yml        | Docker environment variable | Default                                                                    | Mandatory | Description                                |
|-----------------|-------------------|-----------------------------|----------------------------------------------------------------------------|-----------|--------------------------------------------|
| Connector ID    | `id`              | `CONNECTOR_ID`              |                                                                            | Yes       | A unique `UUIDv4` for this connector.      |
| Connector Name  | `name`            | `CONNECTOR_NAME`            | `PolySwarm Feed`                                                           | No        | Name shown in OpenCTI.                     |
| Connector Scope | `scope`           | `CONNECTOR_SCOPE`           | `Malware,Indicator,StixFile,Malware-Analysis,Attack-Pattern,Note` | No        | The object types the connector imports.    |
| Log Level       | `log_level`       | `CONNECTOR_LOG_LEVEL`       | `info`                                                                     | No        | `debug`, `info`, `warn` or `error`.        |
| Duration Period | `duration_period` | `CONNECTOR_DURATION_PERIOD` | `PT1H`                                                                     | No        | Time between two runs, in ISO-8601 format. |

### PolySwarm environment variables

| Parameter                    | config.yml                     | Docker environment variable              | Default                         | Mandatory | Description                                                                                                                         |
|------------------------------|--------------------------------|------------------------------------------|---------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------------------------|
| API key                      | `api_key`                      | `POLYSWARM_API_KEY`                      |                                 | Yes       | Your PolySwarm API key.                                                                                                             |
| Account number               | `account_number`               | `POLYSWARM_ACCOUNT_NUMBER`               |                                 | Yes       | Your PolySwarm account number. Used as the user name for the feed (TAXII) login.                                                    |
| API URL                      | `api_url`                      | `POLYSWARM_API_URL`                      | `https://api.polyswarm.network` | No        | Base URL of the PolySwarm API.                                                                                                      |
| Feed collections             | `feed_collections`             | `POLYSWARM_FEED_COLLECTIONS`             | `trustgroup`                    | No        | Comma-separated list of collections to import. Allowed values: `trustgroup`, `ransomware`, `freemium`. Unknown values are rejected. |
| Feed backfill days           | `feed_backfill_days`           | `POLYSWARM_FEED_BACKFILL_DAYS`           | `14`                            | No        | How many days of feed history to import on the first run only.                                                                      |
| Feed indicator valid days    | `feed_indicator_valid_days`    | `POLYSWARM_FEED_INDICATOR_VALID_DAYS`    | `90`                            | No        | Days from import time until feed indicators expire (`valid_until`).                                                                 |
| Hunting enabled             | `hunting_enabled`              | `POLYSWARM_HUNTING_ENABLED`              | `false`                         | No        | Import hits from your own PolySwarm live hunts.                                                                                     |
| Hunting backfill hours       | `hunting_backfill_hours`       | `POLYSWARM_HUNTING_BACKFILL_HOURS`       | `24`                            | No        | How many hours of hunting hits to import on the first run only.                                                                     |
| Hunting indicator valid days | `hunting_indicator_valid_days` | `POLYSWARM_HUNTING_INDICATOR_VALID_DAYS` | `30`                            | No        | Days from import time until hunting indicators expire.                                                                              |
| TLP level                    | `tlp_level`                    | `POLYSWARM_TLP_LEVEL`                    | `clear`                         | No        | TLP marking applied to every object the connector sends. One of `clear`, `white`, `green`, `amber`, `amber+strict`, `red`.          |
| Max objects per run          | `max_objects_per_run`          | `POLYSWARM_MAX_OBJECTS_PER_RUN`          | `20000`                         | No        | Stop paging once this many objects have been collected in a run. The next run resumes where this one stopped.                       |

## Deployment

### Docker Deployment

Use the published image `opencti/connector-polyswarm-feed:rolling`, or build your own from the provided `Dockerfile`:

```shell
docker build . -t opencti/connector-polyswarm-feed:rolling
```

Edit `docker-compose.yml` (the secrets are `ChangeMe` placeholders), then start it:

```shell
docker compose up -d
```

### Manual Deployment

1. Create a `config.yml` next to `config.yml.sample` and fill in the values.
2. Install the dependencies:

```shell
pip3 install -r src/requirements.txt
```

3. Start the connector from the `src` directory:

```shell
python3 main.py
```

## Behavior

### Feed collections

PolySwarm exposes three feed collections:

- `trustgroup`: the 14-day feed. This is the only collection enabled by default.
- `ransomware`
- `freemium`: the collection that carries MITRE ATT&CK patterns.

Each run, the connector asks each enabled collection for objects added since the last run. On the first run it goes back `POLYSWARM_FEED_BACKFILL_DAYS` days.

### Objects created per sample

The feed delivers one STIX bundle per sample. For each sample, OpenCTI receives:

- Malware objects for the families named in the feed
- The File, with its hashes
- Indicators for the MD5, SHA-1 and SHA-256 hashes
- One malware-analysis object per detection engine, holding that engine's result
- Relationships between these objects
- MITRE ATT&CK attack patterns, when the feed provides them (freemium collection)

Every object carries the PolySwarm author identity and the TLP marking from `POLYSWARM_TLP_LEVEL`.

### Live hunting hits

When `POLYSWARM_HUNTING_ENABLED=true`, the connector also reads hits from the live hunts in your own PolySwarm account. For each hit it creates:

- A File with its hashes
- An indicator on the SHA-256
- A note with the rule name, matched strings and detection counts
- Labels of the form `polyswarm-hunt:<rule_name>`
- A `polyswarm-family:<name>` label on the file, the indicator and the note, whenever the hit reports a family name
- A malware family object and an `indicates` relationship, only when the reported name looks like a real malware family

Many hits report an antivirus style label in the family field (for example `Trojan.Packed2` or `PUA.Generic`) rather than a family name. The connector creates a malware object only for names that pass a conservative check: names with dots, slashes, colons or brackets, generic words (such as generic, agent, packed, heur, suspicious, malware, trojan, pua, adware, riskware, phishing, unknown, variant, gen), names made only of a type prefix, random-looking strings and very short names are not treated as families. The name is never lost: it stays in the note and in the `polyswarm-family:<name>` label. The check is a heuristic and errs on the side of not creating a malware object; PolySwarm's own list of known family names was not used because it does not contain several real family names seen in hits.

A hit that was already imported is not imported again. The connector remembers a bounded number of recent hit identifiers in its state.

### Indicator lifetime

Indicators are given a `valid_until` of the import time plus `POLYSWARM_FEED_INDICATOR_VALID_DAYS` (feed) or `POLYSWARM_HUNTING_INDICATOR_VALID_DAYS` (hunting). `valid_until` is never earlier than `valid_from`, so an indicator is not expired when it is created.

### State and resuming

The connector stores its progress in the OpenCTI connector state, per collection and for hunting. The backfill settings apply to the first run only. When a run reaches `POLYSWARM_MAX_OBJECTS_PER_RUN`, it stops paging, and the next run resumes from the recorded position.

### Volume

Because each sample brings one malware-analysis object per engine, a sample is typically dozens of objects (roughly 12 to 17 analysis objects and 16 to 27 relationships, plus the file, malware and indicators). Large backfills therefore produce a lot of data. To keep it manageable:

- Leave `POLYSWARM_FEED_COLLECTIONS` at `trustgroup` and add the others only when you need them.
- Lower `POLYSWARM_FEED_BACKFILL_DAYS` for the first run.
- Lower `POLYSWARM_MAX_OBJECTS_PER_RUN` so each run does a smaller batch.
- Shorten `POLYSWARM_FEED_INDICATOR_VALID_DAYS` if you want hashes to age out sooner.

## Troubleshooting

- **401 or 403 errors.** The account number or API key is wrong, or your PolySwarm plan does not include access to that feed collection. Check both values, and check which collections your plan includes.
- **Runs that import nothing.** This is normal between feed updates. The connector logs that there was nothing new and tries again at the next period.
- **Unknown collection error at startup.** `POLYSWARM_FEED_COLLECTIONS` only accepts `trustgroup`, `ransomware` and `freemium`.
- **A run stops early.** It reached `POLYSWARM_MAX_OBJECTS_PER_RUN`. The next run continues from where it stopped.
- **More detail.** Set `CONNECTOR_LOG_LEVEL=debug`.
