# OpenCTI Obstracts Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner | -    | -       |

## Table of Contents

- [Introduction](#introduction)
  - [Screenshots](#screenshots)
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
  - [Custom STIX Objects and OpenCTI Compatibility](#custom-stix-objects-and-opencti-compatibility)
  - [Processing Details](#processing-details)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

[Obstracts](https://www.obstracts.com/) is a web application that transforms posts from leading security blogs into structured, actionable threat intelligence.

The OpenCTI Obstracts Connector synchronizes intelligence from the blogs you are subscribed to in Obstracts into OpenCTI.

> **Note**: This connector only works with Obstracts Web ([https://www.obstracts.com](https://www.obstracts.com)). It does not support self-hosted Obstracts installations at this time.

### Screenshots

![Obstracts Feed subscriptions](media/obstracts-subscriptions.png)

![Obstracts STIX extractions](media/obstracts-extraction-graph.png)

![Obstracts STIX extractions](media/obstracts-opencti-reports.png)

---

## Installation

### Requirements

- OpenCTI >= 6.5.10
- Obstracts team subscribed to a plan with API access enabled
- Obstracts API Key

### Generating an API Key

[![Creating an Obstracts API Key to Use with the Obstracts OpenCTI Connector](https://img.youtube.com/vi/IeP9blaF2U4/0.jpg)](https://www.youtube.com/watch?v=IeP9blaF2U4)

[This video demonstrates the steps outlined below](https://www.youtube.com/watch?v=IeP9blaF2U4).

1. Log in to your Obstracts account
2. Navigate to "Account Settings"
3. Locate the API section and select "Create Token"
4. Select the team you want to use and generate the key
  * If you don't see a team listed, you do not belong to a team on a plan with API access. Please upgrade the teams account to continue.
5. Copy the API Key for the OpenCTI Connector configuration

---

## Configuration

### Configuration Variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

A few notes on the Obstracts-specific settings:

- **API key** (`OBSTRACTS_API_KEY`): see [Generating an API Key](#generating-an-api-key) above.
- **Feed IDs** (`OBSTRACTS_FEED_IDS`): it is recommended to leave this setting empty. When left blank, the connector downloads post content for all feeds your team is subscribed to in Obstracts. If you only want to ingest data from specific feeds, provide a comma-separated list of feed IDs instead (for example: `a0850464-c04e-42cc-9b4f-6e8094ad90ea,87295120-5ac0-4e91-907d-32f50cd50147`).
- **Days to backfill** (`OBSTRACTS_DAYS_TO_BACKFILL`): number of days of historical data to import, based on the `created` value of the report. It applies to every feed that has not been imported yet, including feeds subscribed to later in Obstracts. The recommended maximum is `365`.
- **Duration period** (`CONNECTOR_DURATION_PERIOD`): the connector polls Obstracts for new posts in your subscriptions at this interval. The recommended value is `PT1H`. It replaces the deprecated `OBSTRACTS_INTERVAL_HOURS`, which is still read (in hours) when `CONNECTOR_DURATION_PERIOD` is not set.

---

## Deployment

### Docker Deployment

Use the following `docker-compose.yml`:

```yaml
services:
  connector-obstracts:
    image: opencti/connector-dogesec-obstracts:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_OBSTRACTS_ID}
      - CONNECTOR_NAME=Obstracts
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT12H
      - OBSTRACTS_BASE_URL=https://api.obstracts.com/
      - OBSTRACTS_API_KEY=${OBSTRACTS_API_KEY}
      - OBSTRACTS_FEED_IDS=
      - OBSTRACTS_DAYS_TO_BACKFILL=90
    restart: always
    depends_on:
      - opencti
```

### Manual Deployment

1. Clone the repository and navigate to the connector directory
2. Install dependencies: `pip install -r requirements.txt`
3. Configure `config.yml`
4. Run: `python main.py`

---

## Behavior

### Data Flow

```mermaid
graph LR
    %% Box 1: Obstracts Web
    subgraph Obstracts_Web["Obstracts Web"]
        Blogs[Security Blogs]
        NLP[NLP Extractions]
        Blogs --> NLP
    end

    %% Box 2: Obstracts API
    subgraph Obstracts_API["Obstracts API"]
        API[API]
        Bundle[STIX Bundle]
        API --> Bundle
    end
    
    %% Box 3: OpenCTI
    subgraph OpenCTI["OpenCTI"]
        Connector[Connector]
        STIX[STIX Objects]

        Connector --> STIX
        STIX --> report[Report]
        STIX --> attack-pattern[Attack Pattern]
        STIX --> campaign[Campaign]
        STIX --> course-of-action[Course of Action]
        STIX --> identity[Identity]
        STIX --> indicator[Indicator]
        STIX --> infrastructure[Infrastructure]
        STIX --> intrusion-set[Intrusion Set]
        STIX --> location[Location]
        STIX --> malware[Malware]
        STIX --> threat-actor[Threat Actor]
        STIX --> tool[Tool]
        STIX --> vulnerability[Vulnerability]
        STIX --> x-mitre-tactic[ATT&CK Tactic]
        STIX --> x-mitre-data-source[ATT&CK Data Source]
        STIX --> x-mitre-data-component[ATT&CK Data Component]

        indicator --> autonomous-system[Autonomous System]
        indicator --> bank-account[Bank Account]
        indicator --> cryptocurrency-wallet[Cryptocurrency Wallet]
        indicator --> directory[Directory]
        indicator --> domain-name[Domain Name]
        indicator --> email-addr[Email Address]
        indicator --> file[File]
        indicator --> ipv4-addr[IPv4 Address]
        indicator --> ipv6-addr[IPv6 Address]
        indicator --> network-traffic[Network Traffic]
        indicator --> mac-addr[MAC Address]
        indicator --> payment-card[Payment Card]
        indicator --> phone-number[Phone Number]
        indicator --> software[Software]
        indicator --> url[URL]
        indicator --> user-agent[User Agent]
        indicator --> windows-registry-key[Windows Registry Key]
    end

    %% Cross-section flow
    NLP --> API
    Bundle --> Connector

```

### Entity Mapping

| Obstracts Data | OpenCTI Entity | Notes |
|----------------|----------------|-------|
| Blog Post | Report | Original blog post as report |
| Extracted Relationships | Relationships | Obstracts uses NLP to define descriptive relationships between extracted objects |
| Extracted Attack Patterns | Attack Pattern | Extracted Attack Patterns, includes MITRE ATT&CK Techniques |
| Extracted Campaigns | Campaign | Extracted Campaigns, includes MITRE ATT&CK Campaigns |
| Extracted Course of Actions | Course of Action | Extracted Course of Actions, includes MITRE ATT&CK Mitigations |
| Extracted Identities | Identity | Extracted Identities. Also includes Identities created for the Feed (blog) |
| Extracted Infrastructure | Infrastructure | Extracted Infrastructure |
| Extracted Intrusion Sets | Intrusion Set | Extracted Intrusion Sets, includes MITRE ATT&CK Groups |
| Extracted Locations | Location | Extracted Locations |
| Extracted Malwares | Malware | Extracted Malware families, includes MITRE ATT&CK Software |
| Extracted Actors | Threat Actor | Named threat actors |
| Extracted Tools | Tool | Extracted Tools, includes MITRE ATT&CK Software |
| Extracted Vulnerabilities | Vulnerability | Named vulnerabilities |
| Extracted ATT&CK Tactics | x-mitre-tactic | ATT&CK Tactics |
| Extracted ATT&CK Data Sources | x-mitre-data-source | ATT&CK Data Sources |
| Extracted ATT&CK Data Components | x-mitre-date-component | ATT&CK Data Components |
| Extracted IOCs | Indicator/Observable | For each IOC extraction, an Indicator will also be created. The following Observables (SCOs) are supported; autonomous-system, bank-account, cryptocurrency-wallet, directory, domain-name, email-addr, file, ipv4-addr, ipv6-addr, network-traffic, mac-addr, payment-card, phone-number, software, url, user-agent, windows-registry-key |

### Custom STIX Objects and OpenCTI Compatibility

Obstracts includes several custom STIX object types that are not currently supported by OpenCTI. These custom objects are:

* `attack-action` (SDO)
* `attack-flow` (SDO)
* `exploit` (SDO)
* `weaknesses` (SDO)
* `x-mitre-asset` (SDO MITRE ATT&CK)
* `x-mitre-analytic` (SDO MITRE ATT&CK)
* `x-mitre-detection-strategy` (SDO MITRE ATT&CK)
* `cryptocurrency-transaction` (SCO)
* `data-source` (SCO)

When a STIX Bundle associated with a Post contains any of these object types, OpenCTI will report import errors for those specific objects. This behavior is expected.

All other supported STIX objects in the bundle will import successfully and remain usable in OpenCTI.

### Processing Details

1. **Feed Selection**:
   - Specify feed IDs for selective import
   - Leave blank to import all subscribed feeds
   - New feed subscriptions are automatically included

2. **Backfill Logic**:
   - On first run or new feed subscription, backfills historical data
   - Recommended maximum backfill period: 365 days
   - Configurable via `OBSTRACTS_DAYS_TO_BACKFILL`

3. **Incremental Updates**:
   - Polls at the interval set by `CONNECTOR_DURATION_PERIOD` (default: 1 hour)
   - Only fetches new/updated intelligence since last run

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug`.

### Verification

Navigate to `Data` → `Ingestion` → `Connectors` → `Obstracts` to verify the connector is working.

---

## Additional Information

### About Obstracts

- **Website**: [obstracts.com](https://www.obstracts.com/)
- **Sign up**: Free tier available
- **Provider**: [dogesec](https://dogesec.com/)

### Support

- **OpenCTI Support**: For general connector installation help
- **dogesec Community Forum**: [community.dogesec.com](https://community.dogesec.com/) (recommended)
- **dogesec Support Portal**: [support.dogesec.com](https://support.dogesec.com/) (requires plan with email support)

### Use Cases

| Use Case | Description |
|----------|-------------|
| Blog Intelligence | Automate extraction of IOCs from security blogs |
| Threat Research | Track threat actor/malware mentions |
| TTP Tracking | Identify ATT&CK techniques discussed in blogs |
| Early Warning | Get indicators before formal advisories |
