# OpenCTI Stixify Connector

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
  - [Finding Dossier IDs](#finding-dossier-ids)
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

[Stixify](https://www.stixify.com/) is a web application that transforms reports and documents into structured, actionable threat intelligence.

The OpenCTI Stixify Connector synchronizes intelligence from Stixify Dossiers into OpenCTI, enabling automated ingestion of structured STIX data extracted from reports.

> **Note**: This connector only works with Stixify Web ([https://www.stixify.com](https://www.stixify.com)). It does not support self-hosted Stixify installations at this time.

### Screenshots

![Stixify STIX extractions](media/stixify-graph.png)

![Stixify reports](media/stixify-reports.png)

![Stixify dossiers](media/stixify-dossiers.png)

---

## Installation

### Requirements

- OpenCTI >= 6.5.10
- Stixify team subscribed to a plan with API access enabled
- Stixify API Key

### Generating an API Key

[![Creating a Stixify API Key to Use with the Stixify OpenCTI Connector](https://img.youtube.com/vi/rpSMyLzInJw/0.jpg)](https://www.youtube.com/watch?v=rpSMyLzInJw)

[This video demonstrates the steps outlined below](https://www.youtube.com/watch?v=rpSMyLzInJw).

1. Log in to your Stixify account
2. Navigate to "Account Settings"
3. Locate the API section and select "Create Token"
4. Select the team you want to use and generate the key
4. Select the team you want to use and generate the key
  * If you don't see a team listed, you do not belong to a team on a plan with API access. Please upgrade the teams account to continue.
5. Copy the key for configuration

---

## Configuration

### Configuration Variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

### Finding Dossier IDs

The connector imports the Reports (and the objects extracted from them) of the Dossiers listed in `STIXIFY_DOSSIER_IDS`, as comma-separated IDs, for example `f0895eb3-7d90-4b45-8664-a7e157ba880f,b63c638e-43e6-43d4-bfac-5b71c264b132`. Set at least one Dossier ID: the connector stops at startup when none is set.

You do not need to own a Dossier to import it, but it must be visible to you. To check, log in to Stixify with the team the API key belongs to and make sure you can see the Dossier.

---

## Deployment

### Docker Deployment

Use the following `docker-compose.yml`:

```yaml
services:
  connector-stixify:
    image: opencti/connector-dogesec-stixify:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_STIXIFY_ID}
      - CONNECTOR_NAME=Stixify
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT12H
      - STIXIFY_BASE_URL=https://api.stixify.com/
      - STIXIFY_API_KEY=${STIXIFY_API_KEY}
      - STIXIFY_DOSSIER_IDS=dossier1-uuid,dossier2-uuid
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
    %% Box 1: Stixify Web
    subgraph Stixify_Web["Stixify Web"]
        Reports[Intel Reports]
        NLP[NLP Extractions]
        Reports --> NLP
    end

    %% Box 2: Stixify API
    subgraph Stixify_API["Stixify API"]
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

| Stixify Data | OpenCTI Entity | Notes |
|----------------|----------------|-------|
| Uploaded Report | Report | Original report as a STIX report |
| Extracted Relationships | Relationships | Stixify uses NLP to define descriptive relationships between extracted objects |
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

Stixify includes several custom STIX object types that are not currently supported by OpenCTI. These custom objects are:

* `attack-action` (SDO)
* `attack-flow` (SDO)
* `exploit` (SDO)
* `weaknesses` (SDO)
* `x-mitre-asset` (SDO MITRE ATT&CK)
* `x-mitre-analytic` (SDO MITRE ATT&CK)
* `x-mitre-detection-strategy` (SDO MITRE ATT&CK)
* `cryptocurrency-transaction` (SCO)
* `data-source` (SCO)

When a STIX Bundle associated with a Report contains any of these object types, OpenCTI will report import errors for those specific objects. This behavior is expected.

All other supported STIX objects in the bundle will import successfully and remain usable in OpenCTI.

### Processing Details

1. **Dossier Selection**:
   - At least one Dossier ID must be provided
   - Can import from multiple dossiers (comma-separated)
   - Access to dossiers visible to authenticated team

2. **Historical Import**:
   - All historical intelligence from reports is ingested
   - New intelligence added to dossiers is imported on schedule

3. **Incremental Updates**:
   - Polls at the configured `CONNECTOR_DURATION_PERIOD` (default: 1 hour)
   - Only fetches new/updated intelligence since last run

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug`.

### Verification

Navigate to `Data` → `Ingestion` → `Connectors` → `Stixify` to verify the connector is working.

---

## Additional Information

### About Stixify

- **Website**: [stixify.com](https://www.stixify.com/)
- **Sign up**: Free tier available
- **Provider**: [dogesec](https://dogesec.com/)

### Support

- **OpenCTI Support**: For general connector installation help
- **dogesec Community Forum**: [community.dogesec.com](https://community.dogesec.com/) (recommended)
- **dogesec Support Portal**: [support.dogesec.com](https://support.dogesec.com/) (requires plan with email support)

### Use Cases

| Use Case | Description |
|----------|-------------|
| Report Processing | Extract intelligence from PDF threat reports |
| Document Analysis | Analyze advisories, bulletins, research papers |
| IOC Extraction | Automate indicator extraction from documents |
| Intelligence Library | Build searchable intelligence from reports |
