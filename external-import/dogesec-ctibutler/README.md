# OpenCTI CTI Butler Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

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
  - [Processing Details](#processing-details)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

[CTI Butler](https://www.ctibutler.com/) is a web application that stores common cyber threat intelligence knowledge bases (e.g., MITRE ATT&CK, MITRE CWE, MITRE CAPEC, MITRE ATLAS...) as STIX Objects.

The OpenCTI CTI Butler Connector syncs intelligence from CTI Butler's knowledge bases to OpenCTI, enabling automated import of standardized threat intelligence frameworks.

The OpenCTI CTI Butler Connector can be used to replace the following connectors, [MITRE ATLAS](https://hub.filigran.io/cybersecurity-solutions/open-cti-integrations/mitre-atlas), [MITRE ATT&CK](https://hub.filigran.io/cybersecurity-solutions/open-cti-integrations/mitre), and [DISARM Framework](https://hub.filigran.io/cybersecurity-solutions/open-cti-integrations/disarm-framework).

> **Note**: This connector only works with CTI Butler Web. It does not support self-hosted CTI Butler installations at this time.

### Screenshots

![CTI Butler MITRE ATT&CK](media/ctibutler-attack.png)

![CTI Butler STIX Butler](media/ctibutler-object.png)

---

## Installation

### Requirements

- OpenCTI >= 6.5.10
- CTI Butler team subscribed to a plan with API access enabled
- CTI Butler API Key

### Generating an API Key

[![Creating a CTI Butler API Key](https://img.youtube.com/vi/AENI22ybO14/0.jpg)](https://www.youtube.com/watch?v=AENI22ybO14)

[This video demonstrates the steps outlined below](https://www.youtube.com/watch?v=AENI22ybO14).

1. Log in to your CTI Butler account
2. Navigate to "Account Settings"
3. Locate the API section and select "Create Token"
4. Select the team you want to use and generate the key
  * If you don't see a team listed, you do not belong to a team on a plan with API access. Please upgrade the teams account to continue.
5. Copy the key for configuration

---

## Configuration

### Configuration Variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

`CONNECTOR_DURATION_PERIOD` defaults to `P7D`, which is recommended because knowledge bases change very infrequently.
The deprecated `CTIBUTLER_INTERVAL_DAYS` is still accepted and converted to a duration in days.

#### Available Knowledge Bases

Set `CTIBUTLER_KNOWLEDGEBASES` to a comma-separated list of knowledge bases, without spaces. The available knowledge bases are:

- `attack-enterprise`: MITRE ATT&CK for Enterprise
- `attack-mobile`: MITRE ATT&CK for Mobile
- `attack-ics`: MITRE ATT&CK for ICS
- `capec`: Common Attack Pattern Enumeration and Classification
- `disarm`: DISARM Framework
- `atlas`: MITRE ATLAS (AI/ML threats)
- `location`: Location data
- `sector`: Industry sector data

---

## Deployment

### Docker Deployment

Use the following `docker-compose.yml`:

```yaml
services:
  connector-ctibutler:
    image: opencti/connector-dogesec-ctibutler:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_CTIBUTLER_ID}
      - CONNECTOR_NAME=CTIButler
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=P7D
      - CTIBUTLER_BASE_URL=https://api.ctibutler.com/
      - CTIBUTLER_API_KEY=${CTIBUTLER_API_KEY}
      - CTIBUTLER_KNOWLEDGEBASES=attack-enterprise,capec
    restart: always
    depends_on:
      - opencti
```

### Manual Deployment

1. Clone the repository and navigate to the connector directory
2. Install dependencies: `pip install -r requirements.txt`
3. Configure `config.yml`:

```yaml
opencti:
  url: 'http://localhost:8080'
  token: 'your-token'

connector:
  id: 'your-uuid'
  name: 'CTI Butler'
  log_level: 'info'
  duration_period: 'P7D'

ctibutler:
  base_url: 'https://api.ctibutler.com/'
  api_key: 'your-api-key'
  knowledgebases: 'attack-enterprise,capec'
```

4. Run: `python main.py`

---

## Behavior

### Data Flow

```mermaid
graph LR
    %% Box 1: CTI Butler Web
    subgraph CTIButler_Web["CTI Butler Web"]
        Knowledgebases[Knowledgebases]
    end

    %% Box 2: CTI Butler
    subgraph CTIButler_API["CTI Butler"]
        API[API]
        Bundle[STIX Bundle]
        API --> Bundle
    end
    
    %% Box 3: OpenCTI
    subgraph OpenCTI["OpenCTI"]
        Connector[Connector]
        AttckEnterprise[MITRE ATT&CK Enterprise]
        AttckMobile[MITRE ATT&CK Mobile]
        AttckICS[MITRE ATT&CK ICS]
        Capec[MITRE CAPEC]
        Atlas[MITRE ATLAS]
        Disarm[DISARM]
        Location[Locations]
        Sectors[Sectors]
    end

    %% Cross-section flow
    Knowledgebases --> API
    Bundle --> Connector

    %% Connector links
    Connector --> AttckEnterprise
    Connector --> AttckMobile
    Connector --> AttckICS
    Connector --> Capec
    Connector --> Atlas
    Connector --> Location
    Connector --> Sectors

```

### Entity Mapping

#### MITRE ATT&CK Enterprise/Mobile/ICS

| CTI Butler Data | OpenCTI Entity | Notes |
|---------------------------|----------------|-------|
| Tactic | x-mitre-tactic | ATT&CK Tactics |
| Technique/Sub-technique | Attack Pattern | ATT&CK Techniques |
| Campaign | Campaign | ATT&CK Campaigns |
| Mitigation | Course of Action | ATT&CK Mitigations |
| Software | Tool / Malware | ATT&CK Softwares |
| Group | Intrusion Set | ATT&CK Intrusion Set |
| Data Source | x-mitre-data-source | ATT&CK Data Sources |
| Data Component | x-mitre-data-component | ATT&CK Data Components |
| Asset | x-mitre-asset| ATT&CK ICS Assets |

Note, Detection Stratergy (`x-mitre-detection-strategy`) and Analytic (`x-mitre-analytic`) objects (introduced in ATT&CK v18 are not currently supported in OpenCTI but are supported by Open CTI. You will see failures in the logs when the connector tries to import these objects

#### MITRE CWE

CTI Butler also has a CWE Knowledgebase. You cannot use this connector to import the CWE knowledgebase because OpenCTI does not support the custom STIX `weakness` objects used by CTI Butler to represent CWEs.

#### MITRE CAPEC

| CTI Butler Data | OpenCTI Entity | Notes |
|---------------------------|----------------|-------|
| Technique | Attack Pattern | CAPEC Techniques |

#### MITRE ATLAS

| CTI Butler Data | OpenCTI Entity | Notes |
|---------------------------|----------------|-------|
| Tactic | x-mitre-tactic | ATLAS Tactics |
| Technique/Sub-technique | Attack Pattern | ATLAS Techniques |
| Mitigation | Course of Action | ATLAS Mitigations |

#### DISARM

| CTI Butler Data | OpenCTI Entity | Notes |
|---------------------------|----------------|-------|
| Tactic | x-mitre-tactic | DISARM Tactics |
| Technique/Sub-technique | Attack Pattern | DISARM Techniques |

#### MITRE Location

| CTI Butler Data | OpenCTI Entity | Notes |
|---------------------------|----------------|-------|
| Country | Location | Countries |
| Region | Location | Regions |
| Sub-region | Location | Sub-regions |
| Intermediate Region | Location | Intermediate Regions |

#### MITRE Sector

| CTI Butler Data | OpenCTI Entity | Notes |
|---------------------------|----------------|-------|
| Sectors | Identity | Industrial Sectors |

### Processing Details

1. **Knowledge Base Selection**:
   - Configure which knowledge bases to import via `CTIBUTLER_KNOWLEDGEBASES`
   - Each knowledge base is fetched independently

2. **STIX Import**:
   - CTI Butler provides native STIX 2.1 objects
   - Direct import preserves all relationships and metadata
   - Includes external references to source documentation

3. **Update Frequency**:
   - Controlled by `CONNECTOR_DURATION_PERIOD`
   - Recommended: Weekly updates (7 days)
   - Knowledge bases are updated at source periodically

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug`.

### Verification

Navigate to `Data` → `Ingestion` → `Connectors` → `CTI Butler` to verify the connector is working.

Common issues:

- **Authentication failed**: Verify API key and team subscription
- **Empty imports**: Check knowledge base names are spelled correctly
- **Connection errors**: Verify network access to `api.ctibutler.com`

---

## Additional Information

### About CTI Butler

- **Website**: [ctibutler.com](https://www.ctibutler.com/)
- **Sign up**: Free tier available
- **Provider**: [dogesec](https://dogesec.com/)

### Support

- **OpenCTI Support**: For general connector installation help
- **dogesec Community Forum**: [community.dogesec.com](https://community.dogesec.com/) (recommended)
- **dogesec Support Portal**: [support.dogesec.com](https://support.dogesec.com/) (requires plan with email support)

### Use Cases

| Use Case | Description |
|----------|-------------|
| ATT&CK Integration | Import MITRE ATT&CK techniques |
| Weakness Analysis | Track CWE entries |
| Attack Pattern Library | Import CAPEC attack patterns |
| Multi-Framework | Combine multiple frameworks in one import |
