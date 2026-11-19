# OpenCTI Cyber Threat Exchange Connector

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
  - [Processing Details](#processing-details)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

[Cyber Threat Exchange](https://www.cyberthreatexchange.com/) is a marketplace for threat intelligence.

The OpenCTI Cyber Threat Exchange Connector synchronizes intelligence from Feeds you are subscribed to Cyber Threat Exchange into OpenCTI.

> **Note**: This connector only works with Cyber Threat Exchange Web ([https://www.cyberthreatexchange.com](https://www.cyberthreatexchange.com)). It does not support self-hosted Cyber Threat Exchange installations at this time.

---

## Installation

### Requirements

- OpenCTI >= 6.8.0
- Cyber Threat Exchange team subscribed to a plan with API access enabled
- Cyber Threat Exchange API Key

### Generating an API Key

1. Log in to your Cyber Threat Exchange account
2. Navigate to "Account Settings"
3. Locate the API section and select "Create Token"
4. Select the team you want to use and generate the key
  * If you don't see a team listed, you do not belong to a team on a plan with API access. Please upgrade the teams account to continue.
5. Copy the key for configuration

---

## Configuration

### Configuration Variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

They are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

#### OpenCTI Parameters

| Parameter | Docker envvar | config.yml | Mandatory | Description |
|-----------|---------------|------------|-----------|-------------|
| OpenCTI URL | `OPENCTI_URL` | `opencti.url` | Yes | The URL of the OpenCTI platform |
| OpenCTI Token | `OPENCTI_TOKEN` | `opencti.token` | Yes | The default admin token configured in the OpenCTI platform |

#### Base Connector Parameters

| Parameter | Docker envvar | config.yml | Mandatory | Default | Description |
|-----------|---------------|------------|-----------|---------|-------------|
| Connector ID | `CONNECTOR_ID` | `connector.id` | No | `b51736f7-7ed8-4c41-b247-eadd836f4f6c` | A unique `UUIDv4` for this connector |
| Connector Name | `CONNECTOR_NAME` | `connector.name` | No | `CyberThreatExchange` | Name displayed in OpenCTI |
| Connector Scope | `CONNECTOR_SCOPE` | `connector.scope` | No | `cyberthreatexchange` | The scope of the connector |
| Log Level | `CONNECTOR_LOG_LEVEL` | `connector.log_level` | No | `error` | Log level: `debug`, `info`, `warn`, `warning` or `error` |
| Duration Period | `CONNECTOR_DURATION_PERIOD` | `connector.duration_period` | No | `PT1H` | Polling interval as an ISO 8601 duration. The connector polls Cyber Threat Exchange for new Reports in the Feed(s) at this schedule. The minimum and recommended value is `PT1H` |

#### Connector Extra Parameters

| Parameter | Docker envvar | config.yml | Mandatory | Default | Description |
|-----------|---------------|------------|-----------|---------|-------------|
| Base URL | `CYBERTHREATEXCHANGE_BASE_URL` | `cyberthreatexchange.base_url` | No | `https://api.cyberthreatexchange.com/` | Cyber Threat Exchange API URL |
| API Key | `CYBERTHREATEXCHANGE_API_KEY` | `cyberthreatexchange.api_key` | Yes | - | API key for authentication |
| Feed IDs | `CYBERTHREATEXCHANGE_FEED_IDS` | `cyberthreatexchange.feed_ids` | Yes | - | Comma-separated Feed IDs. Pass the Feed IDs like so `f0895eb3-7d90-4b45-8664-a7e157ba880f,b63c638e-43e6-43d4-bfac-5b71c264b132`. The connector stops at startup when no Feed ID is set |
| Interval Hours | `CYBERTHREATEXCHANGE_INTERVAL_HOURS` | `cyberthreatexchange.interval_hours` | No | - | **Deprecated**: use `CONNECTOR_DURATION_PERIOD` instead. Polling interval in hours, still honoured when `CONNECTOR_DURATION_PERIOD` is not set |

---

## Deployment

### Docker Deployment

Use the following `docker-compose.yml`:

```yaml
services:
  connector-cyberthreatexchange:
    image: opencti/connector-dogesec-cyberthreatexchange:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_CYBERTHREATEXCHANGE_ID}
      - CONNECTOR_NAME=CyberThreatExchange
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT12H
      - CYBERTHREATEXCHANGE_BASE_URL=https://api.cyberthreatexchange.com/
      - CYBERTHREATEXCHANGE_API_KEY=${CYBERTHREATEXCHANGE_API_KEY}
      - CYBERTHREATEXCHANGE_FEED_IDS=feed1-uuid,feed2-uuid
    restart: always
    depends_on:
      - opencti
```

### Manual Deployment

1. Clone the repository and navigate to the connector directory
2. Install dependencies: `pip install -r requirements.txt`
3. Configure `config.yml`
4. Run: `python connector.py`

---

## Behavior

### Data Flow

```mermaid
graph LR
    %% Box 1: Cyber Threat Exchange Web
    subgraph CyberThreatExchange_Web["Cyber Threat Exchange Web"]
        IntelFeeds[Intel Feeds]
    end

    %% Box 2: Cyber Threat Exchange API
    subgraph CyberThreatExchange_API["Cyber Threat Exchange API"]
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
    IntelFeeds --> API
    Bundle --> Connector
```

### Processing Details

1. **Feed Selection**:
   - At least one Feed ID must be provided
   - Can import from multiple feeds (comma-separated)
   - Access to feeds visible to authenticated team
2. **Historical Import**:
   - All historical intelligence from reports is ingested
   - New intelligence added to feeds is imported on schedule
3. **Incremental Updates**:
   - Polls at the interval set by `CONNECTOR_DURATION_PERIOD` (default: 1 hour)
   - Only fetches new/updated intelligence since last run

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug`.

### Verification

Navigate to `Data` → `Ingestion` → `Connectors` → `CyberThreatExchange` to verify the connector is working.

---

## Additional Information

### About CyberThreatExchange

- **Website**: [cyberthreatexchange.com](https://www.cyberthreatexchange.com/)
- **Sign up**: Free tier available
- **Provider**: [dogesec](https://dogesec.com/)

### Support

- **OpenCTI Support**: For general connector installation help
- **dogesec Community Forum**: [community.dogesec.com](https://community.dogesec.com/) (recommended)
- **dogesec Support Portal**: [support.dogesec.com](https://support.dogesec.com/) (requires plan with email support)