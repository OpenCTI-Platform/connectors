# OpenCTI Hatching Triage Sandbox Connector

| Status | Date | Comment |
|--------|------|---------|
| Filigran Verified | -    | -       |

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration](#configuration)
  - [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
  - [Data Flow](#data-flow)
  - [Enrichment Mapping](#enrichment-mapping)
  - [Processing Details](#processing-details)
  - [Generated STIX Objects](#generated-stix-objects)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

Hatching Triage is a malware analysis sandbox that automatically analyzes malicious files and URLs, extracting configuration data, network indicators, and behavioral information.

This internal enrichment connector submits files (Artifacts) and URLs to Hatching Triage for dynamic analysis and enriches OpenCTI with the analysis results including:
- Malware family identification
- C2 server addresses and URLs
- Network indicators (domains, IPs)
- Extracted credentials
- MITRE ATT&CK TTPs
- Dropped files and configurations
- Botnet and campaign information

---

## Installation

### Requirements

- OpenCTI Platform >= 6.0.0
- Hatching Triage API token
- Network access to Hatching Triage API (tria.ge)

---

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

---

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example `docker-compose.yml`:

```yaml
services:
  connector-hatching-triage-sandbox:
    image: opencti/connector-hatching-triage-sandbox:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Hatching Triage Sandbox
      - CONNECTOR_SCOPE=Artifact,Url
      - CONNECTOR_AUTO=false
      - CONNECTOR_LOG_LEVEL=error
      - HATCHING_TRIAGE_SANDBOX_TOKEN=ChangeMe
      #- HATCHING_TRIAGE_SANDBOX_BASE_URL=https://tria.ge/api
      #- HATCHING_TRIAGE_SANDBOX_USE_EXISTING_ANALYSIS=true
      #- HATCHING_TRIAGE_SANDBOX_FAMILY_COLOR=#0059f7
      #- HATCHING_TRIAGE_SANDBOX_BOTNET_COLOR=#f79e00
      #- HATCHING_TRIAGE_SANDBOX_CAMPAIGN_COLOR=#7a01e5
      #- HATCHING_TRIAGE_SANDBOX_TAG_COLOR=#54483b
      #- HATCHING_TRIAGE_SANDBOX_MAX_TLP=TLP:AMBER
    restart: always
```

### Manual Deployment

1. Clone the repository
2. Copy `src/config.yml.sample` to `src/config.yml` and configure
3. Install dependencies: `pip install -r src/requirements.txt`
4. Run: `cd src && python3 main.py`

---

## Usage

The connector enriches Artifact and URL observables by:
1. Checking for existing analysis (if enabled)
2. Submitting the sample to Hatching Triage
3. Waiting for analysis completion
4. Processing and importing the results

Trigger enrichment:
- Manually via the OpenCTI UI
- Automatically if `CONNECTOR_AUTO=true`
- Via playbooks

---

## Behavior

### Data Flow

```mermaid
flowchart LR
    A[Artifact/URL] --> B[Hatching Triage Connector]
    B --> C{Existing Analysis?}
    C -->|Yes| D[Fetch Report]
    C -->|No| E[Submit Sample]
    E --> F[Wait for Analysis]
    F --> D
    D --> G[Process Overview Report]
    G --> H[External Reference]
    G --> I[Labels/Tags]
    G --> J[C2 Servers]
    G --> K[Credentials]
    G --> L[Domains/IPs]
    G --> M[Attack Patterns]
    G --> N[Extracted Files]
    G --> O[Notes]
```

### Enrichment Mapping

| Triage Data | OpenCTI Entity | Relationship |
|-------------|----------------|--------------|
| `analysis.tags` | Labels | family, botnet, campaign tags |
| `extracted.config.c2` | IPv4-Addr, URL | `communicates-with` or `related-to` |
| `extracted.config.credentials` | Hostname, Email-Addr | `related-to` |
| `targets.iocs.domains` | Domain-Name | `communicates-with` or `related-to` |
| `targets.iocs.ips` | IPv4-Addr | `communicates-with` or `related-to` |
| `signatures.ttp` | Attack Pattern | `uses` or `related-to` |
| `extracted.dropper.urls` | URL | `related-to` |
| `extracted.dumped_file` | Artifact | `related-to` |
| `extracted.config` | Note | Configuration details |

### Processing Details

1. **Existing Analysis Check**: If enabled, searches for existing analysis by SHA256 hash or URL
2. **Sample Submission**: Submits file or URL if no existing analysis found
3. **Analysis Wait**: Polls for analysis completion status
4. **Tag Processing**: Creates colored labels based on tag type (family, botnet, campaign)
5. **Config Extraction**: Extracts C2 servers, credentials, and configuration data
6. **IOC Extraction**: Creates observables for domains, IPs, and URLs from dynamic analysis
7. **TTP Mapping**: Maps detected signatures to MITRE ATT&CK patterns
8. **File Extraction**: Downloads and uploads extracted/dropped files

### Generated STIX Objects

| Object Type | Description |
|-------------|-------------|
| External Reference | Link to Hatching Triage analysis report |
| Labels | Malware family, botnet, campaign, and other tags |
| Note | Configuration JSON data |
| URL | C2 servers and dropper URLs |
| IPv4-Addr | C2 IP addresses and network IOCs |
| Domain-Name | Network communication domains |
| Hostname | Credential hosts |
| Email-Addr | SMTP credentials |
| Attack Pattern | MITRE ATT&CK TTPs with x_mitre_id |
| Artifact | Extracted/dropped files |
| Relationship | Various relationships between entities |

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug` to see detailed connector operations including:
- Sample submission status
- Analysis progress
- Report processing details

Common issues:
- **Analysis Failed**: Check if the sample type is supported
- **Timeout**: Complex samples may take longer to analyze
- **File Not Available**: Extracted files may take time to become available

---

## Additional Information

- [Hatching Triage Documentation](https://tria.ge/docs/)
- [Get Triage API Token](https://tria.ge/account)
- [Triage Public Cloud](https://tria.ge/)
