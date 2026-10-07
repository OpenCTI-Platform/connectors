# OpenCTI ESET ETI Report Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

The ESET ETI Report Enrichment connector automatically downloads PDF reports from the ESET Threat Intelligence (ETI) portal and attaches them to ESET report objects in OpenCTI.

## Table of Contents

- [OpenCTI ESET ETI Report Connector](#opencti-eset-eti-report-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

ESET Threat Intelligence (ETI) provides comprehensive threat intelligence including APT reports, malware analysis, and threat actor profiles. ESET report objects imported into OpenCTI typically contain external references linking to the ETI portal where detailed PDF reports are available.

This connector automates the process of:
- Detecting ESET report objects with ETI portal links
- Downloading PDF reports from the ETI API
- Attaching the PDF files directly to the report objects in OpenCTI

## Installation

### Requirements

- OpenCTI Platform >= 6.5.1
- ESET Threat Intelligence API credentials (API key and secret)

For information on obtaining API credentials, visit the [ESET Threat Intelligence documentation](https://help.eset.com/eti_portal/en-US/access_credentials.html).

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

`CONNECTOR_AUTO` defaults to `false`: ETI is a paid, quota-limited source, so reports are only enriched on demand unless you enable it.

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-eset-enrichment:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-eset-enrichment:
    image: opencti/connector-eset-enrichment:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - ESET_API_KEY=ChangeMe
      - ESET_API_SECRET=ChangeMe
      # Optional
      # - CONNECTOR_AUTO=false
      # - CONNECTOR_LOG_LEVEL=error
      # - ESET_API_HOST=https://eti.eset.com/
      # - ESET_MAX_TLP=TLP:AMBER
    restart: always
```

Start the connector:

```bash
docker compose up -d
```

### Manual Deployment

1. Copy and configure `config.yml` from the provided `config.yml.sample`.

2. Install dependencies:

```bash
pip3 install -r requirements.txt
```

3. Start the connector from the `src` directory:

```bash
python3 main.py
```

## Usage

The connector enriches ESET report objects by downloading and attaching PDF reports.

**Analyses → Reports**

When automatic mode is enabled, the connector will automatically process new ESET reports. Alternatively, select an ESET report and click the enrichment button to manually trigger.

## Behavior

The connector identifies ESET reports with ETI portal links and downloads the associated PDF files.

### Data Flow

```mermaid
graph LR
    subgraph OpenCTI Input
        Report[Report Object]
        ExtRef[ETI Portal Link]
    end

    subgraph ESET ETI API
        API[ETI API v2]
        PDF[PDF Report]
    end

    subgraph OpenCTI Output
        EnrichedReport[Enriched Report]
        Attachment[PDF Attachment]
    end

    Report --> ExtRef
    ExtRef --> API
    API --> PDF
    PDF --> Attachment
    Report --> EnrichedReport
    Attachment --> EnrichedReport
```

### Enrichment Process

| Step | Action                                           | Description                                           |
|------|--------------------------------------------------|-------------------------------------------------------|
| 1    | Scope Check                                      | Verify entity type is in connector scope              |
| 2    | Creator Check                                    | Confirm report was created by ESET                    |
| 3    | TLP Check                                        | Validate TLP against `ESET_MAX_TLP`                   |
| 4    | Attachment Check                                 | Skip if PDF already attached                          |
| 5    | URL Extraction                                   | Find ETI portal download link                         |
| 6    | PDF Download                                     | Download report via ETI API                           |
| 7    | Attachment                                       | Attach PDF to report object                           |

### URL Pattern Matching

The connector looks for ETI portal URLs matching the pattern:
```
https://[www.]*.eset.com/reports/apt/{report_uid}/download
```

These URLs are converted to API calls:
```
{api_host}/api/v2/apt-reports/{report_uid}/download/pdf
```

### Processing Details

1. **Scope Validation**: Ensures the entity type matches the configured scope (`report`)
2. **Creator Validation**: Only processes reports created by "ESET"
3. **TLP Validation**: Respects TLP markings and the `ESET_MAX_TLP` setting (`CONNECTOR_TEMPLATE_MAX_TLP` is deprecated)
4. **Duplicate Prevention**: Skips reports that already have the PDF attached
5. **URL Discovery**: Searches report's related objects for ETI portal links
6. **API Authentication**: Uses Bearer token with format `{api_key}|{api_secret}`
7. **File Attachment**: Adds PDF as base64-encoded attachment to report

### Generated STIX Objects

| STIX Property      | Description                                            |
|--------------------|--------------------------------------------------------|
| x_opencti_files    | PDF report attached as file to the report object       |

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

Log output includes:
- Entity processing status
- Creator validation results
- URL extraction details
- Download progress
- Bundle sending status

## Additional information

- **ESET Only**: The connector only processes reports created by the ESET identity
- **ETI Portal Required**: Reports must contain ETI portal download links in their objects
- **Duplicate Prevention**: Reports with existing PDF attachments are skipped
- **API Documentation**: [ESET Threat Intelligence Portal Help](https://help.eset.com/eti_portal/en-US/)
- **Credential Creation**: [ETI Access Credentials Guide](https://help.eset.com/eti_portal/en-US/access_credentials.html)
- **Playbook Support**: This connector supports OpenCTI playbook automation. In a playbook, a report that is skipped (out of scope, not created by ESET, PDF already attached or no ETI portal link) is passed on unchanged.
