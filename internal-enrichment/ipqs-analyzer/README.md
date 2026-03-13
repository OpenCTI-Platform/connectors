# OpenCTI IPQS Analyzer Connector

| Status    | Date | Comment |
| --------- | ---- | ------- |
| Community | -    | -       |

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration](#configuration)
  - [OpenCTI Configuration](#opencti-configuration)
  - [Base Connector Configuration](#base-connector-configuration)
  - [IPQS Analyzer Configuration](#ipqs-analyzer-configuration)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
  - [Data Flow](#data-flow)
  - [Analysis Reports](#analysis-reports)
  - [Generated STIX Objects](#generated-stix-objects)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

[IPQualityScore (IPQS) Analyzer](https://www.ipqualityscore.com/) is a fraud prevention and risk-scoring platform that provides comprehensive malware analysis and threat detection for files and URLs. This connector submits file artifacts and URLs to IPQS for analysis and enriches OpenCTI with threat intelligence, risk scores, and detection results.

Key features:

- **File Malware Scanning**: Advanced malware detection for files including ransomware, trojans, keyloggers, spyware, rootkits, viruses, and unwanted software
- **URL Threat Analysis**: Real-time URL scanning for phishing, malware, suspicious links, and parked domains
- **Risk-based Scoring**: Comprehensive risk assessment with confidence levels and threat classifications
- **Multi-Engine Detection**: Results from multiple threat detection engines (IPQS Threat Defender, Emerging Threats, etc.)
- **Caching Support**: Efficient lookup of recently scanned files (last 24 hours) to reduce API calls
- **Async Processing**: Polling mechanism for handling large or complex analysis requests
- **Comprehensive Reporting**: Detailed analysis reports with file metadata, hashes, and threat intelligence

---

## Installation

### Requirements

- OpenCTI Platform >= 5.12.20
- IPQS Analyzer API key with sufficient credits (10 credits per scan request)
- Python 3.12+
- Network access to IPQS Analyzer API

**Note**: IPQS provides 1,000 free credits for testing. Sign up at [IPQualityScore](https://www.ipqualityscore.com/create-account) to get started.

---

## Configuration

### OpenCTI Configuration

| Parameter       | Docker envvar   | Mandatory | Description                                                |
| --------------- | --------------- | --------- | ---------------------------------------------------------- |
| `opencti_url`   | `OPENCTI_URL`   | Yes       | The URL of the OpenCTI platform                            |
| `opencti_token` | `OPENCTI_TOKEN` | Yes       | The default admin token configured in the OpenCTI platform |

### Base Connector Configuration

| Parameter                    | Docker envvar                | Mandatory | Description                                          |
| ---------------------------- | ---------------------------- | --------- | ---------------------------------------------------- |
| `connector_id`               | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` unique for this connector |
| `connector_name`             | `CONNECTOR_NAME`             | Yes       | The name of the connector instance                   |
| `connector_scope`            | `CONNECTOR_SCOPE`            | Yes       | Must be `Artifact,Url`                               |
| `connector_auto`             | `CONNECTOR_AUTO`             | Yes       | Enable/disable auto-enrichment                       |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | Yes       | Default confidence level (0-100)                     |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`        | Yes       | Log level (`debug`, `info`, `warn`, `error`)         |

### IPQS Analyzer Configuration

| Parameter                   | Docker envvar               | Mandatory | Description                                                       |
| --------------------------- | --------------------------- | --------- | ----------------------------------------------------------------- |
| `ipqs_analyzer_server`      | `IPQS_ANALYZER_SERVER`      | Yes       | IPQS server URL (e.g., `https://www.ipqualityscore.com/api/json`) |
| `ipqs_analyzer_api_key`     | `IPQS_ANALYZER_API_KEY`     | Yes       | IPQS API key                                                      |
| `ipqs_analyzer_default_tlp` | `IPQS_ANALYZER_DEFAULT_TLP` | No        | Default TLP marking for created objects (default: `TLP:CLEAR`)    |
| `ipqs_analyzer_max_tlp`     | `IPQS_ANALYZER_MAX_TLP`     | No        | Maximum TLP level for analysis submission (default: `TLP:AMBER`)  |

---

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example `docker-compose.yml`:

```yaml
version: "3"
services:
  connector-ipqs-analyzer:
    image: opencti/connector-ipqs-analyzer:latest
    environment:
      - OPENCTI_URL=http://localhost:8080
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ipqs-analyzer
      - CONNECTOR_NAME=IPQS Analyzer
      - CONNECTOR_SCOPE=Artifact,Url
      - CONNECTOR_AUTO=false
      - CONNECTOR_CONFIDENCE_LEVEL=80
      - CONNECTOR_LOG_LEVEL=info
      - IPQS_ANALYZER_SERVER=https://www.ipqualityscore.com/api/json
      - IPQS_ANALYZER_API_KEY=ChangeMe
      - IPQS_ANALYZER_DEFAULT_TLP=TLP:CLEAR
      - IPQS_ANALYZER_MAX_TLP=TLP:AMBER
    restart: always
```

### Manual Deployment

1. Clone the repository
2. Copy `src/config.yml.sample` to `src/config.yml` and configure
3. Install dependencies: `pip install -r requirements.txt`
4. Run the connector: `python src/ipqs_analyzer.py`

---

## Usage

The connector enriches Artifact and URL observables by:

1. Submitting files or URLs to IPQS for analysis
2. Checking cached results first for efficiency
3. Waiting for analysis completion with polling mechanism
4. Extracting threat data and risk scores
5. Creating relationships and enrichment data in OpenCTI

Trigger enrichment:

- Manually via the OpenCTI UI on Artifact entities
- Automatically if `CONNECTOR_AUTO=true`
- Via playbooks

---

## Behavior

### Data Flow

```
Artifact Observable or URL Observable
       ↓
IPQS Connector
       ↓
Check Lookup Cache ─→ Return Cached Results
       ↓ (if not cached)
Submit to Scan Endpoint
       ↓
Get Request ID
       ↓
Poll Postback Endpoint (up to 8 retries, 10s interval)
       ↓
Extract Threat Intelligence
       ↓
┌──────┬───────┐
↓      ↓       ↓
Labels  Scores  External
(Threat)(OpenCTI) Refs
       ↓
Update OpenCTI with Enrichment Data
```

### Analysis Reports

The connector imports various analysis data from IPQS:

| Report Type             | Description                                                                           |
| ----------------------- | ------------------------------------------------------------------------------------- |
| **Detection Results**   | Multi-engine malware detection results (IPQS Threat Defender, Emerging Threats, etc.) |
| **Risk Assessment**     | Overall risk scores and threat classifications                                        |
| **File Metadata**       | File size, type, hashes (SHA256, MD5, SHA1), scan timestamps                          |
| **URL Analysis**        | Phishing detection, malware links, domain reputation, parked domain detection         |
| **Threat Intelligence** | Suspicious behavior detection, spam domains, abusive content                          |
| **External References** | Links to IPQS analysis reports and threat intelligence                                |

**API Response Fields:**

- `success`: Request success status
- `message`: Response message
- `file_hash`: SHA256 hash of analyzed file
- `type`: Scan type (scan/lookup)
- `status`: Scan status (completed/cached/pending)
- `result`: Array of engine detection results
- `request_id`: Unique request identifier for polling

### Generated STIX Objects

| Object Type            | Description                                                       |
| ---------------------- | ----------------------------------------------------------------- |
| **Labels**             | Risk classifications (Malicious/Clean) based on detection results |
| **External Reference** | Links to IPQS analysis reports                                    |
| **IPv4-Addr**          | Related IP addresses extracted from analysis (if applicable)      |
| **AutonomousSystem**   | Related ASN information (if applicable)                           |
| **Relationship**       | Links between observables and infrastructure indicators           |
| **Indicator**          | File hash indicators with detection patterns                      |
| **Note**               | Failure notes when enrichment encounters errors                   |

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug` to see:

- File submission details
- Cache lookup results
- Polling progress and retry attempts
- STIX object generation

Common issues:

| Issue                         | Solution                                                                                       |
| ----------------------------- | ---------------------------------------------------------------------------------------------- |
| **Insufficient Credits**      | Each scan costs 10 IPQS credits. Check your account balance and upgrade if needed.             |
| **Timeout errors**            | Complex samples may take longer. The connector polls up to 8 times with 10s intervals.         |
| **API key errors**            | Verify your IPQS API key is valid and has malware scanning permissions.                        |
| **Cache lookup failures**     | Ensure file hashes are correctly computed. Network issues may prevent cache checks.            |
| **OpenCTI connection errors** | Verify `OPENCTI_URL` and `OPENCTI_TOKEN` are correct. Check platform availability.             |
| **Rate limiting**             | IPQS may rate-limit requests. Consider `CONNECTOR_AUTO=false` to reduce automatic submissions. |
| **Webhook setup**             | For high-volume processing, consider setting up IPQS webhooks instead of polling.              |

---

## Additional Information

- [IPQualityScore](https://www.ipqualityscore.com/)
- [Malware File Scanner API Documentation](https://www.ipqualityscore.com/documentation/malware-file-scanner-api/overview)
- [OpenCTI Platform](https://docs.opencti.io/latest/deployment/installation/)
- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html)

### API Information

- **Cost**: 10 credits per malware scan request
- **Caching**: Lookup results cached for 24 hours
- **Async Processing**: Large files processed asynchronously with polling
- **Webhook Support**: Available for high-volume processing
- **Response Time**: Typically 30 seconds to several minutes for complex analysis

### Server URLs

- **Primary API**: `https://www.ipqualityscore.com`
- **Documentation**: `https://www.ipqualityscore.com/documentation/malware-file-scanner-api/overview`
