# OpenCTI RST Noise Control Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
  - [Requirements](#requirements)
- [Configuration](#configuration)
  - [OpenCTI Configuration](#opencti-configuration)
  - [Base Connector Configuration](#base-connector-configuration)
  - [RST Noise Control Configuration](#rst-noise-control-configuration)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Usage](#usage)
- [Behavior](#behavior)
  - [Data Flow](#data-flow)
  - [Actions](#actions)
  - [Processing Details](#processing-details)
- [Debugging](#debugging)
- [Additional Information](#additional-information)

---

## Introduction

The [RST Noise Control](https://www.rstcloud.com/rst-noise-control/) connector checks if observables and indicators are benign or potentially noisy and not worth detecting. It helps reduce false positives by identifying well-known, popular, or benign values that could trigger false alerts.

Key features:
- Identify benign/noisy indicators
- Customizable score adjustments
- Detection flag management
- Trusted source filtering
- Pay-as-you-go pricing model

---

## Installation

### Requirements

- OpenCTI Platform >= 6.0.0
- RST Cloud API key ([Get one here](https://aws.amazon.com/marketplace/pp/prodview-bmd536bqonz22) or contact trial@rstcloud.net)
- Network access to RST Cloud API

---

## Configuration
Configuring the connector is straightforward. The minimal setup requires entering the RST Cloud API key and specifying the OpenCTI connection settings. 

### OpenCTI Configuration

| Parameter | Docker envvar | Mandatory | Description |
|-----------|---------------|-----------|-------------|
| `opencti_url` | `OPENCTI_URL` | Yes | The URL of the OpenCTI platform |
| `opencti_token` | `OPENCTI_TOKEN` | Yes | The default admin token configured in the OpenCTI platform |

### Base Connector Configuration

| Parameter | Docker envvar | Mandatory | Default | Description |
|-----------|---------------|-----------|---------|-------------|
| `connector_id` | `CONNECTOR_ID` | No | `04543793-50e8-4d02-b472-e88a62e8f161` | A valid arbitrary `UUIDv4` unique for this connector |
| `connector_name` | `CONNECTOR_NAME` | No | `RST Noise Control` | The name of the connector instance |
| `connector_scope` | `CONNECTOR_SCOPE` | No | `IPv4-Addr,Domain-Name,Url,StixFile,indicator` | Supported: `IPv4-Addr,Domain-Name,Url,StixFile,indicator` |
| `connector_auto` | `CONNECTOR_AUTO` | No | `false` | Enable/disable auto-enrichment |
| `connector_log_level` | `CONNECTOR_LOG_LEVEL` | No | `error` | Log level (`debug`, `info`, `warn`, `warning`, `error`) |
| `connector_max_tlp` | `CONNECTOR_MAX_TLP` | No | `TLP:AMBER+STRICT` | Maximum TLP of the entities the connector is allowed to enrich |

### RST Noise Control Configuration

In `config.yml`, these parameters go in the `rst_noise_control` section (the legacy `rst-noise-control` section name is still accepted).

| Parameter | Docker envvar | Mandatory | Default | Description |
|-----------|---------------|-----------|---------|-------------|
| `api_key` | `RST_NOISE_CONTROL_API_KEY` | Yes | - | RST Cloud API key |
| `base_url` | `RST_NOISE_CONTROL_BASE_URL` | No | `https://api.rstcloud.net/v1` | API base URL |
| `timeout` | `RST_NOISE_CONTROL_TIMEOUT` | No | `10` | API request timeout in seconds |
| `max_tlp` | `RST_NOISE_CONTROL_MAX_TLP` | No | - | Deprecated: use `CONNECTOR_MAX_TLP` instead |
| `update_confidence` | `RST_NOISE_CONTROL_UPDATE_CONFIDENCE` | No | `true` | Update confidence based on result |
| `update_score` | `RST_NOISE_CONTROL_UPDATE_SCORE` | No | `true` | Update score based on result |
| `change_action_score_change` | `RST_NOISE_CONTROL_CHANGE_ACTION_SCORE_CHANGE` | No | `10` | Score reduction for "Change" action |
| `drop_action_score_change` | `RST_NOISE_CONTROL_DROP_ACTION_SCORE_CHANGE` | No | `50` | Score reduction for "Drop" action |
| `drop_action_detection_flag` | `RST_NOISE_CONTROL_DROP_ACTION_DETECTION_FLAG` | No | `true` | Unset detection flag on Drop |

---

## Deployment

### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example `docker-compose.yml`:

```yaml
version: '3'
services:
  connector-rst-noise-control:
    image: opencti/connector-rst-noise-control:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - RST_NOISE_CONTROL_API_KEY=ChangeMe
    restart: always
```

### Manual Deployment

1. Clone the repository
2. Copy `src/config.yml.sample` to `src/config.yml` and configure
3. Install dependencies: `pip install -r requirements.txt`
4. Run the connector

---

## Usage

The connector reduces false positives by:
1. Checking indicators against RST Noise Control database
2. Identifying benign or noisy values
3. Adjusting scores based on findings
4. Optionally unsetting detection flags

Trigger enrichment:
- Manually via the OpenCTI UI
- Automatically if `CONNECTOR_AUTO=true`
- Via playbooks

---

## Behavior

### Data Flow

```mermaid
flowchart LR
    A[Observable/Indicator] --> B[RST Noise Control]
    B --> C{RST Cloud API}
    C --> D{Action?}
    D -->|Not Found| E[No Change]
    D -->|Change| F[Reduce Score by M]
    D -->|Drop| G[Reduce Score by N]
    G --> H[Unset Detection Flag]
    F --> I[OpenCTI]
    G --> I
    E --> I
```

### Actions

| Action | Description | Default Score Change |
|--------|-------------|---------------------|
| Not Found | Value is not marked as noisy | No change |
| Change | Value may be noisy | Reduce score by 10 |
| Drop | Value is likely benign | Reduce score by 50 |

### Processing Details

1. **Score Reduction**: Scores are reduced by the configured amount, with a minimum of 0
2. **Detection Flag**: When action is "Drop" and `drop_action_detection_flag=true`, the detection flag is unset
3. **Trusted Filter List**: Add trusted IoC sources to a filter list to avoid API calls for known-good sources

---

## Debugging

Enable debug logging by setting `CONNECTOR_LOG_LEVEL=debug` to see:
- API request/response details
- Action decisions
- Score adjustment calculations

---

## Additional Information

- [RST Cloud](https://www.rstcloud.com/)
- [RST Noise Control](https://www.rstcloud.com/rst-noise-control/)
- [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-bmd536bqonz22)
- Contact: trial@rstcloud.net

### Use Cases

- **Reduce Alert Fatigue**: Automatically lower scores for common benign indicators
- **Improve Detection Accuracy**: Unset detection flags for noisy indicators
- **Prioritize True Threats**: Focus analyst attention on genuine threats
