# OpenCTI FT3 Framework Connector

This connector imports the FT3 (Fraud Tactics, Techniques, and Procedures) framework from Stripe into OpenCTI.

## Overview

The FT3 framework is a structured approach to understanding and defending against fraud, similar to how MITRE ATT&CK works for cybersecurity. It provides a comprehensive taxonomy of fraud tactics and techniques that organizations can use to improve their fraud detection and prevention strategies.

## Configuration

The connector accepts the following configuration variables:

| Parameter | Docker envvar | Mandatory | Description |
| --- | --- | --- | --- |
| `opencti_url` | `OPENCTI_URL` | Yes | The URL of the OpenCTI platform. |
| `opencti_token` | `OPENCTI_TOKEN` | Yes | The default admin token configured in the OpenCTI platform parameters file. |
| `connector_id` | `CONNECTOR_ID` | Yes | A unique UUIDv4 identifying the connector. |
| `connector_name` | `CONNECTOR_NAME` | No | The name of the connector (default: FT3 Framework) |
| `connector_scope` | `CONNECTOR_SCOPE` | No | The scope of data the connector imports |
| `connector_log_level` | `CONNECTOR_LOG_LEVEL` | No | Log level (debug, info, warn, error) |
| `ft3_interval` | `FT3_INTERVAL` | No | Interval in days between runs (default: 7) |
| `ft3_tactics_url` | `FT3_TACTICS_URL` | No | URL to FT3 tactics JSON (default: GitHub) |
| `ft3_techniques_url` | `FT3_TECHNIQUES_URL` | No | URL to FT3 techniques JSON (default: GitHub) |

## Deployment

### Docker Deployment

```bash
docker-compose up -d
```

### Manual Deployment

1. Install the required Python dependencies:
```bash
pip3 install -r src/requirements.txt
```

2. Copy `src/config.yml.sample` to `src/config.yml` and update with your OpenCTI credentials:
```yaml
opencti:
  url: 'http://your-opencti-instance:8080'
  token: 'your-opencti-token'
```

3. Run the connector:
```bash
cd src
python3 -m src
```

## Data Sources

The connector downloads two JSON files from the FT3 framework repository:
- **Tactics**: https://raw.githubusercontent.com/stripe/ft3/refs/heads/master/FT3_Tactics.json
- **Techniques**: https://raw.githubusercontent.com/stripe/ft3/refs/heads/master/FT3_Techniques.json

These files are converted to STIX 2.1 format before being imported into OpenCTI.

## STIX Objects Created

The connector creates the following STIX objects:
- **identity**: FT3 Framework identity
- **x-opencti-kill-chain**: FT3 kill chain definition
- **x-mitre-tactic**: Fraud tactics
- **attack-pattern**: Fraud techniques
- **relationship**: Sub-technique relationships

## License

This connector is licensed under the same terms as the OpenCTI platform.
