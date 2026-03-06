# OpenCTI Akamai Client List Stream Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | - | Initial IPv4 version |

The Akamai connector synchronizes OpenCTI IPv4 indicators with Akamai Client Lists.

## Introduction

This STREAM connector listens to OpenCTI live stream and automatically updates an Akamai Client List based on IPv4 STIX Indicators.

Supported object:

- IPv4 indicators

## Requirements

- OpenCTI >= 6.x
- Akamai Client List API enabled
- EdgeGrid credentials
- Target Client List of type IP

## Configuration variables

### OpenCTI variables

| Variable | Mandatory | Description |
|----------|-----------|-------------|
| OPENCTI_URL | Yes | OpenCTI platform URL |
| OPENCTI_TOKEN | Yes | OpenCTI API token |

### Connector variables

| Variable | Mandatory | Description |
|----------|-----------|-------------|
| CONNECTOR_ID | Yes | Unique UUID |
| CONNECTOR_TYPE | Yes | Must be STREAM |
| CONNECTOR_SCOPE | Yes | Must be indicator |
| CONNECTOR_LIVE_STREAM_ID | Yes | Live Stream ID |
| CONNECTOR_LIVE_STREAM_LISTEN_DELETE | Yes | Listen delete events |
| CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES | Yes | No dependency filtering |
| AKAMAI_BASE_URL | Yes | Akamai API base URL |
| AKAMAI_CLIENT_TOKEN | Yes | EdgeGrid client token |
| AKAMAI_CLIENT_SECRET | Yes | EdgeGrid client secret |
| AKAMAI_ACCESS_TOKEN | Yes | EdgeGrid access token |
| AKAMAI_CLIENT_LIST_ID | Yes | Target Client List ID |

## Deployment

```bash
docker build -t opencti/connector-akamai-client-list:latest .
