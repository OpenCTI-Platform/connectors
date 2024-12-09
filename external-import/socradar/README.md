# OpenCTI SOCRadar Connector

This connector imports threat intelligence feeds from SOCRadar into OpenCTI. It supports various types of indicators including IP addresses, domains, URLs, and file hashes.

## Description

The SOCRadar connector fetches data from SOCRadar's threat intelligence feeds and imports them into OpenCTI. It supports:
- IP addresses (IPv4 and IPv6)
- Domains
- URLs
- File hashes (MD5, SHA1, SHA256)

Each indicator is created with proper STIX2 formatting and includes:
- Source attribution
- First/last seen dates
- Confidence levels
- TLP marking
- Kill chain phase information

## Requirements

- OpenCTI Platform >= 6.4.2
- SOCRadar API key
- Python 3.11+

## Configuration

| Parameter | Docker envvar | Mandatory | Description |
| --- | --- | --- | --- |
| `opencti_url` | `OPENCTI_URL` | Yes | The URL of the OpenCTI platform |
| `opencti_token` | `OPENCTI_TOKEN` | Yes | The default admin token configured in the OpenCTI platform |
| `connector_id` | `CONNECTOR_ID` | Yes | A valid arbitrary UUIDv4 for this connector |
| `connector_type` | `CONNECTOR_TYPE` | Yes | Must be 'EXTERNAL_IMPORT' |
| `connector_name` | `CONNECTOR_NAME` | Yes | Name of the connector |
| `connector_scope` | `CONNECTOR_SCOPE` | Yes | Scope of the connector (socradar) |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | Yes | Default confidence level for created data |
| `connector_log_level` | `CONNECTOR_LOG_LEVEL` | Yes | Logging level (debug, info, warn, error) |
| `radar_base_feed_url` | `RADAR_BASE_FEED_URL` | Yes | SocRadar API base URL |
| `radar_format_type` | `RADAR_FORMAT_TYPE` | Yes | Response format (.json) |
| `radar_socradar_key` | `RADAR_SOCRADAR_KEY` | Yes | Your SocRadar API key |
| `radar_interval` | `RADAR_INTERVAL` | Yes | Interval between runs in seconds |
