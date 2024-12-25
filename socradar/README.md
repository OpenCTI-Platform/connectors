# OpenCTI SOCRadar Connector

The connector imports threat intelligence feeds from SOCRadar into OpenCTI. It processes various types of indicators including IP addresses, domains, URLs, and file hashes.

SOCRadar provides comprehensive threat intelligence feeds that can be used to detect and prevent various types of cyber threats. The connector fetches these feeds and converts them into standardized STIX2 format for use in OpenCTI, enabling organizations to enhance their threat detection and response capabilities.

## Installation

### Requirements

- OpenCTI Platform >= 6.4.5
- SOCRadar API key
- Python 3.11+

### Configuration

| Parameter | Docker envvar | Mandatory | Description |
| --- | --- | --- | --- |
| `opencti.url` | `OPENCTI_URL` | Yes | The URL of your OpenCTI platform |
| `opencti.token` | `OPENCTI_TOKEN` | Yes | Your OpenCTI admin token |
| `radar.base_feed_url` | `RADAR_BASE_FEED_URL` | Yes | SOCRadar API base URL |
| `radar.socradar_key` | `RADAR_SOCRADAR_KEY` | Yes | Your SOCRadar API key |
| `radar.interval` | `RADAR_INTERVAL` | Yes | Time between runs (in seconds, default: 600) |
| `radar.collections_uuid` | `RADAR_COLLECTIONS_UUID` | Yes | Collection IDs to fetch |

### Debugging

- Set log level to `debug` for detailed connector operations
- Check API key validity if feed collection fails
- Verify network connectivity to SOCRadar API
- Ensure OpenCTI platform is accessible
- Monitor memory usage for large feed processing

### Additional Information

The connector processes the following data:
* IP addresses (IPv4 and IPv6)
* Domain names
* URLs
* File hashes (MD5, SHA1, SHA256)
