# OpenCTI MISP Intel Stream Connector

This connector streams threat intelligence from OpenCTI to MISP, automatically creating, updating, and deleting MISP events based on OpenCTI containers (reports, groupings, and case management objects).

## Overview

The MISP Intel connector listens to the OpenCTI live stream and synchronizes container objects with MISP:

- **Supported Containers**: Reports, Groupings, Case Incidents, Case RFI (Request for Information), Case RFT (Request for Takedown)
- **Automatic Synchronization**: Creates, updates, and deletes MISP events in real-time
- **Bidirectional Linking**: Adds external references in OpenCTI pointing to created MISP events
- **Full Context**: Resolves and includes all referenced objects from containers

## Features

- Real-time streaming of OpenCTI containers to MISP
- Comprehensive STIX 2.1 to MISP format conversion with custom logic
- Support for all OpenCTI entity types and observables
- Advanced mapping of OpenCTI entities to MISP galaxies
- Full conversion of STIX patterns to MISP attributes
- STIX 2.1 sightings support
- Preservation of threat intelligence context (tags, labels, confidence levels)
- Automatic mapping of OpenCTI authors to MISP creator organizations
- Configurable owner organization for MISP events
- Configurable distribution and threat levels
- Proxy support for enterprise environments

## Requirements

- OpenCTI Platform >= 6.4.0
- Python >= 3.9
- MISP instance with API access
- Valid API keys for both OpenCTI and MISP

## Installation

### Docker Installation (Recommended)

1. Create a `.env` file with your configuration:

```bash
# OpenCTI Configuration
OPENCTI_URL=http://opencti:8080
OPENCTI_TOKEN=your-opencti-token

# Connector Configuration
CONNECTOR_ID=your-connector-uuid
CONNECTOR_LIVE_STREAM_ID=live
CONNECTOR_LOG_LEVEL=info

# MISP Configuration
MISP_URL=https://misp.example.com
MISP_API_KEY=your-misp-api-key
MISP_SSL_VERIFY=true
MISP_DISTRIBUTION_LEVEL=1
MISP_THREAT_LEVEL=2
```

2. Run the connector:

```bash
docker-compose up -d
```

### Manual Installation

1. Clone the repository:

```bash
git clone https://github.com/OpenCTI-Platform/connectors.git
cd connectors/stream/misp-intel
```

2. Install Python dependencies:

```bash
pip install -r src/requirements.txt
```

3. Copy and configure the configuration file:

```bash
cp src/config.yml.sample src/config.yml
# Edit src/config.yml with your settings
```

4. Run the connector:

```bash
cd src
python main.py
```

## Configuration

### Required Configuration

| Parameter | Environment Variable | Description |
|-----------|---------------------|-------------|
| OpenCTI URL | `OPENCTI_URL` | URL of your OpenCTI instance |
| OpenCTI Token | `OPENCTI_TOKEN` | API token for OpenCTI |
| Connector ID | `CONNECTOR_ID` | Unique UUID for this connector |
| MISP URL | `MISP_URL` | URL of your MISP instance |
| MISP API Key | `MISP_API_KEY` | API key for MISP |

### Optional Configuration

| Parameter | Environment Variable | Default | Description |
|-----------|---------------------|---------|-------------|
| Log Level | `CONNECTOR_LOG_LEVEL` | `info` | Logging level (debug, info, warning, error) |
| Live Stream ID | `CONNECTOR_LIVE_STREAM_ID` | `live` | ID of the OpenCTI stream to listen to |
| SSL Verify | `MISP_SSL_VERIFY` | `true` | Verify SSL certificates for MISP |
| Owner Organization | `MISP_OWNER_ORG` | None | Organization that will own events in MISP |
| Distribution Level | `MISP_DISTRIBUTION_LEVEL` | `1` | MISP distribution level (0-3) |
| Threat Level | `MISP_THREAT_LEVEL` | `2` | MISP threat level (1-4) |
| Container Types | `CONNECTOR_CONTAINER_TYPES` | All supported | Comma-separated list of container types to process |
| Hard Delete | `MISP_HARD_DELETE` | `false` | Permanently delete events without blocklisting |

### Distribution Levels

- `0`: Your organisation only
- `1`: This community only
- `2`: Connected communities
- `3`: All communities

### Threat Levels

- `1`: High
- `2`: Medium
- `3`: Low
- `4`: Undefined

## Data Mapping

### Container to MISP Event

| OpenCTI Field | MISP Field | Notes |
|---------------|------------|-------|
| Container Name | Event Info | Event title |
| Created Date | Event Date | Creation timestamp |
| Created By (Author) | Creator Org (Orgc) | Organization that created the content in OpenCTI |
| Configured Org | Owner Org (Org) | Organization that owns the event in MISP |
| Confidence | Threat Level | Mapped based on confidence score |
| Labels | Tags | Added with `opencti:label=` prefix |
| Objects | Attributes/Objects | Converted based on type |

### Observable Type Mapping

| STIX Type | MISP Type | Category |
|-----------|-----------|----------|
| ipv4-addr | ip-dst | Network activity |
| ipv6-addr | ip-dst | Network activity |
| domain-name | domain | Network activity |
| url | url | Network activity |
| file (MD5) | md5 | Payload delivery |
| file (SHA1) | sha1 | Payload delivery |
| file (SHA256) | sha256 | Payload delivery |
| email-addr | email-src | Network activity |

## Operation Modes

### Create Event

When a new container is created in OpenCTI:
1. Resolves the container and all its references
2. Converts to STIX 2.1 bundle
3. Transforms to MISP event format
4. Creates event in MISP
5. Adds external reference in OpenCTI

### Update Event

When a container is updated in OpenCTI:
1. Retrieves the existing MISP event UUID from external references
2. Fetches updated container data
3. Updates the MISP event with new information

### Delete Event

When a container is deleted in OpenCTI:
1. Retrieves the MISP event UUID from external references
2. Deletes the corresponding MISP event

The deletion behavior is controlled by the `MISP_HARD_DELETE` configuration:
- **Soft Delete (default, `MISP_HARD_DELETE=false`)**: The event UUID is added to MISP's blocklist, preventing re-importation of the same event
- **Hard Delete (`MISP_HARD_DELETE=true`)**: The event is permanently deleted without blocklisting, allowing the same event to be re-imported later if needed

## Troubleshooting

### Common Issues

1. **Connection Failed**: Verify URLs and API keys are correct
2. **SSL Errors**: Set `MISP_SSL_VERIFY=false` for self-signed certificates
3. **Missing Events**: Check container type filter configuration
4. **Conversion Errors**: Check logs for specific entity or observable conversion issues

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
CONNECTOR_LOG_LEVEL=debug
```

### Health Check

The connector logs its status during startup:
- Connection verification to both OpenCTI and MISP
- Stream ID validation
- Configuration summary

## Development

### Project Structure

```
misp-intel/
├── src/
│   ├── models/                  # Pydantic configuration models
│   │   ├── __init__.py
│   │   └── configs/
│   │       ├── __init__.py
│   │       ├── base_settings.py      # Base configuration class
│   │       ├── config_loader.py      # Main configuration loader
│   │       ├── connector_configs.py  # OpenCTI & connector settings
│   │       └── misp_configs.py       # MISP-specific settings
│   ├── misp_intel_connector/
│   │   ├── __init__.py
│   │   ├── connector.py         # Main connector logic
│   │   ├── api_handler.py       # MISP API interactions
│   │   ├── stix_to_misp_converter.py  # Comprehensive STIX to MISP conversion
│   │   └── utils.py             # Helper utilities
│   ├── config.yml.sample        # Configuration template
│   ├── main.py                  # Entry point
│   └── requirements.txt         # Python dependencies
├── __metadata__/
│   └── connector_manifest.json  # Connector metadata
├── Dockerfile                   # Container definition
├── docker-compose.yml          # Docker composition
└── entrypoint.sh               # Container entry point
```

### Testing

To test the connector locally:

1. Set up a test MISP instance
2. Configure the connector with test credentials
3. Create a test container in OpenCTI
4. Verify the event appears in MISP
5. Check external reference in OpenCTI

## License

This connector is part of the OpenCTI project and is licensed under the Apache License 2.0.

## Support

For issues and questions:
- Open an issue in the [OpenCTI Connectors repository](https://github.com/OpenCTI-Platform/connectors)
- Join the [OpenCTI Community Slack](https://community.filigran.io)

## Contributing

Contributions are welcome! Please follow the OpenCTI contribution guidelines when submitting pull requests.
