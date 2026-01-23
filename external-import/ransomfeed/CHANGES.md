# RansomFeed Connector - Changes Summary

## Overview
This document summarizes the changes made to the RansomFeed connector to address the feedback received during the pull request review.

## Pull Request Feedback Addressed

### 1. ✅ Migrated from GraphQL API to STIX 2.1 + RabbitMQ

**Previous approach (deprecated):**
- Used direct GraphQL API calls via `self.helper.api.identity.create()`, `self.helper.api.incident.create()`, etc.
- Objects were created synchronously through the API

**New approach (recommended):**
- Creates STIX 2.1 objects using the `stix2` library
- Publishes bundles to RabbitMQ using `self.helper.send_stix2_bundle()`
- OpenCTI workers process the bundles asynchronously
- Follows the pattern shown in the official template: https://github.com/OpenCTI-Platform/connectors/tree/master/templates/external-import

### 2. ✅ Changed from Incident to Report Objects

**Previous approach:**
- Created `Incident` objects for each ransomware attack
- Used relationships like `incident -> targets -> victim`

**New approach:**
- Creates `Report` entities that contain all related objects
- Each report includes:
  - Victim (Identity/Organization)
  - Ransomware group (Intrusion Set)
  - Relationships (targets, located-at, belongs-to)
  - Optional: Location, Domain, Indicators

## Structural Changes

### New Directory Structure
```
ransomfeed/
├── src/
│   ├── config.yml.sample
│   ├── main.py
│   └── ransomfeed/
│       ├── __init__.py
│       ├── api_client.py       # API communication
│       ├── config_loader.py    # Configuration management
│       ├── connector.py        # Main connector logic
│       └── converter_to_stix.py # STIX 2.1 conversion
├── Dockerfile
├── docker-compose.yml
├── entrypoint.sh
├── README.md
└── requirements.txt
```

### File Descriptions

#### `api_client.py`
- Handles all communication with the RansomFeed API
- Provides error handling and logging
- Returns raw data for processing

#### `config_loader.py`
- Loads configuration from YAML file or environment variables
- Validates required parameters
- Provides configuration object to other components

#### `converter_to_stix.py`
- Converts RansomFeed data into STIX 2.1 objects
- Methods for creating:
  - Identity (victims)
  - Intrusion Set (ransomware groups)
  - Location (countries)
  - Domain Name (websites)
  - Indicator (file hashes)
  - Relationship (between entities)
  - Report (main container)

#### `connector.py`
- Main connector logic
- Orchestrates data fetching and processing
- Creates STIX bundles and sends to RabbitMQ
- Manages connector state

#### `main.py`
- Entry point
- Initializes configuration and helper
- Starts the connector with scheduling

## Key Features

### STIX 2.1 Objects Created

1. **Identity** - Organizations representing victims
2. **Intrusion Set** - Ransomware groups with labels
3. **Report** - Container for all related entities
4. **Location** - Countries (if available)
5. **Domain Name** - Victim websites (if available)
6. **Indicator** - File hashes (if available and enabled)
7. **Relationship** - Links between entities:
   - `targets`: Intrusion Set → Victim
   - `targets`: Intrusion Set → Location
   - `located-at`: Victim → Location
   - `belongs-to`: Domain → Victim

### Configuration Options

New configuration parameters:
- `RANSOMFEED_API_URL`: Base URL for the RansomFeed API
- `RANSOMFEED_TLP_LEVEL`: TLP marking level (white, clear, green, amber, red)
- `RANSOMFEED_CREATE_INDICATORS`: Enable/disable indicator creation from hashes
- `CONNECTOR_DURATION_PERIOD`: Interval between runs (ISO 8601 format)

### Best Practices Implemented

1. **Deduplication**: Uses `helper.stix2_deduplicate_objects()` before sending
2. **Bundle Creation**: Uses `helper.stix2_create_bundle()` for proper formatting
3. **Work Management**: Proper work initiation and completion tracking
4. **State Management**: Tracks last run to avoid duplicate imports
5. **Error Handling**: Comprehensive error handling and logging
6. **Marking**: Proper TLP marking on all objects
7. **Author Attribution**: All objects include created_by_ref

## Migration Path

If you have an existing deployment:

1. **Backup your data**: Export existing entities if needed
2. **Update the code**: Replace the entire `src/` directory with the new structure
3. **Update configuration**: Use the new `config.yml.sample` as reference
4. **Update requirements**: Install new dependencies with `pip install -r requirements.txt`
5. **Test**: Run the connector in a test environment first
6. **Deploy**: Deploy to production

## Compatibility

- **OpenCTI**: >= 6.0
- **Python**: >= 3.8
- **pycti**: >= 6.1.0
- **stix2**: >= 3.0.1

## References

- Template connector: https://github.com/OpenCTI-Platform/connectors/tree/master/templates/external-import
- OpenCTI Documentation: https://docs.opencti.io/latest/

## Testing

To test the connector:

```bash
# Set up configuration
cp src/config.yml.sample src/config.yml
# Edit config.yml with your settings

# Install dependencies
pip install -r requirements.txt

# Run the connector
cd src
python main.py
```

## Docker Deployment

```bash
# Build the image
docker build -t opencti/connector-ransomfeed:latest .

# Or use docker-compose
docker-compose up -d
```

## Contact

For questions or issues:
- GitHub: https://github.com/ransomfeed/Ransomfeed_OpenCTI_connector
- Email: dario@ransomfeed.it

