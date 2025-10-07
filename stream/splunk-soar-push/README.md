# Splunk SOAR Push Stream Connector

This connector pushes threat intelligence from OpenCTI to Splunk SOAR (formerly Phantom), creating:
- **Events** from OpenCTI Incidents
- **Cases** from OpenCTI Containers (Reports, Groupings, Case-Incident, Case-RFI, Case-RFT)

## Overview

The Splunk SOAR Push connector listens to the OpenCTI live stream and automatically pushes data to synchronize:

### Incidents → SOAR Events
- OpenCTI Incidents are converted to Splunk SOAR Events (containers with type "default")
- Resolves relationships around incidents including:
  - Observables (IPs, domains, files, etc.)
  - Malware
  - Attack patterns
  - Threat actors
  - Indicators
- All related entities are added as artifacts in the SOAR event

### Containers → SOAR Cases
- OpenCTI Containers (Reports, Groupings, Cases) are converted to Splunk SOAR Cases
- Resolves all entities within the container including:
  - All observables
  - Threat intelligence (malware, threat actors, campaigns)
  - Vulnerabilities
  - Attack patterns
- All contained entities are added as artifacts in the SOAR case

## Installation

### Requirements
- OpenCTI Platform >= 5.12.0
- Splunk SOAR >= 5.0
- Python >= 3.9
- Docker (optional, for containerized deployment)

### Configuration

1. Create a live stream in OpenCTI:
   - Go to Data > Data sharing > Live streams
   - Create a new stream with appropriate filters
   - Note the stream ID

2. Generate a Splunk SOAR API token:
   - In Splunk SOAR, go to Administration > User Management > Users
   - Select your user and generate an automation API token
   - Or use username/password authentication (less secure)

3. Configure the connector by copying `config.yml.sample` to `config.yml` and updating:
   ```yaml
   opencti:
     url: 'http://your-opencti-instance'
     token: 'your-opencti-token'

   connector:
     id: 'unique-connector-id'
     live_stream_id: 'your-stream-id'

   splunk_soar:
     url: 'https://your-splunk-soar-instance.com'
     api_token: 'your-soar-api-token'
   ```

### Docker Deployment

1. Build the Docker image:
   ```bash
   docker build -t opencti-splunk-soar .
   ```

2. Run with docker-compose:
   ```yaml
   version: '3'
   services:
     connector-splunk-soar:
       image: opencti-splunk-soar
       environment:
         - OPENCTI_URL=http://opencti:8080
         - OPENCTI_TOKEN=ChangeMe
         - CONNECTOR_ID=ChangeMe
         - CONNECTOR_LIVE_STREAM_ID=ChangeMe
         - SPLUNK_SOAR_URL=https://soar.example.com
         - SPLUNK_SOAR_API_TOKEN=ChangeMe
       restart: always
   ```

### Manual Deployment

1. Install dependencies:
   ```bash
   pip3 install -r src/requirements.txt
   ```

2. Run the connector:
   ```bash
   cd src
   python3 main.py
   ```

## Features

### Entity Mapping

The connector maps OpenCTI entities to Splunk SOAR artifacts with appropriate CEF fields:

| OpenCTI Entity | SOAR Artifact Type | Key Fields |
|---------------|-------------------|------------|
| IPv4/IPv6 Address | IP Address | sourceAddress |
| Domain | Domain | destinationDnsDomain |
| URL | URL | requestURL |
| File | File | fileName, fileHash |
| Email Address | Email | sourceUserName |
| Malware | Malware | malwareName, malwareTypes |
| Threat Actor | Threat Actor | threatActorName |
| Attack Pattern | Attack Pattern | attackPatternName, mitreAttackId |
| Vulnerability | Vulnerability | cve |
| Indicator | Indicator | indicatorPattern |

### External References

The connector automatically adds external references back to OpenCTI:
- When creating a SOAR event/case, an external reference is added to the OpenCTI entity
- This allows bi-directional navigation between platforms

### Stream Event Handling

- **Create**: New incidents/containers create corresponding SOAR events/cases
- **Update**: Existing SOAR entities are updated with changes from OpenCTI
- **Delete**: Removes external references; optionally closes SOAR entities

### Performance Optimization

- Queue-based processing to avoid stream timeouts
- Bulk artifact creation for better performance
- Configurable batch sizes and limits

## Monitoring

The connector logs all operations including:
- Connection status to both OpenCTI and Splunk SOAR
- Entity processing (create/update/delete)
- Error details with full stack traces
- Performance metrics (queue size, processing times)

## Troubleshooting

### Common Issues

1. **Connection Failed**: 
   - Verify URLs and credentials
   - Check network connectivity
   - Ensure SSL certificates are valid or disable verification

2. **Stream Timeout**:
   - The connector uses a worker queue to handle large entities
   - Increase queue size if needed

3. **Missing Entities**:
   - Check stream filters in OpenCTI
   - Verify entity types are supported

### Debug Mode

Enable debug logging in config.yml:
```yaml
connector:
  log_level: 'DEBUG'
```

## Support

For issues or questions:
- OpenCTI Documentation: https://docs.opencti.io
- Splunk SOAR Documentation: https://docs.splunk.com/Documentation/SOAR
- GitHub Issues: https://github.com/OpenCTI-Platform/connectors
