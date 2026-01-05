# OpenCTI Elastic Security Intel Stream Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

This connector streams threat intelligence from OpenCTI to Elastic Security, creating and managing both threat indicators and SIEM detection rules.

## Features

- **Threat Intelligence Synchronization**: Automatically syncs OpenCTI observables and indicators to Elastic's threat intelligence index
- **SIEM Rule Management**: Converts STIX indicators with patterns into Elastic Security detection rules
- **Custom Pattern Types**: Supports Elastic-specific query languages:
  - KQL (Kibana Query Language)
  - Lucene Query Syntax
  - EQL (Event Query Language)
  - ES|QL (Elasticsearch SQL)
- **Real-time Updates**: Listens to OpenCTI live stream for create, update, and delete events
- **ECS Compliant**: Converts data to Elastic Common Schema (ECS) format

## Configuration

| Parameter | Environment Variable | Description | Default |
|-----------|---------------------|-------------|----|
| OpenCTI URL | `OPENCTI_URL` | The URL of the OpenCTI platform | - |
| OpenCTI Token | `OPENCTI_TOKEN` | The OpenCTI token | - |
| Connector ID | `CONNECTOR_ID` | A valid arbitrary UUID | - |
| Stream ID | `CONNECTOR_LIVE_STREAM_ID` | The stream ID configured in OpenCTI | - |
| Elastic URL | `ELASTIC_SECURITY_URL` | Elasticsearch cluster URL | - |
| Elastic API Key | `ELASTIC_SECURITY_API_KEY` | API key for Elasticsearch | - |
| Verify SSL | `ELASTIC_SECURITY_VERIFY_SSL` | Verify SSL certificates | true |
| CA Certificate | `ELASTIC_SECURITY_CA_CERT` | Path to CA certificate file | - |
| Index Name | `ELASTIC_SECURITY_INDEX_NAME` | Threat intel index name | `logs-ti_custom_opencti.indicator` |
| Expire Time | `ELASTIC_SECURITY_INDICATOR_EXPIRE_TIME` | Days before indicators expire | 90 |
| Batch Size | `ELASTIC_SECURITY_BATCH_SIZE` | Batch size for bulk operations | 100 |

## Prerequisites

1. **Elasticsearch Cluster**: Version 8.x or higher with Security features enabled
2. **API Key**: Create an API key with permissions for:
   - Managing threat intelligence indices
   - Creating and managing detection rules (Kibana privileges)
3. **OpenCTI Stream**: Configure a live stream in OpenCTI that includes indicators and observables

## Installation

### Docker

```bash
docker-compose up -d
```

### Manual

1. Install dependencies:
```bash
pip install -r src/requirements.txt
```

2. Set environment variables or create a `config.yml` file

3. Run the connector:
```bash
python src/main.py
```

## Pattern Type Support

The connector automatically creates vocabulary entries in OpenCTI for Elastic-specific pattern types:

- **kql**: Kibana Query Language for simplified queries
- **lucene**: Full Lucene query syntax for advanced searching
- **eql**: Event Query Language for event-based searches and correlations
- **esql**: Elasticsearch SQL for SQL-like queries

These can be used when creating indicators in OpenCTI with custom patterns.

## Data Flow

1. **Observables**: Converted to ECS threat indicators in Elasticsearch
2. **Indicators without patterns**: Extracted observables are converted to threat indicators
3. **Indicators with patterns**: 
   - Created as detection rules in Elastic Security
   - Also stored as threat indicators for reference

## Troubleshooting

- Check connector logs for connection issues
- Verify API key permissions in Elasticsearch
- Ensure the OpenCTI stream includes the required entity types
- For SSL issues, set `ELASTIC_SECURITY_VERIFY_SSL=false` for testing (not recommended for production)
