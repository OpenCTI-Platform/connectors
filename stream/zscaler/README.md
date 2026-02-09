# OpenCTI Zscaler Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

The Zscaler connector streams OpenCTI domain indicators to Zscaler for URL filtering and blocking.

## Table of Contents

- [OpenCTI Zscaler Connector](#opencti-zscaler-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

This connector integrates OpenCTI threat intelligence into the Zscaler environment by managing domain indicators in Zscaler URL categories. It focuses on domain-name indicators and automatically adds or removes domains from a configurable blacklist category.

Key features:
- Real-time domain indicator management
- Automatic Zscaler configuration activation
- Domain validation before submission
- Classification lookup before blacklisting
- Rate limit handling with automatic retries
- Duplicate domain detection

## Installation

### Requirements

- OpenCTI Platform >= 6.0.0
- Zscaler account with API access
- Zscaler API key, username, and password

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml   | Docker environment variable | Mandatory | Description                                          |
|---------------|--------------|------------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url          | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token        | `OPENCTI_TOKEN`              | Yes       | The default admin token set in the OpenCTI platform. |
| SSL Verify    | ssl_verify   | `OPENCTI_SSL_VERIFY`         | No        | Verify SSL certificates (default: false).            |

### Base connector environment variables

| Parameter                      | config.yml                 | Docker environment variable              | Default          | Mandatory | Description                                                                    |
|--------------------------------|----------------------------|------------------------------------------|------------------|-----------|--------------------------------------------------------------------------------|
| Connector ID                   | id                         | `CONNECTOR_ID`                           |                  | Yes       | A unique `UUIDv4` identifier for this connector instance.                      |
| Connector Type                 | type                       | `CONNECTOR_TYPE`                         | STREAM           | Yes       | Should always be set to `STREAM` for this connector.                           |
| Connector Name                 | name                       | `CONNECTOR_NAME`                         | ZscalerConnector | No        | Name of the connector.                                                         |
| Connector Scope                | scope                      | `CONNECTOR_SCOPE`                        | Zscaler          | Yes       | The scope of the connector.                                                    |
| Live Stream ID                 | live_stream_id             | `CONNECTOR_LIVE_STREAM_ID`               |                  | Yes       | The Live Stream ID of the stream created in the OpenCTI interface.             |
| Live Stream Listen Delete      | live_stream_listen_delete  | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`    | true             | Yes       | Listen to delete events.                                                       |
| Live Stream No Dependencies    | live_stream_no_dependencies| `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES`  | true             | No        | Set to `true` unless synchronizing between OpenCTI platforms.                  |
| Log Level                      | log_level                  | `CONNECTOR_LOG_LEVEL`                    | info             | No        | Determines the verbosity of the logs.                                          |

### Connector extra parameters environment variables

| Parameter        | config.yml            | Docker environment variable | Default           | Mandatory | Description                                         |
|------------------|----------------------|------------------------------|-------------------|-----------|-----------------------------------------------------|
| Username         | zscaler.username     | `ZSCALER_USERNAME`           |                   | Yes       | Zscaler username for API authentication.            |
| Password         | zscaler.password     | `ZSCALER_PASSWORD`           |                   | Yes       | Zscaler password for API authentication.            |
| API Key          | zscaler.api_key      | `ZSCALER_API_KEY`            |                   | Yes       | Zscaler API key.                                    |
| Blacklist Name   | zscaler.blacklist_name | `ZSCALER_BLACKLIST_NAME`   | BLACK_LIST_DYNDNS | Yes       | Name of the Zscaler URL category to manage.         |

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-zscaler:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-zscaler:
    image: opencti/connector-zscaler:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_TYPE=STREAM
      - CONNECTOR_NAME=ZscalerConnector
      - CONNECTOR_SCOPE=Zscaler
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_LIVE_STREAM_ID=ChangeMe
      - CONNECTOR_LIVE_STREAM_LISTEN_DELETE=true
      - CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES=true
      - ZSCALER_USERNAME=ChangeMe
      - ZSCALER_PASSWORD=ChangeMe
      - ZSCALER_API_KEY=ChangeMe
      - ZSCALER_BLACKLIST_NAME=YOUR_CUSTOM_BLACKLIST
    restart: always
    networks:
      - opencti_network

networks:
  opencti_network:
    external: true
```

Start the connector:

```bash
docker compose up -d
```

### Manual Deployment

1. Create `config.yml` based on `config.yml.sample`:

```yaml
opencti:
  url: 'https://your-opencti-instance.com'
  token: 'YOUR_OPENCTI_TOKEN'
  ssl_verify: false

connector:
  name: 'ZscalerConnector'
  id: 'ChangeMe'
  live_stream_id: 'ChangeMe'
  live_stream_listen_delete: true
  scope: 'Zscaler'
  log_level: 'info'

zscaler:
  username: 'YOUR_ZSCALER_USERNAME'
  password: 'YOUR_ZSCALER_PASSWORD'
  api_key: 'YOUR_ZSCALER_API_KEY'
  blacklist_name: 'BLACK_LIST_DYNDNS'
```

2. Install dependencies:

```bash
pip3 install -r requirements.txt
```

3. Start the connector from the `src` directory:

```bash
python3 main.py
```

## Usage

1. Create a Live Stream in OpenCTI (Data Management -> Data Sharing -> Live Streams)
2. Configure the stream to include domain-name indicators
3. Copy the Live Stream ID to the connector configuration
4. Start the connector

The connector will:
- Authenticate with Zscaler API on startup
- Listen for domain indicator create/delete events
- Add domains to the specified blacklist category
- Automatically activate changes in Zscaler

## Behavior

The connector listens to OpenCTI live stream events and manages domains in Zscaler URL categories.

### Data Flow

```mermaid
graph LR
    subgraph OpenCTI
        direction TB
        Stream[Live Stream]
        Indicators[Domain Indicators]
    end

    subgraph Connector
        direction LR
        Listen[Event Listener]
        Validate[Validate Domain]
        Check[Check Classification]
    end

    subgraph Zscaler
        direction TB
        API[Zscaler API]
        Category[URL Category]
        Activate[Activate Changes]
    end

    Stream --> Indicators
    Indicators --> Listen
    Listen --> Validate
    Validate --> Check
    Check --> API
    API --> Category
    Category --> Activate
```

### Event Processing

| Event Type | Action                                       |
|------------|----------------------------------------------|
| create     | Adds domain to Zscaler blacklist category    |
| delete     | Removes domain from Zscaler blacklist        |

### Domain Processing Flow

1. **Pattern Extraction**: Extract domain from STIX pattern `[domain-name:value = 'example.com']`
2. **Validation**: Verify domain format is valid
3. **Classification Lookup**: Check current Zscaler classification
4. **Duplicate Check**: Verify domain not already in blacklist
5. **Add/Remove**: Add or remove domain from URL category
6. **Activation**: Automatically activate Zscaler configuration changes

### Rate Limiting

The connector handles Zscaler API rate limits:
- Maximum 400 requests per hour
- Automatic retry with exponential backoff
- Respects `Retry-After` headers

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

### Common Issues

| Issue                          | Solution                                              |
|--------------------------------|-------------------------------------------------------|
| Authentication failed          | Verify username, password, and API key                |
| Domain already in blacklist    | Normal behavior - domain is skipped                   |
| Invalid domain pattern         | Ensure indicator uses STIX pattern format             |
| Rate limit exceeded (429)      | Connector will automatically retry                    |
| Activation failed (503)        | Connector retries with exponential backoff            |

### FAQ

| Question                                | Answer                                              |
|-----------------------------------------|-----------------------------------------------------|
| What if a domain is already blocked?    | The connector checks and skips duplicates           |
| Can I use multiple blacklists?          | No, one blacklist per connector instance            |
| Does it handle rate limits?             | Yes, with automatic retries                         |

## Additional information

- **Supported Indicators**: Only `domain-name` type indicators
- **Pattern Format**: Must use STIX pattern `[domain-name:value = 'example.com']`
- **API Endpoint**: Uses `zsapi.zscalertwo.net` - adjust if using different Zscaler cloud
- **Session Management**: Automatic re-authentication when session expires
- **Activation**: Changes are automatically activated after each operation
