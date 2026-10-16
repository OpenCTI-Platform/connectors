# OpenCTI Google Safe Browsing Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

The Google Safe Browsing connector enriches Domain-Name, URL, and Hostname observables by checking them against Google's Safe Browsing threat lists, identifying malware, phishing, and unwanted software threats.

This connector can also be used with Yandex Safe Browsing as an alternative provider.

## Table of Contents

- [OpenCTI Google Safe Browsing Connector](#opencti-google-safe-browsing-connector)
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

Google Safe Browsing is a service that lets client applications check URLs against Google's constantly updated lists of unsafe web resources. These include social engineering sites (phishing and deceptive sites), sites that host malware or unwanted software, and sites that host potentially harmful applications.

This connector integrates Google Safe Browsing with OpenCTI to:
- Check domains, URLs, and hostnames against threat lists
- Flag malicious resources with threat type labels
- Update observable scores based on threat detection
- Add threat descriptions to observables

## Installation

### Requirements

- OpenCTI Platform >= 6.0.6
- Google Safe Browsing API key (from Google Cloud Console) or Yandex Safe Browsing API key (from Yandex Dev Portal)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker), in `config.yml` (for manual deployment) or as environment variables.

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter        | config.yml | Docker environment variable | Default                    | Mandatory | Description                                                                 |
|------------------|------------|-----------------------------|----------------------------|-----------|-----------------------------------------------------------------------------|
| Connector ID     | id         | `CONNECTOR_ID`              |                            | Yes       | A unique `UUIDv4` identifier for this connector instance.                   |
| Connector Name   | name       | `CONNECTOR_NAME`            | Google Safe Browsing       | No        | Name of the connector.                                                      |
| Connector Scope  | scope      | `CONNECTOR_SCOPE`           | Url,Domain-Name,Hostname   | No        | The scope of observables the connector will enrich.                         |
| Log Level        | log_level  | `CONNECTOR_LOG_LEVEL`       | error                      | No        | Determines the verbosity of the logs: `debug`, `info`, `warn`, or `error`.  |
| Auto Mode        | auto       | `CONNECTOR_AUTO`            | false                      | No        | Enables or disables automatic enrichment of observables.                    |
| Max TLP          | max_tlp    | `CONNECTOR_MAX_TLP`         | amber                      | No        | Observables with a higher TLP are not sent to the Safe Browsing API: `clear`, `white`, `green`, `amber`, `amber+strict` or `red`. |

### Connector extra parameters environment variables

| Parameter | config.yml (`safe_browsing`) | Docker environment variable    | Default                               | Mandatory | Description                                                                                          |
|-----------|------------------------------|--------------------------------|---------------------------------------|-----------|------------------------------------------------------------------------------------------------------|
| API Key   | api_key                      | `SAFE_BROWSING_API_KEY`        |                                       | Yes*      | Safe Browsing API key (Google or Yandex). *Unless the deprecated `GOOGLE_SAFE_BROWSING_API_KEY` is set. |
| API URL   | api_url                      | `SAFE_BROWSING_API_URL`        | `https://safebrowsing.googleapis.com` | No        | Safe Browsing API base URL. Use `https://sba.yandex.net` for Yandex.                                 |
| API Key   |                              | `GOOGLE_SAFE_BROWSING_API_KEY` |                                       | No        | **Deprecated**, use `SAFE_BROWSING_API_KEY`. Used only if `SAFE_BROWSING_API_KEY` is unset.          |

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-google-safebrowsing:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-google-safebrowsing:
    image: opencti/connector-google-safebrowsing:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      # - CONNECTOR_NAME=Google Safe Browsing
      # - CONNECTOR_SCOPE=Url,Domain-Name,Hostname
      # - CONNECTOR_LOG_LEVEL=error
      # - CONNECTOR_AUTO=false
      # - CONNECTOR_MAX_TLP=amber
      - SAFE_BROWSING_API_KEY=ChangeMe
      # - SAFE_BROWSING_API_URL=https://safebrowsing.googleapis.com # Use https://sba.yandex.net for Yandex
    restart: always
```

Start the connector:

```bash
docker compose up -d
```

### Manual Deployment

1. Copy `config.yml.sample` to `config.yml` and fill in the values, or set the environment variables.

2. Install dependencies from the `src` directory:

```bash
pip3 install -r requirements.txt
```

3. Start the connector from the `src` directory:

```bash
python3 main.py
```

## Usage

The connector checks observables against Google/Yandex Safe Browsing threat lists.

**Observations → Observables**

Select a Domain-Name, URL, or Hostname observable, then click the enrichment button and choose Google Safe Browsing.

## Behavior

The connector queries the Google/Yandex Safe Browsing API to check if URLs/domains are flagged as threats.

### Data Flow

```mermaid
graph LR
    subgraph OpenCTI Input
        Domain[Domain-Name]
        URL[URL]
        Hostname[Hostname]
    end

    subgraph Google/Yandex Safe Browsing API
        API[Threat Match API v4]
    end

    subgraph OpenCTI Output
        EnrichedObs[Enriched Observable]
        Score[Score: 100]
        Label[Threat Type Label]
        Description[Threat Description]
    end

    Domain --> API
    URL --> API
    Hostname --> API
    API --> EnrichedObs
    EnrichedObs --> Score
    EnrichedObs --> Label
    EnrichedObs --> Description
```

### Threat Types Checked

| Threat Type                      | Description                                         |
|----------------------------------|-----------------------------------------------------|
| MALWARE                          | Sites hosting malicious software                    |
| SOCIAL_ENGINEERING               | Phishing and deceptive sites                        |
| UNWANTED_SOFTWARE                | Sites distributing unwanted software                |
| POTENTIALLY_HARMFUL_APPLICATION  | Sites with potentially harmful applications         |
| THREAT_TYPE_UNSPECIFIED          | Unspecified threat type                             |

### Platform Types Checked

- ANY_PLATFORM (checks across all platforms)

### Threat Entry Types Checked

- URL
- EXECUTABLE
- THREAT_ENTRY_TYPE_UNSPECIFIED

### Enrichment Mapping

| Safe Browsing Data | OpenCTI Property          | Description                              |
|--------------------|---------------------------|------------------------------------------|
| threatType         | Label                     | Applied as label to observable           |
| threatType         | x_opencti_description     | Added to observable description          |
| platformType       | x_opencti_description     | Added to observable description          |
| threatEntryType    | x_opencti_description     | Added to observable description          |
| Match found        | x_opencti_score           | Set to 100 when threat detected          |

### Processing Details

1. **Observable Type Check**: Verifies entity is Domain-Name, URL, or Hostname and is in the connector scope
2. **TLP Check**: Skips observables whose TLP is higher than `CONNECTOR_MAX_TLP`
3. **API Query**: Sends threat match request to Safe Browsing API
4. **Result Processing**: If match found:
   - Sets observable score to 100 (malicious)
   - Adds threat type label
   - Updates description with threat details
5. **Bundle Creation**: Creates and sends STIX bundle with updated observable

### Generated STIX Objects

| Update                | Condition             | Description                              |
|-----------------------|-----------------------|------------------------------------------|
| x_opencti_score       | When threat detected  | Set to 100 indicating malicious          |
| x_opencti_description | When threat detected  | Threat type, platform, and entry type    |
| Label                 | When threat detected  | Threat type name as label                |

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

Log output includes:
- Observable processing status
- Safe Browsing API query details
- Threat match results
- Bundle sending status

## Additional information

- **API Key Required**: Obtain from [Google Cloud Console](https://console.cloud.google.com/apis/credentials) or [Yandex Dev Portal](https://developer.tech.yandex.ru/keys/)
- **Free Tier Available**: Safe Browsing API has a free usage tier
- **Rate Limits**: Subject to Google/Yandex API rate limits
- **Score Assignment**: Flagged observables receive score of 100
- **Label Application**: Threat type is applied as a label for easy filtering
