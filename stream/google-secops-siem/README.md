# OpenCTI Google SecOps SIEM Connector

The Google SecOps SIEM connector streams OpenCTI STIX indicators to Google SecOps SIEM as UDM entities for threat detection and correlation.

## Table of Contents

- [OpenCTI Google SecOps SIEM Connector](#opencti-google-secops-siem-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Google Cloud Service Account Setup](#google-cloud-service-account-setup)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
    - [Dissemination assurance (deployment write-back)](#dissemination-assurance-deployment-write-back)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

This connector enables the dissemination of OpenCTI STIX indicators into Google SecOps SIEM. The connector consumes indicators from an OpenCTI stream, converts them to [UDM entities](https://cloud.google.com/chronicle/docs/reference/udm-field-list#securityresult), and pushes them into Google SecOps SIEM using the [entities.import](https://cloud.google.com/chronicle/docs/reference/rest/v1alpha/projects.locations.instances.entities/import) API.

Key features:
- Real-time synchronization of STIX indicators to Google SecOps SIEM
- Conversion to Unified Data Model (UDM) format
- Support for multiple observable types (IP, Domain, URL, File)
- Delete event handling for indicator lifecycle management
- Includes dashboard template for visualization

## Installation

### Requirements

- Python 3.11.x (not compatible with 3.12 and above)
- OpenCTI Platform >= 6.4.x
- pycti >= 6.4.x
- Google Cloud service account with SecOps SIEM API access

### Google Cloud Service Account Setup

Follow these steps to create and configure a service account for the connector:

1. **Enable the Chronicle API**
   In the Google Cloud project linked to your SecOps instance, enable the Chronicle API (`chronicle.googleapis.com`).
   Navigate to **APIs & Services > Library**, search for "Chronicle API", and click **Enable**.

2. **Create a service account**
   Go to **IAM & Admin > Service Accounts** and click **Create Service Account**.
   Give it a descriptive name (e.g. `opencti-secops-connector`) and proceed to the next step.

3. **Grant the Chronicle API Editor role**
   On the "Grant this service account access to project" step, assign the role **Chronicle API Editor** (`roles/chronicle.editor`).
   This role grants the permissions required to create, update, and delete UDM entities via the Chronicle API.

4. **Create and download a JSON key**
   Once the service account is created, go to its **Keys** tab, click **Add Key > Create new key**, select **JSON**, and download the file.
   This JSON file contains all the fields required by the connector configuration (`private_key_id`, `private_key`, `client_email`, `client_id`, etc.).

5. **Configure the connector**
   Use the values from the downloaded JSON key file to populate the connector environment variables:
   - `SECOPS_SIEM_PROJECT_REGION` : Your SecOps instance region (e.g. `us`, `europe`).
   - `SECOPS_SIEM_PROJECT_ID` : The Google Cloud project ID linked to your SecOps instance.
   - `SECOPS_SIEM_PROJECT_INSTANCE` :  Your SecOps customer ID (found under **Settings > SIEM Settings > Profile** in the SecOps UI).
   - All other `SECOPS_SIEM_*` variables map directly to fields in the service account JSON key.

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

| Parameter                   | config.yml                  | Docker environment variable             | Default | Mandatory | Description                                                                |
|-----------------------------|-----------------------------|-----------------------------------------|---------|-----------|----------------------------------------------------------------------------|
| Connector ID                | id                          | `CONNECTOR_ID`                          |         | Yes       | A unique `UUIDv4` identifier for this connector instance.                  |
| Connector Type              | type                        | `CONNECTOR_TYPE`                        | STREAM  | Yes       | Should always be set to `STREAM` for this connector.                       |
| Connector Name              | name                        | `CONNECTOR_NAME`                        |         | Yes       | Name of the connector.                                                     |
| Live Stream ID              | live_stream_id              | `CONNECTOR_LIVE_STREAM_ID`              |         | Yes       | The Live Stream ID of the stream created in the OpenCTI interface.         |
| Live Stream Listen Delete   | live_stream_listen_delete   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | true    | Yes       | Listen to delete events for the entity.                                    |
| Live Stream No Dependencies | live_stream_no_dependencies | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | true    | Yes       | Set to `true` unless synchronizing between OpenCTI platforms.              |
| Log Level                   | log_level                   | `CONNECTOR_LOG_LEVEL`                   | info    | No        | Determines the verbosity of the logs: `debug`, `info`, `warn`, or `error`. |

### Connector extra parameters environment variables

| Parameter                 | config.yml                     | Docker environment variable      | Default | Mandatory | Description                                          |
|---------------------------|--------------------------------|----------------------------------|---------|-----------|------------------------------------------------------|
| Google Project Region     | secops_siem.project_region     | `SECOPS_SIEM_PROJECT_REGION`     |         | Yes       | Region where the Google SecOps instance is located.  |
| Google Project ID         | secops_siem.project_id         | `SECOPS_SIEM_PROJECT_ID`         |         | Yes       | GCP Project ID.                                      |
| Google Project Instance   | secops_siem.project_instance   | `SECOPS_SIEM_PROJECT_INSTANCE`   |         | Yes       | Google SecOps customer ID.                           |
| Google Private Key ID     | secops_siem.private_key_id     | `SECOPS_SIEM_PRIVATE_KEY_ID`     |         | Yes       | Service account `private_key_id` value.              |
| Google Private Key        | secops_siem.private_key        | `SECOPS_SIEM_PRIVATE_KEY`        |         | Yes       | Service account `private_key` value.                 |
| Google Client Email       | secops_siem.client_email       | `SECOPS_SIEM_CLIENT_EMAIL`       |         | Yes       | Service account `client_email` value.                |
| Google Client ID          | secops_siem.client_id          | `SECOPS_SIEM_CLIENT_ID`          |         | Yes       | Service account `client_id` value.                   |
| Google Auth URI           | secops_siem.auth_uri           | `SECOPS_SIEM_AUTH_URI`           |         | Yes       | Service account `auth_uri` value.                    |
| Google Token URI          | secops_siem.token_uri          | `SECOPS_SIEM_TOKEN_URI`          |         | Yes       | Service account `token_uri` value.                   |
| Google Auth Provider Cert | secops_siem.auth_provider_cert | `SECOPS_SIEM_AUTH_PROVIDER_CERT` |         | Yes       | Service account `auth_provider_x509_cert_url` value. |
| Google Client Cert URL    | secops_siem.client_cert_url    | `SECOPS_SIEM_CLIENT_CERT_URL`    |         | Yes       | Service account `client_x509_cert_url` value.        |

For `secops_siem.private_key` in `config.yml`, prefer YAML multiline format to preserve PEM newlines:

```yaml
secops_siem:
  private_key: |-
    -----BEGIN PRIVATE KEY-----
    ...
    -----END PRIVATE KEY-----
```

The connector also normalizes escaped newlines (`\\n`) if the key is provided through environment variables or single-line values.

## Deployment

### Docker Deployment

Before building the Docker container, ensure you have set the version of `pycti` in `requirements.txt` to match the version of OpenCTI you are running.

Build the Docker image:

```bash
docker build -t opencti/connector-google-secops-siem:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-google-secops-siem:
    image: opencti/connector-google-secops-siem:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=Google SecOps SIEM
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_LIVE_STREAM_ID=ChangeMe
      - CONNECTOR_LIVE_STREAM_LISTEN_DELETE=true
      - CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES=true
      - SECOPS_SIEM_PROJECT_REGION=us
      - SECOPS_SIEM_PROJECT_ID=ChangeMe
      - SECOPS_SIEM_PROJECT_INSTANCE=ChangeMe
      - SECOPS_SIEM_PRIVATE_KEY_ID=ChangeMe
      - SECOPS_SIEM_PRIVATE_KEY=ChangeMe
      - SECOPS_SIEM_CLIENT_EMAIL=ChangeMe
      - SECOPS_SIEM_CLIENT_ID=ChangeMe
      - SECOPS_SIEM_AUTH_URI=ChangeMe
      - SECOPS_SIEM_TOKEN_URI=ChangeMe
      - SECOPS_SIEM_AUTH_PROVIDER_CERT=ChangeMe
      - SECOPS_SIEM_CLIENT_CERT_URL=ChangeMe
    restart: always
```

Start the connector:

```bash
docker compose up -d
```

### Manual Deployment

1. Create `config.yml` based on `config.yml.sample`.

2. Install dependencies:

```bash
pip3 install -r requirements.txt
```

3. Start the connector from the `src` directory:

```bash
python3 main.py
```

## Usage

The connector only supports the ingestion of Indicator entities with a STIX pattern into Google SecOps SIEM. Configure the OpenCTI stream to only expose indicators with a STIX pattern:

1. Create a Live Stream in OpenCTI (Data Management -> Data Sharing -> Live Streams)
2. Configure the stream with filters:
   - Entity type = `Indicator`
   - Pattern type = `stix`
3. Copy the Live Stream ID to the connector configuration
4. Start the connector

## Behavior

The connector listens to OpenCTI live stream events and converts indicators to UDM entities for Google SecOps SIEM.

### Data Flow

```mermaid
graph LR
    subgraph OpenCTI
        direction TB
        Stream[Live Stream]
        Indicators[Indicator Events]
    end

    subgraph Connector
        direction LR
        Listen[Event Listener]
        Convert[Convert to UDM]
    end

    subgraph SecOps
        direction TB
        API[entities.import API]
        SIEM[Google SecOps SIEM]
    end

    Stream --> Indicators
    Indicators --> Listen
    Listen --> Convert
    Convert --> API
    API --> SIEM
```

### Event Processing

| Event Type | Action                                                                                                           |
|------------|------------------------------------------------------------------------------------------------------------------|
| create     | Creates UDM entity in Google SecOps SIEM                                                                         |
| update     | Updates UDM entity in Google SecOps SIEM                                                                         |
| delete     | Nothing: Google SecOps cannot delete imported entities, they stop matching at the end of their validity interval |

### Entity Mapping

| OpenCTI Observable Type | Google SecOps UDM Entity Type |
|-------------------------|-------------------------------|
| IPv4-Addr               | IP_ADDRESS                    |
| IPv6-Addr               | IP_ADDRESS                    |
| Domain-Name             | DOMAIN_NAME                   |
| Hostname                | DOMAIN_NAME                   |
| URL                     | URL                           |
| File                    | FILE                          |

### UDM Field Mapping

| Google SecOps UDM Field             | OpenCTI Source                                   |
|-------------------------------------|--------------------------------------------------|
| metadata.vendor_name                | `FILIGRAN`                                       |
| metadata.product_name               | `OPENCTI`                                        |
| metadata.collected_timestamp        | UTC timestamp when indicator is submitted        |
| metadata.product_entity_id          | Indicator `identifier` value                     |
| metadata.description                | Indicator `description` value                    |
| metadata.interval.start_time        | Indicator `valid_from` value                     |
| metadata.interval.end_time          | Indicator `valid_until` value                    |
| metadata.entity_type                | Mapped from observable type                      |
| metadata.threat.confidence_details  | Indicator `confidence` value                     |
| metadata.threat.confidence_score    | Indicator `confidence` value                     |
| metadata.threat.risk_score          | Indicator `score` value                          |
| metadata.threat.category_details    | Indicator associated labels                      |
| metadata.threat.url_back_to_product | OpenCTI URL link to the indicator                |

### Dissemination assurance (deployment write-back)

The connector reports to OpenCTI whether each indicator was accepted by Google SecOps. The status is stored on the
`deployed-on` relationship between the indicator and the `Google SecOps SIEM` Security Platform entity (created if it
does not exist), and detection hits are counted with a sighting of the indicator on that entity.

| When                                       | Reported to OpenCTI                                                                                  |
|--------------------------------------------|------------------------------------------------------------------------------------------------------|
| Indicator ingested in Google SecOps        | `deployed`, with the STIX id of the indicator (`metadata.product_entity_id` of its entities) as external id |
| Indicator rejected by Google SecOps        | `failed`, with the API error, the HTTP status and the Google SecOps response                         |
| Indicator without any supported observable | Nothing: the indicator is never ingested                                                             |
| Delete event                               | Nothing: imported entities cannot be deleted, they stay live until their `valid_until`               |
| Periodic run, `pending` (analyst retry)    | The indicator is ingested again and reported `deployed` or `failed`                                  |
| Hits                                       | IoC matches whose artifact (domain, destination IP address, file hash) is the value of a deployed indicator |

- **No read-back**: the Google SecOps API cannot list nor delete the imported UDM entities, so the presence of the
  indicators is not reconciled: they are never reported `active` or `removed` by the connector, and a withdrawal
  requested in OpenCTI cannot be applied (the entity stops matching at the end of its validity interval, after which
  OpenCTI flags the deployment `expired`).
- **Periodic run**: every `DEPLOYMENT_RECONCILIATION_INTERVAL` minutes, the `pending` deployments (retry requested by an
  analyst in OpenCTI) are ingested again and the hits are collected.
- **Hits**: the IoC matches of the instance (`legacySearchEnterpriseWideIoCs`, at most 10,000 per request) matched since
  the previous run are read. A truncated time window is halved and read oldest first (at most 8 requests per run); when
  the budget runs out, the next run resumes at the first window left unread, so no match is lost. A match counts one hit for every deployed indicator whose value is its artifact (domain,
  destination IP address, MD5, SHA-1 or SHA-256 hash), at the time Google SecOps last saw the artifact in the
  environment; hits already reported are never counted twice. URL indicators have no IoC match artifact and get no hit.
- **IOC validation requests**: OpenAEV runs the benign validation tests requested in OpenCTI and writes their results;
  the requests only target indicators this connector reports `deployed`. The retry requested by an analyst
  (`pending`) is handled by the periodic run.
- **Permissions**: hit reporting needs the `chronicle.legacies.legacySearchEnterpriseWideIoCs` IAM permission on the
  Google SecOps instance, in addition to the entity import permission. Check that the role granted to the service
  account includes it (or add a custom role); without it, set `HITS_REPORTING_ENABLED=false`.
- **Graceful degradation**: on OpenCTI platforms without the deployment write-back API the feature is a no-op (logged
  once). Write-back errors are logged as warnings and never block the dissemination.

| Environment variable                 | Default              | Description                                                                       |
|--------------------------------------|----------------------|-----------------------------------------------------------------------------------|
| `DEPLOYMENT_REPORTING_ENABLED`       | `true`               | Report the deployment status of the ingested indicators.                          |
| `DEPLOYMENT_RECONCILIATION_INTERVAL` | `60`                 | Minutes between two periodic runs (re-push and hits), `0` disables them.          |
| `HITS_REPORTING_ENABLED`             | `true`               | Report the IoC match hits of the deployed indicators.                             |
| `SECURITY_PLATFORM_NAME`             | `Google SecOps SIEM` | Name of the Security Platform entity in OpenCTI.                                  |
| `SECURITY_PLATFORM_TYPE`             | `SIEM`               | Type of the Security Platform entity (`security_platform_type_ov`).               |
| `SECURITY_PLATFORM_ID`               |                      | Id of an existing Security Platform entity, used instead of the name.             |

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

Log output includes:
- Event processing status
- UDM entity conversion details
- API request/response information

### Common Issues

| Issue                      | Solution                                                   |
|----------------------------|------------------------------------------------------------|
| Rate limiting (429 errors) | Implement backoff mechanism; check quota limits            |
| OAuth token expiry         | Tokens expire after 1 hour; refresh automatically          |
| Update latency             | Changes reflect in 2-3 hours on dashboard, 5 min on search |
| Authentication errors      | Verify service account credentials                         |
| Logs show `[DEPLOYMENT] Cannot read the detections from the vendor` | The service account lacks `chronicle.legacies.legacySearchEnterpriseWideIoCs`: grant it, or set `HITS_REPORTING_ENABLED=false` |

## Additional information

- **Dashboard**: A dashboard template is included in the `dashboard/` folder for visualizing ingested indicators
- **Quota Limits**: Refer to [service limits documentation](https://cloud.google.com/chronicle/docs/reference/service-limits)
- **Rate Limiting**: See [burst limits FAQ](https://cloud.google.com/chronicle/docs/ingestion/burst-limits#frequently_asked_questions)
- **Token Management**: OAuth tokens expire after 1 hour by default; use `serviceAccounts.generateAccessToken` for custom lifetimes up to 12 hours
- **Update Latency**: IOC updates appear in custom dashboards within 2-3 hours, direct search within 5 minutes
- **Supported Observables**: Domain, Hostname, IPv4, IPv6, URL, File
