# OpenCTI MISP Intel Connector

| Status | Date | Comment |
|--------|------|---------|
| Filigran Verified | -    | -       |

The MISP Intel connector streams threat intelligence from OpenCTI to MISP, automatically creating, updating, and deleting MISP events based on OpenCTI containers.

## Table of Contents

- [OpenCTI MISP Intel Connector](#opencti-misp-intel-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Mappings](#mappings)
    - [Container Field Mapping](#container-field-mapping)
    - [Threat Level Calculation](#threat-level-calculation)
    - [Entity to Galaxy Mapping](#entity-to-galaxy-mapping)
    - [Indicator Pattern Mapping](#indicator-pattern-mapping)
    - [Observable to MISP Object Mapping](#observable-to-misp-object-mapping)
    - [Identity and Location Mapping](#identity-and-location-mapping)
    - [Tag Generation](#tag-generation)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

This connector streams threat intelligence from OpenCTI to MISP, automatically creating, updating, and deleting MISP events based on OpenCTI containers (reports, groupings, and case management objects).

Key features:
- Real-time streaming of OpenCTI containers to MISP
- Comprehensive STIX 2.1 to MISP format conversion
- Support for all OpenCTI entity types and observables
- Advanced mapping of OpenCTI entities to MISP galaxies
- Full conversion of STIX patterns to MISP attributes
- STIX 2.1 sightings support
- Bidirectional linking via external references
- Configurable distribution and threat levels
- Proxy support for enterprise environments
- Queue-based architecture to handle large containers without stream timeouts

## Installation

### Requirements

- OpenCTI Platform >= 6.4.0
- Python >= 3.10
- MISP instance with API access
- Valid API keys for both OpenCTI and MISP

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-misp-intel:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
  connector-misp-intel:
    image: opencti/connector-misp-intel:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=ChangeMe
      - CONNECTOR_ID=ChangeMe
      - CONNECTOR_NAME=MISP Intel
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_LIVE_STREAM_ID=ChangeMe
      - MISP_URL=https://misp.example.com
      - MISP_API_KEY=ChangeMe
      - MISP_SSL_VERIFY=true
      - MISP_DISTRIBUTION_LEVEL=1
      - MISP_THREAT_LEVEL=2
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

1. Create a Live Stream in OpenCTI (Data Management -> Data Sharing -> Live Streams)
2. Configure the stream to include containers (reports, groupings, cases)
3. Copy the Live Stream ID to the connector configuration
4. Start the connector

## Behavior

The connector listens to OpenCTI live stream events and synchronizes containers to MISP events.

### Data Flow

```mermaid
graph LR
    subgraph OpenCTI
        direction TB
        Stream[Live Stream]
        Containers[Container Events]
    end

    subgraph Connector
        direction LR
        Listen[Event Listener]
        Queue[Work Queue]
        Worker[Worker Thread]
        Convert[STIX to MISP Converter]
    end

    subgraph MISP
        direction TB
        API[MISP API]
        Events[MISP Events]
    end

    Stream --> Containers
    Containers --> Listen
    Listen --> Queue
    Queue --> Worker
    Worker --> Convert
    Convert --> API
    API --> Events
```

### Event Processing

| Event Type | Action                                       |
|------------|----------------------------------------------|
| create     | Creates MISP event, adds external reference  |
| update     | Updates MISP event (or creates if not found) |
| delete     | Deletes or blocklists MISP event, removes external reference if container still exists |

When a marking or a report type is removed from a container, the update event of the stream is used to remove the corresponding MISP event tag. Other tags (labels, tags added manually in MISP) are not removed.

### Supported Container Types

| OpenCTI Container Type | STIX Type               | MISP Event Created |
|------------------------|-------------------------|--------------------|
| Report                 | report                  | Yes                |
| Grouping               | grouping                | Yes                |
| Case-Incident          | case-incident / x-opencti-case-incident | Yes |
| Case-RFI               | case-rfi / x-opencti-case-rfi | Yes          |
| Case-RFT               | case-rft / x-opencti-case-rft | Yes          |

## Mappings

### Container Field Mapping

| OpenCTI Field           | MISP Field       | Description                              |
|-------------------------|------------------|------------------------------------------|
| Container Name          | Event Info       | Event title                              |
| Created Date            | Event Date       | Creation timestamp                       |
| Modified Date           | Event Timestamp  | Last modification timestamp              |
| Created By (Author)     | Orgc (Creator Org) | Organization that created the content  |
| Configured Owner Org    | Org (Owner Org)  | Organization that owns the event         |
| Calculated Threat Level | Threat Level ID  | Mapped based on indicator/observable scores |
| Labels                  | Tags             | Container labels as event tags           |
| Markings                | Tags             | Container markings of the types set in `MISP_MARKING_TYPES_TO_CONVERT` as event tags |
| Report Types            | Tags             | Report types as `report-type:*` event tags |
| Description             | Comment Attribute| Added as comment attribute               |
| Analysis Status         | Analysis         | Always set to 2 (Completed)              |

### Threat Level Calculation

The MISP threat level is dynamically calculated based on the average `x_opencti_score` of all indicators and observables in the container:

| Average Score | MISP Threat Level |
|---------------|-------------------|
| >= 75         | 1 (High)          |
| >= 50         | 2 (Medium)        |
| >= 25         | 3 (Low)           |
| < 25          | 4 (Undefined)     |

If no scores are found, the connector falls back to the container's own `confidence` attribute (as set in OpenCTI), or 50 (Low) when it is not set:

| Confidence Level | MISP Threat Level |
|------------------|-------------------|
| >= 80            | 1 (High)          |
| >= 60            | 2 (Medium)        |
| >= 30            | 3 (Low)           |
| < 30             | 4 (Undefined)     |

### Entity to Galaxy Mapping

The connector maps OpenCTI entities to MISP galaxies for proper contextual tagging:

| STIX/OpenCTI Entity Type | MISP Galaxy Type                    | Notes                                          |
|--------------------------|-------------------------------------|------------------------------------------------|
| threat-actor             | threat-actor                        | Direct mapping                                 |
| intrusion-set            | threat-actor                        | Also adds alias tags for known aliases         |
| malware                  | malware                             | Direct mapping                                 |
| tool                     | tool                                | Direct mapping                                 |
| attack-pattern           | mitre-attack-pattern                | Formatted as "Name - TechniqueID" when MITRE ID available |
| campaign                 | mitre-campaign                      | MITRE campaign galaxy                          |
| course-of-action         | mitre-course-of-action              | MITRE mitigation galaxy                        |
| infrastructure           | infrastructure                      | Direct mapping                                 |
| incident                 | incident                            | Direct mapping                                 |
| x-opencti-incident       | incident                            | OpenCTI incident type                          |
| x-opencti-case-incident  | incident                            | Case incident mapping                          |
| x-mitre-data-source      | mitre-data-source                   | MITRE data source galaxy                       |
| x-mitre-data-component   | mitre-data-component                | MITRE data component galaxy                    |
| vulnerability            | branded-vulnerability               | Only for CVE-formatted names                   |
| identity (organization)  | target-information / sector         | Based on identity_class                        |
| identity (class/sector)  | sector                              | Industry sectors                               |
| location (country)       | country                             | Country-level locations                        |
| location (region)        | region                              | Regional locations                             |

### Indicator Pattern Mapping

The connector parses STIX 2.1 indicator patterns and maps them to MISP attribute types:

| STIX Pattern Type              | MISP Type         | MISP Category       |
|--------------------------------|-------------------|---------------------|
| ipv4-addr:value                | ip-dst            | Network activity    |
| ipv6-addr:value                | ip-dst            | Network activity    |
| domain-name:value              | domain            | Network activity    |
| hostname:value                 | hostname          | Network activity    |
| url:value                      | url               | Network activity    |
| email-addr:value               | email-src         | Network activity    |
| mac-addr:value                 | mac-address       | Network activity    |
| autonomous-system              | AS                | Network activity    |
| file:hashes.MD5                | md5               | Payload delivery    |
| file:hashes.SHA-1              | sha1              | Payload delivery    |
| file:hashes.SHA-256            | sha256            | Payload delivery    |
| file:hashes.SHA-512            | sha512            | Payload delivery    |
| file:hashes.SSDEEP             | ssdeep            | Payload delivery    |
| file:name                      | filename          | Payload delivery    |
| file:size                      | size-in-bytes     | Payload delivery    |
| file:mime_type                 | mime-type         | Payload delivery    |
| process:pid                    | process-pid       | Artifacts dropped   |
| process:name                   | process-name      | Artifacts dropped   |
| process:command_line           | command-line      | Artifacts dropped   |
| windows-registry-key:key       | regkey            | Artifacts dropped   |
| windows-registry-value-type    | regkey\|value     | Artifacts dropped   |
| x509-certificate:serial_number | x509-fingerprint-sha1 | Payload delivery |
| user-account:account_login     | username          | Other               |
| mutex:name                     | mutex             | Artifacts dropped   |
| network-traffic:src_port       | port              | Network activity    |
| network-traffic:dst_port       | port              | Network activity    |
| network-traffic:protocols      | protocol          | Network activity    |
| software:name                  | filename          | Other               |
| software:vendor                | text              | Other               |
| software:version               | version           | Other               |

### Observable to MISP Object Mapping

STIX observables are converted to MISP objects with their associated attributes:

| STIX Observable Type     | MISP Object Type     | Attributes Included                                           |
|--------------------------|----------------------|---------------------------------------------------------------|
| file                     | file                 | filename, md5, sha1, sha256, sha512, ssdeep, size-in-bytes, mimetype |
| network-traffic          | network-connection   | src-port, dst-port, protocol                                  |
| process                  | process              | pid, name, command-line                                       |
| windows-registry-key     | registry-key         | key, value                                                    |
| x509-certificate         | x509                 | serial-number, issuer, subject                                |
| user-account             | user-account         | username, display-name, account-type                          |
| email-message            | email                | from, to, subject, email-body                                 |
| mutex                    | mutex                | name                                                          |
| software                 | software             | name, vendor, version                                         |
| domain-name              | domain-ip            | domain                                                        |
| ipv4-addr                | ip-port              | ip                                                            |
| ipv6-addr                | ip-port              | ip                                                            |
| url                      | url                  | url                                                           |
| autonomous-system        | asn                  | asn, description                                              |
| mac-addr                 | mac-address          | mac-address                                                   |
| directory                | directory            | path                                                          |
| artifact                 | artifact             | payload, mimetype                                             |

### Identity and Location Mapping

**Identity Mapping** (based on `identity_class`):

| Identity Class | MISP Galaxy           | Notes                                    |
|----------------|-----------------------|------------------------------------------|
| organization   | target-information    | Or `sector` if x_opencti_type is sector  |
| class          | sector                | Industry sectors                         |
| individual     | target-information    | Individuals                              |
| system         | target-information    | Technical systems                        |
| group          | threat-actor or target-information | Based on labels (APT, threat) |

**Location Mapping** (based on `x_opencti_location_type`):

| Location Type        | MISP Galaxy           |
|----------------------|-----------------------|
| country              | country               |
| region               | region                |
| city                 | target-information    |
| administrative-area  | target-information    |
| position             | target-information    |

### Tag Generation

The connector generates various tags for MISP events:

| Tag Type                | Format                           | Example                                    |
|-------------------------|----------------------------------|--------------------------------------------|
| Source tag              | `source:opencti`                 | `source:opencti`                           |
| Container type          | `opencti:type:{type}`            | `opencti:type:report`                      |
| Confidence level        | `confidence:{level}`             | `confidence:85`                            |
| TLP marking             | `tlp:{level}`                    | `tlp:amber+strict`                         |
| PAP marking             | `PAP:{level}`                    | `PAP:AMBER`                                |
| Report type             | `report-type:{type}`             | `report-type:threat-report`                |
| Galaxy clusters         | `misp-galaxy:{type}="{value}"`   | `misp-galaxy:threat-actor="APT29"`         |
| MITRE ATT&CK            | `misp-galaxy:mitre-attack-pattern="{name} - {id}"` | `misp-galaxy:mitre-attack-pattern="Spearphishing - T1566"` |
| Threat actor aliases    | `threat-actor-alias:{alias}`     | `threat-actor-alias:Cozy Bear`             |
| Observable type         | `observable-type:{type}`         | `observable-type:ipv4-addr`                |
| Threat level            | `threat-level:{level}`           | `threat-level:high`                        |
| Infrastructure type     | `infrastructure:c2`              | `infrastructure:c2`                        |
| Standard entities       | `opencti:{entity_type}:{name}`   | `opencti:channel:Telegram`                 |
| MITRE extensions        | `mitre:{type}:{name}`            | `mitre:data-source:Network Traffic`        |

### Distribution Levels

| Level | Description                |
|-------|----------------------------|
| 0     | Your organisation only     |
| 1     | This community only        |
| 2     | Connected communities      |
| 3     | All communities            |

### Threat Levels

| Level | Description |
|-------|-------------|
| 1     | High        |
| 2     | Medium      |
| 3     | Low         |
| 4     | Undefined   |

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

### Common Issues

| Issue                          | Solution                                              |
|--------------------------------|-------------------------------------------------------|
| Connection failed              | Verify URLs and API keys are correct                  |
| SSL errors                     | Set `MISP_SSL_VERIFY=false` for self-signed certs     |
| Missing events                 | Check container type filter configuration             |
| Conversion errors              | Check logs for specific entity conversion issues      |
| Stream timeouts                | The connector uses a queue-based architecture to prevent timeouts |
| Queue full warnings            | The work queue has a limit of 100 items; reduce stream volume or check processing speed |

## Additional information

- **UUID Mapping**: The OpenCTI container ID is used directly as the MISP event UUID for seamless bidirectional mapping
- **Bidirectional Linking**: External references are added to OpenCTI containers pointing to created MISP events
- **Soft Delete**: When `MISP_HARD_DELETE=false`, deleted event UUIDs are added to MISP blocklist to prevent re-importation
- **Hard Delete**: When `MISP_HARD_DELETE=true` (default), events are permanently deleted and can be re-imported later
- **External Reference Cleanup**: When a container is removed from the stream filter (but still exists in OpenCTI), the connector removes the MISP external reference from the container
- **Duplicate Prevention**: The converter tracks added attributes to prevent duplicate MISP attributes with the same type and value
- **Proxy Support**: Configure HTTP/HTTPS proxy for enterprise environments
- **Sightings**: STIX 2.1 sightings are processed and can be attached to MISP attributes
- **Organization Handling**: Creator org (orgc) is extracted from the container's `created_by_ref`, while owner org is configured via `MISP_OWNER_ORG`
