# Certificate Search (cert.sh) External Import

This connector integrates [Cert.SH](https://crt.sh/) data with the OpenCTI platform, facilitating automated import and management of cybersecurity information. It allows users to track relevant intelligence and threats by importing domain-related data from Cert.SH into OpenCTI.

## Installation

### Requirements

- OpenCTI Platform version 5.11.13 or higher.

### Configuration

Configuration parameters are set using environment variables. Some are set in the `docker-compose.yml` and are not typically modified by end users. Others are set in the `.env` file (refer to `.env.sample` for examples).

#### Connector Configuration in `docker-compose.yml`

| Docker envvar                    | Mandatory | Description                                                                                                                                                                       |
|----------------------------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `OPENCTI_URL`                    | Yes       | URL of the OpenCTI platform. e.g., http://opencti:8080                                                                                                                            |
| `OPENCTI_TOKEN`                  | Yes       | Default admin token for OpenCTI.                                                                                                                                                  |
| `CONNECTOR_NAME`                 | Yes       | Name displayed in OpenCTI. e.g., crtsh                                                                                                                                            |
| `CONNECTOR_SCOPE`                | Yes       | Supported scope, e.g., `stix2`.                                                                                                                                                   |
| `CONNECTOR_ID`                   | Yes       | Unique `UUIDv4` for this connector.                                                                                                                                               |
| `CONNECTOR_LOG_LEVEL`            | Yes       | Log level (`debug`, `info`, `warn`, `error`).                                                                                                                                     |
| `CONNECTOR_RUN_EVERY`            | Yes       | The time unit is represented by a single character at the end of the string: d for days, h for hours, m for minutes, and s for seconds. e.g., `30s` is 30 seconds. `1d` is 1 day. |

#### User-Configurable Settings in `.env` File

| Docker envvar                | Mandatory | Description                                                                          |
|------------------------------|-----------|--------------------------------------------------------------------------------------|
| `CRTSH_DOMAIN`               | Yes       | Domain to search for e.g., google.com                                                |
| `CRTSH_LABELS`               | Yes       | Comma separated list of labels e.g., crtsh,osint                                     |
| `CRTSH_MARKING_REFS`         | Yes       | TLP Marking Refs e.g., TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED                      |
| `CRTSH_IS_EXPIRED`           | Yes       | Filters epired certificates. One of the following: true, false                       |
| `CRTSH_IS_WILDCARD`          | Yes       | Applies a wildcard expression for the Domain. One of the following: true, false      |

### Additional Information

This connector ingests and updates information from Cert.SH, focusing on domain-related cybersecurity data. Users should consider the scope and limitations of the data when utilizing this connector.

#### Environment Variables for Cert.SH Integration
```env
OPENCTI_URL=http://opencti:8080
OPENCTI_TOKEN=[Your token]
CONNECTOR_ID=[UUIDv4]
CONNECTOR_CONFIDENCE_LEVEL=100
CONNECTOR_LOG_LEVEL=info
CONNECTOR_RUN_EVERY=60s
CONNECTOR_UPDATE_EXISTING_DATA=false
CONNECTOR_SCOPE=stix2
CONNECTOR_NAME=crtsh
CRTSH_DOMAIN=[Domain to search, e.g., google.com]
CRTSH_LABELS=crtsh
CRTSH_MARKING_REFS=TLP:WHITE
CRTSH_IS_EXPIRED=false
CRTSH_IS_WILDCARD=false
```

#### Cert.SH Request Format
```bash
https://crt.sh/?q={domain}&output=json
```

#### STIX Objects Overview
These objects represent structured information about cybersecurity threats and indicators. The following STIX objects are created with this integration:

##### 1. X509Certificate
- **Description**: Represents an X.509 Certificate.
- **Properties**:
  - `type`: "x509-certificate".
  - `issuer`: The issuer name of the certificate.
  - `validity_not_before`: Start date of certificate validity.
  - `validity_not_after`: End date of certificate validity.
  - `subject`: The subject name of the certificate.
  - `serial_number`: The serial number of the certificate.
  - `x509_v3_extensions`: Extensions for the X.509 v3 certificate.
  - `object_marking_refs`: References to marking definitions.
  - `labels`: Custom labels.

##### 2. DomainName
- **Description**: Represents a domain name.
- **Properties**:
  - `type`: "domain-name".
  - `value`: The domain name value.
  - `object_marking_refs`: References to marking definitions.
  - `labels`: Custom labels.

##### 3. EmailAddress
- **Description**: Represents an email address.
- **Properties**:
  - `type`: "email-addr".
  - `value`: The email address value.
  - `object_marking_refs`: References to marking definitions.
  - `labels`: Custom labels.

##### 4. Relationship
- **Description**: Represents a relationship between two STIX objects.
- **Properties**:
  - `type`: "relationship".
  - `relationship_type`: Type of relationship, typically "related-to".
  - `source_ref`: Reference to the source object.
  - `target_ref`: Reference to the target object.
  - `object_marking_refs`: References to marking definitions.
  - `labels`: Custom labels.

##### TODO

Update tests