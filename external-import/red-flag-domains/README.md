# OpenCTI Red Flag Domains Connector

## Installation

This connector facilitates the import of domain names from the Red Flag Domains platform into OpenCTI. Red Flag Domains provides lists of very recently registered, probably malicious domain names in French TLDs. More details can be found [here](https://red.flag.domains/).

## Configuration

| Parameter                        | Docker envvar                    | Description                                                                                        |
|----------------------------------|----------------------------------|----------------------------------------------------------------------------------------------------|
| `opencti_url`                    | `OPENCTI_URL`                    | The URL of the OpenCTI platform.                                                                   |
| `opencti_token`                  | `OPENCTI_TOKEN`                  | The default admin token configured in the OpenCTI platform parameters file.                        |
| `connector_id`                   | `CONNECTOR_ID`                   | A valid arbitrary `UUIDv4` that must be unique for this connector.                                 |
| `connector_name`                 | `CONNECTOR_NAME`                 | The name of the connector, can be just "Red Flag Domains"                                          |
| `connector_scope`                | `CONNECTOR_SCOPE`                | Must be `red-flag-domains`.                                                                        |
| `connector_confidence_level`     | `CONNECTOR_CONFIDENCE_LEVEL`     | The default confidence level for created relationships (0 -> 100).                                 |
| `connector_update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | If an entity already exists, update its attributes with information provided by this connector.    |
| `connector_log_level`            | `CONNECTOR_LOG_LEVEL`            | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).      |
| `redflagdomains_url`             | `REDFLAGDOMAINS_URL`             | The Red Flag Domains URL.                                                                          |

## Docker Compose Example

Here is an example of a `docker-compose.yml` entry for the Red Flag Domains connector:

```yaml
connector-redflag-domains:
  image: redflag
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=OPEN_CTI_TOKEN
    - CONNECTOR_ID=CONNECTOR_ID
    - "CONNECTOR_NAME=Red Flag Domains"
    - CONNECTOR_SCOPE=red-flag-domains
    - CONNECTOR_CONFIDENCE_LEVEL=70
    - CONNECTOR_UPDATE_EXISTING_DATA=False
    - CONNECTOR_LOG_LEVEL=info
    - REDFLAGDOMAINS_URL=https://dl.red.flag.domains/daily/
  restart: always
  depends_on:
    - opencti
