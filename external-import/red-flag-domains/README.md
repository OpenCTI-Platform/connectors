# OpenCTI Red Flag Domains Connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

## Installation

This connector facilitates the import of domain names from the Red Flag Domains platform into OpenCTI. Red Flag Domains provides lists of very recently registered, probably malicious domain names in French TLDs. More details can be found [here](https://red.flag.domains/).

## Configuration

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

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
    - CONNECTOR_LOG_LEVEL=info
    - REDFLAGDOMAINS_URL=https://dl.red.flag.domains/daily/
  restart: always
  depends_on:
    - opencti
