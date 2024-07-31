# Internal Enrichment Intelfinder Connector

This connector is designed for integration with the OpenCTI platform and [Intelfinder](https://intelfinder.io/). The integration imports Intelfinder alerts and converts them into OpenCTI incidents. Applicable `elements` are transformed into their related Stix objects and linked to the parent incident. 

## Installation

### Requirements

- OpenCTI Platform >= 6.2.9
- Intelfinder Subscription and [API Token](https://dash.intelfinder.io/integrations.php?i=api)
- Intelfinder API enabled

### Configuration

Configuration parameters are provided using environment variables. Some of them are placed directly in the `docker-compose.yml` since they are not expected to be modified by final users once defined by the developer of the connector.

#### Docker Environment Variables (Set in `docker-compose.yml`)

| Docker envvar             | Mandatory | Description                            |
| ------------------------- | --------- | -------------------------------------- |

#### User Configuration Variables (Set in `.env` file)

| Docker envvar                       | Mandatory | Description                                                                                                                                                                                                         |
| ----------------------------------- | --------- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `OPENCTI_URL`                       | Yes       | The URL of the OpenCTI platform. Example: `http://opencti:8080`                                                                                                                                                     |
| `OPENCTI_TOKEN`                     | Yes       | Connector API token for OpenCTI.                                                                                                                                                                                    |
| `CONNECTOR_NAME`                    | Yes       | A connector name to be shown in OpenCTI.                                                                                                                                                                            |
| `CONNECTOR_SCOPE`                   | Yes       | Supported scope. E.g., `stix2`.                                                                                                                                                                                     |
| `CONNECTOR_ID`                      | Yes       | A unique `UUIDv4` for this connector.                                                                                                                                                                               |
| `CONNECTOR_LOG_LEVEL`               | Yes       | Log level (`debug`, `info`, `warning`, `error`).                                                                                                                                                                    |
| `CONNECTOR_RUN_EVERY`               | Yes       | Frequency of connector execution. The time unit is represented by a single character at the end of the string: d for days, h for hours, m for minutes, and s for seconds. e.g., `30s` is 30 seconds. `1d` is 1 day. |
| `CONNECTOR_UPDATE_EXISTING_DATA`    | Yes       | Whether to update existing data (e.g., `true` or `false`).                                                                                                                                                          |
| `INTELFINDER_TOKEN`                 | Yes       | Token for Intelfinder access.                                                                                                                                                                                       |
| `INTELFINDER_LABELS`                | Yes       | Labels for Intelfinder data. (e.g., `intelfinder,osint`)                                                                                                                                                            |
| `INTELFINDER_MARKING_REFS`          | Yes       | TLP Marking Refs e.g., `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`                                                                                                                                             |
| `INTELFINDER_SEED_ALERT_ID`         | No        | Intelfinder Seed Alert ID, Provide initial Alert ID to start import from (e.g., `64d02b1e8592e8209a077bf2`)                                                                                                         |

### Supported Stix2 Objects

- `URL`, `DomainName`, `IPv4Address`, `IPv6Address`, `Note`, `UserAccount`

### Supported OpenCTI Custom Objects

- `CustomObjectCaseIncident`, `CustomObjectTask`

## Additional Details
Intelfinder occassionaly will create a large content payload. The code supports logic to TRUNCATE the payload in the event it is larger than 80% of the RabbitMQ Default maximum. The following message will be in place where content is TRUNCATED: `TRUNCATED DUE TO SIZE LIMIT, CHECK INTELFINDER FOR FULL CONTENT.`. While the RabbitMQ maximum can be adjusted, there are other dependencies for OpenCTI and STIX objects that have a maximum content size, therefore, this connector is set to the lowest ceiling to limit complications.
