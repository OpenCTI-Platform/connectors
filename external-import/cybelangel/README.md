# CybelAngel Connector for OpenCTI

The scope of this connector is : **CybelAngel Threat Intelligence Claimed Attacks**

This connector allows you to automatically import threat intelligence from the CybelAngel platform into OpenCTI. It retrieves claimed attacks and transforms them into STIX 2.1 objects, including intrusion sets, campaigns, victim organizations, and relationships.

## Requirements

- Python 3.10+
- OpenCTI Platform >= 6.7.0

## Configuration

The connector uses a `config.yml` file for configuration. Below is an example:

| Parameter                  | Docker env var             | Mandatory | Description                                                                                              |
|----------------------------|----------------------------|-----------|----------------------------------------------------------------------------------------------------------|
| `opencti_url`              | `OPENCTI_URL`              | Yes       | The URL of the OpenCTI platform.                                                                         |
| `opencti_token`            | `OPENCTI_TOKEN`            | Yes       | The user token configured in the OpenCTI platform.                                                       |
| `connector_id`             | `CONNECTOR_ID`             | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                       |
| `connector_type`           | `CONNECTOR_TYPE`           | No        | `EXTERNAL_IMPORT`                                                                                        |
| `connector_name`           | `CONNECTOR_NAME`           | No        | Name of the connector, e.g., `CybelAngel`.                                                               |
| `connector_scope`          | `CONNECTOR_SCOPE`          | No        | Supported scope: `all`.                                                                                  |
| `connector_log_level`      | `CONNECTOR_LOG_LEVEL`      | No        | Log output for the connector. Defaults to `error`.                                                       |
| `cybelangel_client_id`     | `CYBELANGEL_CLIENT_ID`     | Yes       | The client ID provided by CybelAngel.                                                                    |
| `cybelangel_client_secret` | `CYBELANGEL_CLIENT_SECRET` | Yes       | The client secret provided by CybelAngel.                                                                |
| `cybelangel_api_url`       | `CYBELANGEL_API_URL`       | No        | Defaults to `https://api.cybelangel.com/v1`.                                                             |
| `cybelangel_auth_url`      | `CYBELANGEL_AUTH_URL`      | No        | Defaults to `https://auth.cybelangel.com/oauth/token`.                                                   |
| `cybelangel_interval`      | `CYBELANGEL_INTERVAL`      | No        | Run interval, in hours. Defaults to `1`.                                                                 |
| `cybelangel_fetch_period`  | `CYBELANGEL_FETCH_PERIOD`  | No        | Number of days to look back for claimed attacks. Defaults to `7`. Use `all` to retrieve all the elements |
| `cybelangel_marking`       | `CYBELANGEL_MARKING`       | No        | TLP marking to apply to created entities. Defaults to `TLP:AMBER+STRICT`.                                |

## Behavior

- The connector authenticates with the CybelAngel API using OAuth2.
- It fetches claimed attacks published within the last `fetch_period` days. If the `fetch_period` parameter is set to `all`, the connector fetches all claimed attacks available. 
- Each attack is transformed into a STIX bundle containing:
  - `Intrusion set` for threat actors
  - `Location` for victim countries
  - `Identity` for victim organizations (`Organization`) and industries (`Sector`)
  - `Campaign` for the attack campaign
  - `Relationship` objects linking all entities
- The STIX bundle is then sent to OpenCTI.

## Development Notes

- The `published_at_range` parameter is dynamically calculated using the current date and the `fetch_period`.