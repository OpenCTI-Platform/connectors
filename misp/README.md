# OpenCTI MISP Connector

## Installation

The MISP connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings. 

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a Docker with the image `opencti/connector-misp:latest`. We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI. 

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

| Parameter                         | Docker envvar                      | Mandatory    | Description                                                                                         |
| --------------------------------- | --------------------------------- | ------------ | --------------------------------------------------------------------------------------------------- |
| `opencti-url`                     | `OPENCTI_URL`                     | Yes          | The URL of the OpenCTI platform.                                                                    |
| `opencti-token`                   | `OPENCTI_TOKEN`                   | Yes          | The default admin token configured in the OpenCTI platform parameters file.                         |
| `connector-id`                    | `CONNECTOR_ID`                    | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                  |
| `connector-type`                  | `CONNECTOR_TYPE`                  | Yes          | Must be `EXTERNAL_IMPORT` (this is the connector type).                                             |
| `connector-name`                  | `CONNECTOR_NAME`                  | Yes          | The name of the MISP instance, to identify it if you have multiple MISP connectors.                 |
| `connector-scope`                 | `CONNECTOR_SCOPE`                 | Yes          | Must be `misp`, not used in this connector.                                                         |
| `connector-confidence_level`      | `CONNECTOR_CONFIDENCE_LEVEL`      | Yes          | The default confidence level for created relationships (a number between 1 and 4).                  |
| `connector-update_existing_data`  | `CONNECTOR_UPDATE_EXISTING_DATA`  | Yes          | If an entity already exists, update its attributes with information provided by this connector.     |
| `connector-log_level`             | `CONNECTOR_LOG_LEVEL`             | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).       |
| `misp-url`                        | `MISP_URL`                        | Yes          | The MISP instance URL.                                                                              |
| `misp-key`                        | `MISP_KEY`                        | Yes          | The MISP instance key.                                                                              |           
| `misp-ssl_verify`                 | `MISP_SSL_VERIFY`                 | Yes          | A boolean (`True` or `False`), check if the SSL certificate is valid when using `https`.            |
| `misp-create_reports`             | `MISP_CREATE_REPORTS`             | Yes          | A boolean (`True` or `False`), create reports for each imported MISP event.                         |
| `misp-report_class`               | `MISP_REPORT_CLASS`               | No           | If `create_reports` is `True`, specify the `report_class` (category), default is `MISP Event`       |
| `misp-import_from_date`           | `MISP_IMPORT_FROM_DATE`           | No           | A date formatted `YYYY-MM-DD`, only import events created after this date.                          | 
| `misp-import_tags`                | `MISP_IMPORT_TAGS`                | No           | A list of tags separated with `,`, only import events with these tags.                              |
| `misp-import_creator_orgs`        | `MISP_IMPORT_CREATOR_ORGS`        | No           | A list of org identifiers separated with `,`, only import events created by these orgs.             |
| `misp-import_owner_orgs`          | `MISP_IMPORT_OWNER_ORGS`          | No           | A list of org identifiers separated with `,`, only import events owned by these orgs                |
| `misp-import_distribution_levels` | `MISP_IMPORT_DISTRIBUTION_LEVELS` | No           | A list of distribution levels separated with `,`, only import events with these distribution levels.|
| `misp-import_threat_levels`       | `MISP_IMPORT_THREAT_LEVELS`       | No           | A list of threat levels separated with `,`, only import events with these threat levels.            |
| `misp-interval`                   | `MISP_INTERVAL`                   | Yes          | Check for new event to import every `n` minutes.                                                    |

## Behavior

The MISP connector will check all new events or latest modified event since the last run for import. The import process has the following steps:

- Iterate other MISP events to import with the given parameters and on **modified events since the last run**.
- Convert each associated galaxy or tags to OpenCTI entities: `Threat actors` / `Intrusion sets` / `Malwares` / `Attack Patterns`).
- Convert each attribute to `Indicators`.
- Import all `Indicators`, `Threat actors`, `Intrusion sets`, `Malwares` and `Attack Patterns`.
- Create `indicates` relationships between the `Indicators` and `Threat actors` / `Malwares`.
- Create `uses` relationships between `Threat actors` / `Intrusion sets` / `Malwares` and `Attack patterns`.
- Create `indicates` relationships between the previously created `uses` relationships.