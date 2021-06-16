# OpenCTI MISP Connector

## Installation

The MISP connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a Docker with the image `opencti/connector-misp:latest`. We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

**Warning**: This connector is compatible with MISP >=2.4.135.3.

| Parameter                         | Docker envvar                     | Mandatory    | Description                                                                                         |
| --------------------------------- | --------------------------------- | ------------ | --------------------------------------------------------------------------------------------------- |
| `opencti_url`                     | `OPENCTI_URL`                     | Yes          | The URL of the OpenCTI platform.                                                                    |
| `opencti_token`                   | `OPENCTI_TOKEN`                   | Yes          | The default admin token configured in the OpenCTI platform parameters file.                         |
| `connector_id`                    | `CONNECTOR_ID`                    | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                  |
| `connector_type`                  | `CONNECTOR_TYPE`                  | Yes          | Must be `EXTERNAL_IMPORT` (this is the connector type).                                             |
| `connector_name`                  | `CONNECTOR_NAME`                  | Yes          | The name of the MISP instance, to identify it if you have multiple MISP connectors.                 |
| `connector_scope`                 | `CONNECTOR_SCOPE`                 | Yes          | Must be `misp`, not used in this connector.                                                         |
| `connector_confidence_level`      | `CONNECTOR_CONFIDENCE_LEVEL`      | Yes          | The default confidence level for created relationships (a number between 1 and 4).                  |
| `connector_update_existing_data`  | `CONNECTOR_UPDATE_EXISTING_DATA`  | Yes          | If an entity already exists, update its attributes with information provided by this connector.     |
| `connector_log_level`             | `CONNECTOR_LOG_LEVEL`             | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).       |
| `misp_url`                        | `MISP_URL`                        | Yes          | The MISP instance URL.                                                                              |
| `misp_reference_url`              | `MISP_REFERENCE_URL`              | Yes          | The MISP instance reference URL (used to create external reference, optional)                       |
| `misp_key`                        | `MISP_KEY`                        | Yes          | The MISP instance key.                                                                              |
| `misp_ssl_verify`                 | `MISP_SSL_VERIFY`                 | Yes          | A boolean (`True` or `False`), check if the SSL certificate is valid when using `https`.            |
| `misp_datetime_attribute`         | `MISP_DATETIME_ATTRIBUTE`         | Yes          | The attribute to be used in filter to query new MISP events.                                        |
| `misp_create_reports`             | `MISP_CREATE_REPORTS`             | Yes          | A boolean (`True` or `False`), create reports for each imported MISP event.                         |
| `misp_create_object_observables`         | `MISP_CREATE_OBJECT_OBSERVABLES`         | Yes          | A boolean (`True` or `False`), create a text observable for each imported MISP object.               |
| `misp_create_observables`         | `MISP_CREATE_OBSERVABLES`         | Yes          | A boolean (`True` or `False`), create an observable for each imported MISP attribute.               |
| `misp_create_indicators`          | `MISP_CREATE_INDICATORS`          | Yes          | A boolean (`True` or `False`), create an indicator for each imported MISP attribute.                |
| `misp_report_class`               | `MISP_REPORT_CLASS`               | No           | If `create_reports` is `True`, specify the `report_class` (category), default is `MISP Event`       |
| `misp_import_from_date`           | `MISP_IMPORT_FROM_DATE`           | No           | A date formatted `YYYY-MM-DD`, only import events created after this date.                          |
| `misp_import_tags`                | `MISP_IMPORT_TAGS`                | No           | A list of tags separated with `,`, only import events with these tags.                              |
| `misp_import_tags_not`            | `MISP_IMPORT_TAGS_NOT`            | No           | A list of tags separated with `,`, to exclude from import.                                          |
| `misp_import_creator_orgs`        | `MISP_IMPORT_CREATOR_ORGS`        | No           | A list of org identifiers separated with `,`, only import events created by these orgs.             |
| `misp_import_owner_orgs`          | `MISP_IMPORT_OWNER_ORGS`          | No           | A list of org identifiers separated with `,`, only import events owned by these orgs                |
| `misp_import_distribution_levels` | `MISP_IMPORT_DISTRIBUTION_LEVELS` | No           | A list of distribution levels separated with `,`, only import events with these distribution levels.|
| `misp_import_threat_levels`       | `MISP_IMPORT_THREAT_LEVELS`       | No           | A list of threat levels separated with `,`, only import events with these threat levels.            |
| `misp_import_only_published`      | `MISP_IMPORT_ONLY_PUBLISHED`      | No           | Import only MISP published events                                                                   |
| `misp_import_with_attachments`    | `MISP_IMPORT_WITH_ATTACHMENTS`    | No           | Import attachment attribute content as a file if it is a PDF.                                    |
| `misp_interval`                   | `MISP_INTERVAL`                   | Yes          | Check for new event to import every `n` minutes.                                                    |

## Behavior

The MISP connector will check all new events or latest modified event since the last run for import. The import process has the following steps:

- Iterate other MISP events to import with the given parameters and on **modified events since the last run**.
- Convert each associated galaxy or tags to OpenCTI entities: `Threat actors` / `Intrusion sets` / `Malwares` / `Attack Patterns`).
- Convert each attribute to `Indicators`.
- Import all `Indicators`, `Threat actors`, `Intrusion sets`, `Malwares` and `Attack Patterns`.
- Create `indicates` relationships between the `Indicators` and `Threat actors` / `Malwares`.
- Create `uses` relationships between `Threat actors` / `Intrusion sets` / `Malwares` and `Attack patterns`.
- Create `indicates` relationships between the previously created `uses` relationships.
