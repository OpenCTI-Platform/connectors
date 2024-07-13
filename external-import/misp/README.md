# OpenCTI MISP Connector

## Installation

The MISP connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a Docker with the image `opencti/connector-misp:latest`. We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

**Warning**: This connector is compatible with MISP >=2.4.135.3.

| Parameter                                     | Docker envvar                                 | Mandatory    | Description                                                                                          |
|-----------------------------------------------|-----------------------------------------------| ------------ |------------------------------------------------------------------------------------------------------|
| `opencti_url`                                 | `OPENCTI_URL`                                 | Yes          | The URL of the OpenCTI platform.                                                                     |
| `opencti_token`                               | `OPENCTI_TOKEN`                               | Yes          | The default admin token configured in the OpenCTI platform parameters file.                          |
| `connector_id`                                | `CONNECTOR_ID`                                | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                   |
| `connector_name`                              | `CONNECTOR_NAME`                              | Yes          | The name of the MISP instance, to identify it if you have multiple MISP connectors.                  |
| `connector_scope`                             | `CONNECTOR_SCOPE`                             | Yes          | Must be `misp`, not used in this connector.                                                          |
| `connector_log_level`                         | `CONNECTOR_LOG_LEVEL`                         | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).        |
| `misp_url`                                    | `MISP_URL`                                    | Yes          | The MISP instance URL.                                                                               |
| `misp_reference_url`                          | `MISP_REFERENCE_URL`                          | Yes          | The MISP instance reference URL (used to create external reference, optional)                        |
| `misp_key`                                    | `MISP_KEY`                                    | Yes          | The MISP instance key.                                                                               |
| `misp_client_cert`                            | `MISP_CLIENT_CERT`                            | No           | The client certificate of the MISP instance. It must be a path to the client certificate and readable |
| `misp_ssl_verify`                             | `MISP_SSL_VERIFY`                             | Yes          | A boolean (`True` or `False`), check if the SSL certificate is valid when using `https`.             |
| `misp_datetime_attribute`                     | `MISP_DATETIME_ATTRIBUTE`                     | Yes          | The attribute to be used to get the date of the event.                                         |
| `misp_date_filter_field`                      | `MISP_DATE_FILTER_FIELD`                      | Yes          | The attribute to be used in filter to query new MISP events.                                         |
| `misp_report_description_attribute_filter`    | `MISP_REPORT_DESCRIPTION_ATTRIBUTE_FILTER`    | No          |  Filter to be used to find the attribute with report description (example: "type=comment,category=Internal reference").                                         |
| `misp_create_reports`                         | `MISP_CREATE_REPORTS`                         | Yes          | A boolean (`True` or `False`), create reports for each imported MISP event.                          |
| `misp_create_object_observables`              | `MISP_CREATE_OBJECT_OBSERVABLES`              | Yes          | A boolean (`True` or `False`), create a text observable for each imported MISP object.               |
| `misp_create_observables`                     | `MISP_CREATE_OBSERVABLES`                     | Yes          | A boolean (`True` or `False`), create an observable for each imported MISP attribute.                |
| `misp_create_indicators`                      | `MISP_CREATE_INDICATORS`                      | Yes          | A boolean (`True` or `False`), create an indicator for each imported MISP attribute.                 |
| `misp_create_tags_as_labels`                  | `MISP_CREATE_TAGS_AS_LABELS`                  | No          | A boolean (`True` or `False`), create tags as labels.                 |
| `misp_report_class`                           | `MISP_REPORT_CLASS`                           | No           | If `create_reports` is `True`, specify the `report_class` (category), default is `MISP Event`        |
| `misp_import_from_date`                       | `MISP_IMPORT_FROM_DATE`                       | No           | A date formatted `YYYY-MM-DD`, only import events created after this date.                           |
| `misp_import_tags`                            | `MISP_IMPORT_TAGS`                            | No           | A list of tags separated with `,`, only import events with these tags.                               |
| `misp_import_tags_not`                        | `MISP_IMPORT_TAGS_NOT`                        | No           | A list of tags separated with `,`, to exclude from import.                                           |
| `misp_import_creator_orgs`                    | `MISP_IMPORT_CREATOR_ORGS`                    | No           | A list of org identifiers separated with `,`, only import events created by these orgs.              |
| `misp_import_creator_orgs_not`                | `MISP_IMPORT_CREATOR_ORGS_NOT`                | No           | A list of org identifiers separated with `,`, do not import events created by these orgs.            |
| `misp_import_owner_orgs`                      | `MISP_IMPORT_OWNER_ORGS`                      | No           | A list of org identifiers separated with `,`, only import events owned by these orgs                 |
| `misp_import_owner_orgs_not`                  | `MISP_IMPORT_OWNER_ORGS_NOT`                  | No           | A list of org identifiers separated with `,`, do not import events owned by these orgs               |
| `misp_import_distribution_levels`             | `MISP_IMPORT_DISTRIBUTION_LEVELS`             | No           | A list of distribution levels separated with `,`, only import events with these distribution levels. |
| `misp_import_threat_levels`                   | `MISP_IMPORT_THREAT_LEVELS`                   | No           | A list of threat levels separated with `,`, only import events with these threat levels.             |
| `misp_import_only_published`                  | `MISP_IMPORT_ONLY_PUBLISHED`                  | No           | Import only MISP published events                                                                    |
| `misp_import_with_attachments`                | `MISP_IMPORT_WITH_ATTACHMENTS`                | No           | Import attachment attribute content as a file if it is a PDF.                                        |
| `misp_import_to_ids_no_score`                 | `MISP_IMPORT_TO_IDS_NO_SCORE`                 | No           | A score (`Integer`) value for the indicator/observable if the attribute `to_ids` value is no.        |
| `misp_import_unsupported_observables_as_text` | `MISP_IMPORT_UNSUPPORTED_OBSERVABLES_AS_TEXT` | No           | Import unsupported observable as x_opencti_text                                                      |
| `misp_interval`                               | `MISP_INTERVAL`                               | Yes          | Check for new event to import every `n` minutes.                                                     |

## Behavior

The MISP connector will check all new events or latest modified event since the last run for import. The import process has the following steps:

- Iterate other MISP events to import with the given parameters and on **modified events since the last run**.
- Convert each associated galaxy or tags to OpenCTI entities: `Threat actors` / `Intrusion sets` / `Malwares` / `Attack Patterns`).
- Convert each attribute to `Indicators`.
- Import all `Indicators`, `Threat actors`, `Intrusion sets`, `Malwares` and `Attack Patterns`.
- Create `indicates` relationships between the `Indicators` and `Threat actors` / `Malwares`.
- Create `uses` relationships between `Threat actors` / `Intrusion sets` / `Malwares` and `Attack patterns`.
- Create `indicates` relationships between the previously created `uses` relationships.

## Debugging

### No reports imported

When running the MISP Connector, it is sometimes a bit difficult to verify if the configured tags filter correctly. In case no reports are imported, please try this approach to improve your query.

When running the MISP connector, it also logs the query as shown in this example:
```
INFO:root:Listing Threat-Actors with filters null.
INFO:root:Connector registered with ID: 520cc948-5e3e-4df0-82c4-f3646ceee537
INFO:root:Starting ping alive thread
INFO:root:Initiate work for 520cc948-5e3e-4df0-82c4-f3646ceee537
INFO:root:Connector has never run
INFO:root:Fetching MISP events with args: {"tags": {"OR": ["APT", "Threat Type:APT"]}, "date_from": "2020-06-16", "limit": 50, "page": 1}
```
Take the query and do a curl test to see if MISP actually returns any events.
```
curl -i
-H "Accept: application/json"
-H "content-type: application/json"
-H "Authorization: YOUR API KEY"
--data '{"tags": {"OR": ["APT", "Threat Type:APT"]}, "date_from": "2020-06-16", "limit": 50, "page": 1}'
-X POST
http://YOURMISP.SERVER
```
You can also save your tags in a tags.json file and then simply reference curl to the file with `--data "@tags.json"`
Details: https://www.circl.lu/doc/misp/automation/#post-events

If MISP doesn't return anything with your curl query, try to see if any tag names differ from MISP's and alike. Once the query is returning events, the OpenCTI MISP connector should work as well.