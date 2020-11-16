# OpenCTI Kaspersky Connector

The OpenCTI Kaspersky connector can be used to import knowledge from the Kaspersky
Threat Intelligence Portal. The connector leverages the Kaspersky Threat Intelligence
Portal API to retrieve the intelligence published on the Kaspersky
Threat Intelligence Portal, this includes report PDFs, IoCs and YARA rules.

**Note**: A license is required to use the Kaspersky Threat Intelligence Portal
services.

## Installation

The OpenCTI Kaspersky connector is a standalone Python process that must have access
to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-kaspersky:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration

The connector can be configured with the following variables:

| Config Parameter                           | Docker env var                                       | Default                                             | Description                                                                                                       |
| ------------------------------------------ | ---------------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| `base_url`                                 | `KASPERSKY_BASE_URL`                                 | `https://tip.kaspersky.com`          | The base URL for the Kaspersky Threat Intelligence Portal API.                                                                   |
| `user`                                     | `KASPERSKY_USER`                                     | `ChangeMe`                           | The user name obtained from Kaspersky.                                                                                           |
| `password`                                 | `KASPERSKY_PASSWORD`                                 | `ChangeMe`                           | The password obtained from Kaspersky.                                                                                            |
| `certificate_path`                         | `KASPERSKY_CERTIFICATE_PATH`                         | `ChangeMe`                           | The full path to certificate obtained from Kaspersky.                                                                            |
| `tlp`                                      | `KASPERSKY_TLP`                                      | `Amber`                              | The TLP marking used for the imported objects in the OpenCTI.                                                                    |
| `create_observables`                       | `KASPERSKY_CREATE_OBSERVABLES`                       | `true`                               | If true then observables will be created from the Kaspersky IoCs. Affected scopes: publication and master_ioc.                   |
| `create_indicators`                        | `KASPERSKY_CREATE_INDICATORS`                        | `true`                               | If true then indicators will be created from the Kaspersky IoCs. Affected scopes: publication and master_ioc.                    |
| `scopes`                                   | `KASPERSKY_SCOPES`                                   | `publication,master_ioc,master_yara` | The scopes defines what data will be imported from Kaspersky.                                                                    |
| `publication_start_timestamp`              | `KASPERSKY_PUBLICATION_START_TIMESTAMP`              | `0`                                  | The publications updated after this timestamp will be imported. Timestamp in UNIX Epoch time, UTC.                               |
| `publication_report_type`                  | `KASPERSKY_PUBLICATION_REPORT_TYPE`                  | `threat-report`                      | The publications are imported as reports of given type in the OpenCTI.                                                           |
| `publication_report_status`                | `KASPERSKY_PUBLICATION_REPORT_STATUS`                | `New`                                | The status of imported reports in the OpenCTI.                                                                                   |
| `publication_report_ignore_prefixes`       | `KASPERSKY_PUBLICATION_REPORT_IGNORE_PREFIXES`       | `Monthly APT activity report`        | The publications starting with given prefixes will not be imported to the OpenCTI.                                               |
| `publication_excluded_ioc_indicator_types` | `KASPERSKY_PUBLICATION_EXCLUDED_IOC_INDICATOR_TYPES` | `Md5sum,FileItem/Sha1sum`            | The publication IoCs of given type will not be imported to the OpenCTI. Values correspond to OpenIOC search values.              |
| `master_ioc_fetch_weekday`                 | `KASPERSKY_MASTER_IOC_FETCH_WEEKDAY`                 | `1`                                  | If specified then the Master IoC file will be fetched only once on the given ISO weekday, otherwise it is fetched on every run.  |
| `master_ioc_excluded_ioc_indicator_types`  | `KASPERSKY_MASTER_IOC_EXCLUDED_IOC_INDICATOR_TYPES`  | `md5Hash,sha1Hash`                   | The Master IoCs of given type will not be imported to the OpenCTI. Values correspond to OpenIOC indicator types.                 |
| `master_ioc_report_type`                   | `KASPERSKY_MASTER_IOC_REPORT_TYPE`                   | `threat-report`                      | The publications related to Master IoCs are imported as reports of given type in the OpenCTI.                                    |
| `master_ioc_report_status`                 | `KASPERSKY_MASTER_IOC_REPORT_STATUS`                 | `New`                                | The status of imported Master IoC reports in the OpenCTI.                                                                        |
| `master_yara_fetch_weekday`                | `KASPERSKY_MASTER_YARA_FETCH_WEEKDAY`                | `2`                                  | If specified then the Master YARA file will be fetched only once on the given ISO weekday, otherwise it is fetched on every run. |
| `master_yara_report_type`                  | `KASPERSKY_MASTER_YARA_REPORT_TYPE`                  | `threat-report`                      | The publications related to Master YARA rules are imported as reports of given type in the OpenCTI.                              |
| `master_yara_report_status`                | `KASPERSKY_MASTER_YARA_REPORT_STATUS`                | `New`                                | The status of imported Master YARA reports in the OpenCTI.                                                                       |
| `interval_sec`                             | `KASPERSKY_INTERVAL_SEC`                             | `43200`                              | The import interval in seconds.                                                                                                  |

**Note**: It is not recommended to use the default value `0` for configuration parameter `publication_start_timestamp` because of the large data volumes.
