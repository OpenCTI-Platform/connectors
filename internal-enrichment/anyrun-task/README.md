# OpenCTI ANY.RUN task connector

Analyze Url or Artifact in ANY.RUN Interactive Online Malware Sandbox

## Installation

The OpenCTI ANY.RUN task connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the config.yml file or within a Docker with the image anyrun/opencti-connector-anyrun-task:latest. We provide an example of docker-compose.yml file that could be used independently or integrated to the global docker-compose.yml file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

### Requirements

- OpenCTI Platform >= 5.12.32
- ANY.RUN "Hunter" plan or higher

### Configuration


The connector can be configured with the following variables:


| Parameter                    | Docker env_var                   | Mandatory | Description                                                                                                  |
|------------------------------|----------------------------------|-----------|--------------------------------------------------------------------------------------------------------------|
| `opencti_url`                | `OPENCTI_URL`                    | Yes       | The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080` |
| `opencti_token`              | `OPENCTI_TOKEN`                  | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                  |
| `connector_id`               | `CONNECTOR_ID`                   | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                           |
| `connector_name`             | `CONNECTOR_NAME`                 | Yes       | A connector name to be shown in OpenCTI.                                                                     |
| `connector_scope`            | `CONNECTOR_SCOPE`                | Yes       | Supported scope. E. g., `text/html`.                                                                         |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL`     | Yes       | The default confidence level for created sightings (a number between 1 and 4).                               |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`            | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                |
| `auto`                       | `CONNECTOR_AUTO`                 | Yes       | Enable/disable auto-enrichment of observables.                                                               |
| `token`                      | `ANYRUN_TOKEN`                   | Yes       | ANY.RUN API Token                                                                                            |
| `timer`                      | `ANYRUN_TASK_TIMER`              | No        | Time of task                                                                                                 |
| `os`                         | `ANYRUN_OS`                      | No        | Operating System in sandbox                                                                                  |
| `bitness`                    | `ANYRUN_OS_BITNESS`              | No        | Operating System bitness in sandbox                                                                          |
| `version`                    | `ANYRUN_OS_VERSION`              | No        | Operating System version in sandbox                                                                          |
| `locale`                     | `ANYRUN_OS_LOCALE`               | No        | Operating System language. Use locale identifier or country name (Ex: "en-US" or "Brazil").                  |
| `browser`                    | `ANYRUN_OS_BROWSER`              | No        | Which browser to use to open links                                                                           |
| `privacy`                    | `ANYRUN_PRIVACY`                 | No        | Privacy settings (Allowed values: "public", "bylink", "owner", "team") / Default value: "bylink"             |
| `automated_interactivity`    | `ANYRUN_AUTOMATED_INTERACTIVITY` | No        | Automated Interactivity (ML) option                                                                          |
| `ioc`                        | `ANYRUN_IOC`                     | No        | Add IOCs                                                                                                     |
| `mitre`                      | `ANYRUN_MITRE`                   | No        | Add mitre attack patterns relationships                                                                      |
| `processes`                  | `ANYRUN_PROCESSES`               | No        | Add malicious processes                                                                                      |


