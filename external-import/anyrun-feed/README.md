<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="https://raw.githubusercontent.com/anyrun/anyrun-sdk/b3dfde1d3aa018d0a1c3b5d0fa8aaa652e80d883/static/logo.svg">
    </a>
</p>

______________________________________________________________________

# ANY.RUN Threat Intelligence Feed connector for OpenCTI 

The ANY.RUN Threat Intelligence Feed connector provides OpenCTI users with a continuously updated stream of fresh, accurate indicators of compromise, including malicious IPs, URLs, and domains. This enables security teams to proactively defend against emerging, evolving, and persistent cyber threats.
To use the integration, ensure you have an active [ANY.RUN TI Feed subscription](https://any.run/demo/?utm_source=opencti_marketplace&utm_medium=integration&utm_campaign=opencti_form).

## Installation

The ANY.RUN Threat Intelligence Lookup connector for OpenCTI is a standalone Python service that requires access to both the OpenCTI platform and RabbitMQ.

RabbitMQ credentials and connection parameters are provided automatically by the OpenCTI API, based on the platform’s configuration.

You can enable the connector in one of the following ways:

* Run as a Python process: simply configure the `config.yml` file with the appropriate values and launch the connector directly.

* Run in Docker: use the OpenCTI docker image `opencti/connector-anyrun-feed:latest`

ANY.RUN provide a sample `docker-compose.yml` file, which can be used as a standalone deployment or integrated into OpenCTI’s main `docker-compose.yml`.

**Note**:

- If you deploy the connector independently, make sure it can reach RabbitMQ on the port defined in your OpenCTI configuration.
- If you're experiencing issues or require an immediate update, ANY.RUN can provide an updated Docker image upon request.
Please contact our support team at <anyrun-integrations@any.run>.

### Requirements

- OpenCTI Platform >= 6.7.4
- ANY.RUN TI Feed subscription

## Generate Basic Authentication token

To obtain your Basic Authentication token, please contact your ANY.RUN account manager directly or fill out the request [form](https://any.run/demo/?utm_source=opencti_marketplace&utm_medium=integration&utm_campaign=opencti_form).

### Configuration

The connector can be configured with the following variables:  


| Parameter                        | Docker envvar         | Mandatory | Description                                                                                                                                                                   |
|----------------------------------|-----------------------|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                    | `OPENCTI_URL`         | Yes       | The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080`                                                                  |
| `opencti_token`                  | `OPENCTI_TOKEN`       | Yes       | The default admin token configured in the OpenCTI platform parameters file. We recommend setting up a separate ``OPENCTI_TOKEN`` named **ANY.RUN** to identify the work of our integrations.                                                                                                  |
| `connector_id`                   | `CONNECTOR_ID`        | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                            |
| `connector_name`                 | `CONNECTOR_NAME`      | Yes       | A connector name to be shown in OpenCTI.                                                                                                                                      |
| `connector_scope`                | `CONNECTOR_SCOPE`     | Yes       | Supported scope. E. g., `text/html`.                                                                                                                                          |
| `connector_log_level`            | `CONNECTOR_LOG_LEVEL` | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                                 |
| `connector_update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | Yes       | Update data already ingested into the platform. |
| `token`                          | `ANYRUN_BASIC_TOKEN`     | Yes       | ANY.RUN TI Feeds Basic token. See "Generate Basic Authentication token" section in the README file. Example: Basic askAs...s31==                                                                 |
| `feed_fetch_interval`            | `ANYRUN_FEED_FETCH_INTERVAL`       | Yes       | Specify feed fetch interval in minutes                                                                                                                                                           |
| `feed_fetch_depth`               | `ANYRUN_FEED_FETCH_DEPTH`       | Yes       | Specify feed fetch depth in days                                                                                                                                                          |

## Support
This is an ANY.RUN supported connector. For support please contact <anyrun-integrations@any.run>