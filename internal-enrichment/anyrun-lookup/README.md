<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="https://raw.githubusercontent.com/anyrun/anyrun-sdk/b3dfde1d3aa018d0a1c3b5d0fa8aaa652e80d883/static/logo.svg">
    </a>
</p>

______________________________________________________________________


# ANY.RUN Threat Intelligence Lookup connector for OpenCTI 

The ANY.RUN Threat Intelligence Lookup connector enables OpenCTI users to enrich observables such as file hashes, domain names, hostnames, IP addresses, and URLs. This enrichment helps security teams proactively detect and defend against emerging, evolving, and persistent cyber threats.

To use this integration, ensure that you have an active [ANY.RUN TI Lookup license](https://any.run/demo/?utm_source=opencti_marketplace&utm_medium=integration&utm_campaign=opencti_form).

## Installation

The ANY.RUN Threat Intelligence Lookup connector for OpenCTI is a standalone Python service that requires access to both the OpenCTI platform and RabbitMQ.

RabbitMQ credentials and connection parameters are provided automatically by the OpenCTI API, based on the platform’s configuration.

You can enable the connector in one of the following ways:

* Run as a Python process: simply configure the `config.yml` file with the appropriate values and launch the connector directly.

* Run in Docker: use the OpenCTI docker image `opencti/connector-anyrun-lookup:latest`

ANY.RUN provide a sample `docker-compose.yml` file, which can be used as a standalone deployment or integrated into OpenCTI’s main `docker-compose.yml`.

**Note**:

- If you deploy the connector independently, make sure it can reach RabbitMQ on the port defined in your OpenCTI configuration.
- If you're experiencing issues or require an immediate update, ANY.RUN can provide an updated Docker image upon request.
Please contact our support team at <anyrun-integrations@any.run>.

### Requirements

- OpenCTI Platform >= 6.7.4
- ANY.RUN TI Lookup license

### Generate API key

* Follow [ANY.RUN](https://app.any.run/)
* [1] Profile > [2] API and Limits > [3] Generate > [4] Copy

![ANY.RUN Generate API KEY](static/ANYRUN_API_TOKEN.png)


### Configuration


The connector can be configured with the following variables:

| Parameter                    | Docker env_var                   | Mandatory | Description                                                                                                  |
|------------------------------|----------------------------------|-----------|--------------------------------------------------------------------------------------------------------------|
| `opencti_url`                | `OPENCTI_URL`                    | Yes       | The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080` |
| `opencti_token`              | `OPENCTI_TOKEN`                  | Yes       | The default admin token configured in the OpenCTI platform parameters file. We recommend setting up a separate ``OPENCTI_TOKEN`` named **ANY.RUN** to identify the work of our integrations.                                  |
| `connector_id`               | `CONNECTOR_ID`                   | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                            |
| `connector_type`             | `CONNECTOR_TYPE`                 | Yes       | A connector type.                                                                                               |
| `connector_name`             | `CONNECTOR_NAME`                 | Yes       | A connector name to be shown in OpenCTI.                                                                     |
| `connector_scope`            | `CONNECTOR_SCOPE`                | Yes       | Supported scope. E. g., `text/html`.                                                                         |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL`     | Yes       | The default confidence level for created sightings (a number between 1 and 4).                               |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`            | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                |
| `auto`                       | `CONNECTOR_AUTO`                 | Yes       | Enable/disable auto-enrichment of observables.                                                               |
| `token`                      | `ANYRUN_API_KEY`                   | Yes       | ANY.RUN Lookup API-KEY. See "Generate API token" section in the README file.                                                                                          |
| `lookup_depth`               | `ANYRUN_LOOKUP_DEPTH`                   | Yes       | Specify the number of days from the current date for which you want to lookup.                                                                                           |

## Support
This is an ANY.RUN supported connector. For support please contact <anyrun-integrations@any.run>