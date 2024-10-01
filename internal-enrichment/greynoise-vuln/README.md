# OpenCTI GreyNoise Vulnerability Connector

GreyNoise is a system that collects, analyzes, and labels omnidirectional Internet scan and attack activity.

The purpose of this connector is to answer to this question : "Is this vulnerability being exploited in the wild?"

## Installation

The GreyNoise Vulnerability connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ's credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a Docker with the image `opencti/connector-greynoise-vuln:latest`. We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration


| Parameter                              | Docker envvar                          | Mandatory  | Description                                                                                                            |
|----------------------------------------|----------------------------------------|------------|------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                          | `OPENCTI_URL`                          | Yes        | The URL of the OpenCTI platform.                                                                                       |
| `opencti_token`                        | `OPENCTI_TOKEN`                        | Yes        | The default admin token configured in the OpenCTI platform parameters file.                                            |
| `connector_id`                         | `CONNECTOR_ID`                         | Yes        | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                     |
| `connector_name`                       | `CONNECTOR_NAME`                       | Yes        | The name of the GreyNoise connector instance, to identify it if you have multiple GreyNoise connectors.                |
| `connector_scope`                      | `CONNECTOR_SCOPE`                      | Yes        | Must be `vulnerability`.                                                                                               |
| `connector_auto`	                      | `CONNECTOR_AUTO`                       | Yes        | Must be `true` or `false` to enable or disable auto-enrichment of observables                                          |
| `connector_log_level`                  | `CONNECTOR_LOG_LEVEL`                  | Yes        | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                          |
| `greynoise_key`                        | `GREYNOISE_KEY`                        | Yes        | The GreyNoise API key .                                                                                                |
| `greynoise_max_tlp`                    | `GREYNOISE_MAX_TLP`                    | Yes        | Do not send any data to GreyNoise if the TLP of the observable is greater than GREYNOISE_MAX_TLP                       |
| `greynoise_name`	                      | `GREYNOISE_NAME`                       | Yes        | The GreyNoise organization name                                                                                        |
| `greynoise_description`                | `GREYNOISE_DESCRIPTION`                | Yes        | The GreyNoise organization description                                                                                 |


## Behavior

- Create a GreyNoise `Organization` if it doesn't exist with `GREYNOISE_NAME`  and `GREYNOISE_DESCRIPTION`
- Call the GreyNoise API for the CVE ID


## Subscription Information

This connector requires an API key from GreyNoise, which can be access [here](https://viz.greynoise.io/account/api-key).  This connector will provide enrichment data based on your API key type automatically.  Those users with a Vulnerability Prioritization License will see the full data response available.  Please contact [sales@greynoise.io](mailto:sales@greynoise.io) for more information.

