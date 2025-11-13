# OpenCTI GreyNoise Connector

GreyNoise is a system that collects, analyzes, and labels omnidirectional Internet scan and attack activity.

The purpose of this connector is to answer to this question : "Is everyone else seeing this stuff, or is it just me?"

In other words:  "Is this just regular Internet background noise or is machine actually targeting and attacking ME specifically?"

## Installation

The GreyNoise connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a Docker with the image `opencti/connector-greynoise:latest`. We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration


| Parameter                              | Docker envvar                          | Mandatory  | Description                                                                                                               |
|----------------------------------------|----------------------------------------|------------|---------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                          | `OPENCTI_URL`                          | Yes        | The URL of the OpenCTI platform.                                                                                          |
| `opencti_token`                        | `OPENCTI_TOKEN`                        | Yes        | The default admin token configured in the OpenCTI platform parameters file.                                               |
| `connector_id`                         | `CONNECTOR_ID`                         | Yes        | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                        |
| `connector_name`                       | `CONNECTOR_NAME`                       | Yes        | The name of the GreyNoise connector instance, to identify it if you have multiple GreyNoise connectors.                   |
| `connector_scope`                      | `CONNECTOR_SCOPE`                      | Yes        | Must be `ipv4-addr`.                                                                                                      |
| `connector_auto`	                      | `CONNECTOR_AUTO`                       | Yes        | Must be `true` or `false` to enable or disable auto-enrichment of observables                                             |
| `connector_log_level`                  | `CONNECTOR_LOG_LEVEL`                  | Yes        | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                             |
| `greynoise_key`                        | `GREYNOISE_KEY`                        | Yes        | The GreyNoise API key .                                                                                                   |
| `greynoise_max_tlp`                    | `GREYNOISE_MAX_TLP`                    | Yes        | Do not send any data to GreyNoise if the TLP of the observable is greater than GREYNOISE_MAX_TLP                          |
| `greynoise_name`	                      | `GREYNOISE_NAME`                       | Yes        | The GreyNoise organization name                                                                                           |
| `greynoise_description`                | `GREYNOISE_DESCRIPTION`                | Yes        | The GreyNoise organization description                                                                                    |
| `greynoise_sighting_not_seen`          | `GREYNOISE_SIGHTING_NOT_SEEN`          | Yes        | Must be `true` or `false` to enable or disable the creation of a sighting with `count=0` when an IP has not been seen.    |
| `greynoise_default_score`              | `GREYNOISE_DEFAULT_SCORE`              | Yes        | Default_score allows you to add a default score for an indicator and its observable (a number between 1 and 100)          | 
| `greynoise_indicator_score_malicious` | `GREYNOISE_INDICATOR_SCORE_MALICIOUS=90` | No | Indicator score applied when GreyNoise classification is malicious (a number between 1 and 100) |
| `greynoise_indicator_score_suspicious` | `GREYNOISE_INDICATOR_SCORE_SUSPICIOUS=70`| No | Indicator score applied when GreyNoise classification is suspicious (a number between 1 and 100) |
| `greynoise_indicator_score_benign` | `GREYNOISE_INDICATOR_SCORE_BENIGN=20`| No | Indicator score applied when GreyNoise classification is benign (a number between 1 and 100) |


## Behavior

- Create a GreyNoise `Organization` if it doesn't exist with `GREYNOISE_NAME`  and `GREYNOISE_DESCRIPTION`
- If the IPv4 is a network: do noting (not implemented)
- Call the GreyNoise API for the IPv4
- If the IPv4 is knew by GreyNoise:
  - Create a `sighting` from the IPv4 observable to the GreyNoise entity with `count=1`
- If the IPv4 is not knew by GreyNoise:
  - if `GREYNOISE_SIGHTING_NOT_SEEN=true`: create a `sighting` from the IPv4 observable to the GreyNoise entity with `count=0`
  - if `GREYNOISE_SIGHTING_NOT_SEEN=false`: do nothing.
