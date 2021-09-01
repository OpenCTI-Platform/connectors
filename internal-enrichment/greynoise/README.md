# OpenCTI GreyNoise Connector

GreyNoise is a system that collects, analyzes, and labels omnidirectional Internet scan and attack activity. 

The purpose of this connector is to answer to this question : "Is everyone else seeing this stuff, or is it just me?"

In other words:  "Is this just regular Internet background noise or is machine actually targeting and attacking ME specifically?"

## Installation

The GreyNoise connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the `config.yml` file or within a Docker with the image `opencti/connector-greynoise:latest`. We provide an example of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

## Configuration


| Parameter           	     				| Docker envvar                         | Mandatory	| Description                                                                                              |
| ------------------------------------------|-------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------- |
| `opencti_url`                    			| `OPENCTI_URL`                         | Yes       | The URL of the OpenCTI platform.                                                                         |
| `opencti_token`                  			| `OPENCTI_TOKEN`                       | Yes       | The default admin token configured in the OpenCTI platform parameters file.                              |
| `connector_id`                  			| `CONNECTOR_ID`                        | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                       |
| `connector_type`                			| `CONNECTOR_TYPE`                      | Yes       | Must be `INTERNAL_ENRICHMENT` (this is the connector type).                                              |
| `connector_name`                			| `CONNECTOR_NAME`                      | Yes       | The name of the GreyNoise connector instance, to identify it if you have multiple GreyNoise connectors.  |
| `connector_scope`              			| `CONNECTOR_SCOPE`                     | Yes       | Must be `ipv4-addr`.                                                        |
| `connector_auto`							| `CONNECTOR_AUTO`                      | Yes       | Must be `true` or `false` to enable or disable auto-enrichment of observables                                                         |
| `connector_confidence_level`				| `CONNECTOR_CONFIDENCE_LEVEL`          | Yes       | The confidence level for created sightings (a number between 0 and 100).                  |
| `connector_log_level`						| `CONNECTOR_LOG_LEVEL`                 | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).       |
| `greynoise_key`							| `GREYNOISE_KEY`                       | Yes       | The GreyNoise API key .                                                                              |
| `greynoise_max_tlp`						| `GREYNOISE_MAX_TLP`                   | Yes       | Do not send any data to GreyNoise if the TLP of the observable is greater than GREYNOISE_MAX_TLP               |
| `greynoise_name`							| `GREYNOISE_NAME`               		| Yes       | The GreyNoise organization name                                                                              |
| `greynoise_description`					| `GREYNOISE_DESCRIPTION`               | Yes       | The GreyNoise organization description                                                                              |
| `greynoise_sighting_not_seen`				| `GREYNOISE_SIGHTING_NOT_SEEN`			| Yes       | Must be `true` or `false` to enable or disable the creation of a sighting with `count=0` when an IP has not been seen.
| `greynoise_spoofable_confidence_level`	| `GREYNOISE_SPOOFABLE_CONFIDENCE_LEVEL`| Yes       | The confidence level for created sighting (a number between 0 and 100) when activity could be spoofed (the IP has failed to complete a full TCP connection).    


## Behavior

- Create a GreyNoise `Organization` if it doesn't exist with `GREYNOISE_NAME`  and `GREYNOISE_DESCRIPTION`  
- If the IPv4 is a network: do noting (not implemented)
- Call the GreyNoise API for the IPv4 
- If the IPv4 is knew by GreyNoise: 
  - if the activity could be spoofed: create a `sighting` from the IPv4 observable to the GreyNoise entity with `count=1` and `confidence=GREYNOISE_SPOOFABLE_CONFIDENCE_LEVEL` 
  - if the activity could not be spoofed: create a `sighting` from the IPv4 observable to the GreyNoise entity with `count=1` and `confidence=CONNECTOR_CONFIDENCE_LEVEL` 
- If the IPv4 is not knew by GreyNoise:
  - if `GREYNOISE_SIGHTING_NOT_SEEN=true`: create a `sighting` from the IPv4 observable to the GreyNoise entity with `count=0` and `confidence=CONNECTOR_CONFIDENCE_LEVEL` 
  - if `GREYNOISE_SIGHTING_NOT_SEEN=false`: do nothing.
