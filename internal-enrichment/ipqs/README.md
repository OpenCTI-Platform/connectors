# OpenCTI IPQS Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

## Installation

IPQS Fraud and Risk Scoring connector provides enterprise grade fraud prevention, risk analysis, and threat detection. 
Analyze IP addresses, Email addresses, Phone Numbers,  URLs and Domains to identify sophisticated bad actors and high risk behavior.

The OpenCTI IPQS Fraud and Risk Scoring connector is a standalone Python process that must have access to the OpenCTI 
platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as 
configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration
in the `config.yml` file or within a Docker with the image `opencti/connector-ipqs:5.4.2`. We provide an example
of [`docker-compose.yml`](docker-compose.yml) file that could be used independently or integrated to the
global `docker-compose.yml` file of OpenCTI.

### Requirements

- OpenCTI Platform >= 5.4.2
- IPQualityScore API Key. If you do not have API Key, please register [here](https://www.ipqualityscore.com/create-account/openccti)

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_auto`                     | `CONNECTOR_AUTO`                    | Yes          | Enable/disable auto-enrichment of observables.                                                                             |
| `private_key`                        | `IPQS_PRIVATE_KEY`                  | Yes          | IPQualityScore API Key.                                                                                                                                          |

### Debugging ###

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

### Additional information

N/A
