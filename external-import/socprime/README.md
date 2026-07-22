# OpenCTI SOC Prime Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

The OpenCTI SOC Prime connector can be used to import rules (indicators) from the SOC Prime Platform.
The connector leverages the SOC Prime Threat Detection Marketplace API to get the rules.
Rules for importing can be selected using content lists or jobs created on the SOC Prime Platform.

## Installation

The OpenCTI SOC Prime connector is a standalone Python process that requires access to the OpenCTI platform, RabbitMQ
and API Key to the SOC Prime CCM to be able to pull Sigma rules. RabbitMQ credentials and connection parameters are
provided by the OpenCTI API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-socprime:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
RabbitMQ on the port configured in the OpenCTI platform.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._
