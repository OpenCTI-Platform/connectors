# ZeroFox Threat Intelligence Connector

| Status | Date | Comment |
|--------|------|---------|
| Partner Verified | -    | -       |

The OpenCTI ZeroFox connector can be used to import knowledge from the ZeroFox
 platform. The connector leverages the Threat Intelligence data feeds to get data about ...

**Note**: Requires subscription to the ZeroFox CTI feeds. The subscription
details dictate what feeds are available to the connector.
In order to get a suscription, please contact 

## Installation

The OpenCTI ZeroFox connector is a standalone Python process that must have access
to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration as exported environment variables or within a Docker with
the image `opencti/connector-zerofox:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.

### Requirements

- OpenCTI Platform >= 7.260722.0

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._