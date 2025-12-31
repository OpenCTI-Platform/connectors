# OpenCTI AlienVault Connector

The OpenCTI AlienVault connector can be used to import knowledge from the Alien Labs Open Threat Exchange (OTX) platform.
The connector leverages the OTX DirectConnect API to get the threat data of the subscribed pulses.

**Note**: Requires joining the OTX threat intelligence community.

## Installation

The OpenCTI AlienVault connector is a standalone Python process that must have access
to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-alienvault:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.

### Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding these variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## ⚠️ WARNING

The purpose of `filter_indicators`, when enabled, is to retain only indicators whose created timestamp is newer than or equal to latest_pulse_datetime stored in the connector’s state. This behavior can vary depending on the use case.

`filter_indicators` = False → The connector collects all IOCs from a pulse. This may result in a very large number of IOCs being retrieved.

`filter_indicators` = True → The connector collects only recent IOCs. It is normal in this mode for some reports to contain no IOCs if none meet the time criteria.

This filtering logic could be enhanced for more flexibility.

