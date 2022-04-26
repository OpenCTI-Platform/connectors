# OpenCTI SentinelOne Threats Connector

The OpenCTI SentinelOne Threats connector can be used to import Artifacts from BinaryVault.
For more information about BinaryVault and the steps to set it up, see:
https://success.alienvault.com/s/article/UUID-9bf40076-0ba9-2f93-93bd-b4878bd6c220

## Installation

The OpenCTI SentinelOne Threats connector is a standalone Python process that must have access
to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-sentinelone-threats:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.
