# OpenCTI Cluster25 Connector

The OpenCTI Cluster25 connector can be used to import indicators from the C25 platform into OpenCTI.
It uses che current V1 public APIs to get a valid token and import the supported indicators.
In the current implementation, the connector is able to import indicators only.
With future releases, it would be possible to import observables, threat actors and various contents as well.

Note: in order to use the connector, you need a valid pair of CLIENT_ID and CLIENT_SECRET provided by the C25 team.
All the results are implicitly filtered by the user's TLP. 

## Installation

The OpenCTI Cluster25 connector is a standalone Python process that must have access
to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters
are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after
providing the correct configuration in the `config.yml` file or within a Docker with
the image `opencti/connector-cluster25:latest`. We provide an example of
[`docker-compose.yml`](docker-compose.yml) file that could be used independently or
integrated to the global `docker-compose.yml` file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.
### Configuration


| Config Parameter | Docker env var              | Default                                                                | Description                                                                            |
|------------------|-----------------------------|------------------------------------------------------------------------|----------------------------------------------------------------------------------------|
| `base_url`       | `CLUSTER25_BASE_URL`        | `https://api.intelligence.cluster25.io/api/v1`                         | The base URL of the C25 platform. It can be the default one, or your private instance. |
| `client_id`      | `CLUSTER25_CLIENT_ID`       | `ChangeMe`                                                             | The C25 client_id.                                                                     |
| `client_secret`  | `CLUSTER25_CLIENT_SECRET`   | `ChangeMe`                                                             | The C25 client_secret.                                                                 |
| `indicator_types`  | `CLUSTER25_INDICATOR_TYPES` | `ipv4,domain,md5,sha1,sha256,url,email,ipv6,filename`  | The indicators type you want to ingest. By default, all the indicators are collected.  |


### Issues

In case of errors, bugs, or any other issues please feel free to contact the main developer [@CorraMatte](https://github.com/CorraMatte).

