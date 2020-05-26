# OpenCTI Cortex Connector

this connector uses a [Cortex](https://github.com/TheHive-Project/Cortex)
server for observable enrichment.

The connector works for the following OpenCTI observable types:

* ipv4-addr
* ipv6-addr
* domain

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-cortex:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Configuration

The connector can be configured with the following variables:

| Config Parameter       | Docker env var                   | Default | Description                                    |
| -----------------------| -------------------------------- | ------- | ---------------------------------------------- |
| `api_key `             | `CORTEX_API_KEY`                 | `""`    | API authentication key                         |
| `server_url`           | `CORTEX_SERVER_URL`              | `""`    | Url for the cortex server including port       |
| `verify_ssl`           | `CORTEX_VERIFY_SSL`              | `false` | Turns SSL/TLS verification on or off           |
| `confidence_level`     | `CONNECTOR_CONFIDENCE_LEVEL`     | `3`     | The confidence level you give to the connector |

## Behavior

TODO: Behavior
