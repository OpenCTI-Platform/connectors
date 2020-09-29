# OpenCTI Malbeacon Connector

this is an observable enrichment connector that uses the
[Malbeacon](https://malbeacon.com/) API to

The connector works for the following OpenCTI observable types:

* ipv4-addr
* ipv6-addr
* domain
* hostname

**NOTE** - this connector requires an API key that can be requested from
[here](https://malbeacon.com/apply)


## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-malbeacon:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Configuration

Please add your API key to the configuration file.

## Behavior

TODO