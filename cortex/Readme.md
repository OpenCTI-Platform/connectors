# OpenCTI Cortex Connector

this connector uses a [Cortex](https://github.com/TheHive-Project/Cortex)
server for observable enrichment.

The connector works for the following OpenCTI observable types:

* ipv4-addr
* ipv6-addr
* domain
* file-md5
* file-sha1
* file-sha256

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-cortex:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Configuration

TODO: TABLE

## Behavior

TODO: Behavior
