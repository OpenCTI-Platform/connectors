# OpenCTI Hygiene Connector

this is an internal enrichment connector that uses the following external
projects to look for oberservable values in the database that you might want to
delete / decay because they are known to lead to alse-positives when used for
detection:

* [misp-warninglists](https://github.com/MISP/misp-warninglists)

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
Docker with the image `opencti/connector-hygiene:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Configuration

No special configuration is needed.

## Behavior

1. Adds a `Hygiene` tag on items that correspond to a warning list entry.
2. Adds an external reference for every matching warning list.
3. Sets the observable score to `10`.
