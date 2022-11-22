# SophosLabs Intelix Connector

This connector supports enrichment of observables via SophosLabs Intelix.
* [SophosLabs Intelix](https://www.sophos.com/en-us/intelix)

The connector works for the following observable types:

* Url,IPv4-Addr,Domain,File,File-Sha256,Artifact

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `0xbennyv/sophoslabs-intelix-lookup:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.