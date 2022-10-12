# OpenCTI VMRay Analyzer Connector

This connector supports enrichment of observables via VMRay Analyzer.
* [VMRay Analyzer](https://www.vmray.com/)

The connector works for the following observable types:

* Artifact
* Url

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-vmray-analyzer:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Behavior

This connector will submit the Artifact for analysis, wait for it to finish,
and create relationships between the Artifact and any contacted ip, domain, or url.
Labels are created for associated threat and classification names.
For any identified malware configuration, Note entities are created.
An external reference will contain all of the analysis files, for example:

* Memory dumps
* Logs
* Report PDF
* Behaviors
* Malware Configurations
* Stix JSON files