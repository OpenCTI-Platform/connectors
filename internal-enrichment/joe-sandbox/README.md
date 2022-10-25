# OpenCTI Joe Sandbox Connector

This connector supports enrichment of observables via Joe Sandbox.
* [Joe Sandbox](https://www.joesecurity.com/)

The connector works for the following observable types:

* Artifact
* Url

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-joe-sandbox:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Behavior

This connector will submit the observable for analysis, wait for it to finish,
and create relationships between the Artifact and any contacted ip, domain, or url.
Labels are created for associated Yara rule matches.
For any identified malware configuration, Note entities are created.
An external reference will contain all of the analysis reports. The following
list represents the supported list of analysis reports:

* html
* iochtml
* iocjson
* iocxml
* unpackpe
* stix
* ida
* misp
* pdf
* misp
* pcap
* pcapunified
* pcapsslinspection
* maec
* memdumps
* json (not available for Joe Sandbox Cloud Basic)
* xml (not available for Joe Sandbox Cloud Basic)
