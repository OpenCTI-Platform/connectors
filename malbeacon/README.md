# OpenCTI Malbeacon Connector

![Malbeacon Logo](https://malbeacon.com/static/assets/images/pharos1.png)

this is an observable enrichment connector that uses the
[Malbeacon](https://malbeacon.com/) API to add information about origin
networks of attackers.

The connector works for the following OpenCTI observable types:

* ipv4-addr
* ipv6-addr
* domain-name

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

Please add your Malbeacon API key to the configuration file (replace `ChangeMe`).

If you wish to make a lookup for every supported observable type automatically
please set `CONNECTOR_AUTO=true`.

## Behavior

* Adds an external reference to Malbeacon for every observable that is found in the API
* Adds observable and indicators for every Actor IP and Domain entry in Malbeacon

## Known TODOs:

* Add relationships from the Actor objects to the intitial observables
* Use STIX2.1 infrastruture compoments to explain the attacker infrastructure
