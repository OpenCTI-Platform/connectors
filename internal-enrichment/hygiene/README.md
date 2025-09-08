# OpenCTI Internal Enrichment Hygiene Connector

## Status Filigran

| Status            | Date | Comment |
|-------------------|------|---------|
| Filigran Verified | -    | -       |

## Introduction

**Introducing Hygiene**

This is an internal enrichment connector that uses the following external
projects to look for observable values in the database that you might want to
delete / decay because they are known to lead to false-positives when used for
detection:

* [misp-warninglists](https://github.com/MISP/misp-warninglists)

The connector works for the following OpenCTI observable types:

* IPv4-Addr
* IPv6-Addr
* Domain-Name
* StixFile
* Artifact

And works also for the Indicators based on these observables types.

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-hygiene:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Requirements

- tldextract==5.3.0
- pydantic-settings==2.10.1
- pycti==6.7.15
- git+http://github.com/MISP/PyMISPWarningLists.git@main#egg=pymispwarninglists

## Configuration variables environment

Find all the configuration variables available (default/required) here: [Connector Configurations](./__metadata__)

## Behavior

1. Adds a `hygiene` or `hygiene_parent` label by default on items that correspond to a warning list entry. These are configurable(both color and label name)
2. Sets the score of all related indicators to a value based on the number of
   reported entries (1:15, >=3:10, >=5:5, default:20).
