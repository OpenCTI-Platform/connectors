# Threat Fox Import Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

This connector imports data from the [Threat Fox Recent Feed](https://threatfox.abuse.ch/)

The connector adds data for the following OpenCTI observable/indicator types:

- file-md5
- file-sha1
- file-sha256
- ipv4-addr
- domain-name
- url

The connector adds the following Entities:

- Malware

## Installation

### Requirements

- OpenCTI Platform >= 6.8.15

### Configuration

Find all the configuration variables available here: [Connector Configurations](./__metadata__)