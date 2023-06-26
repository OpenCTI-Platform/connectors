# ZeroFox CTI Import Connector

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->
![alt test](https://www.zerofox.com/wp-content/themes/zfox/src/img/zerofox-logo-alt.svg)

This connector imports data from the [ZeroFox CTI API](https://api.zerofox.com/cti/docs/)

The connector adds data for the following OpenCTI observable/indicator types:
* file-md5
* file-sha1
* file-sha256
* file-sha512
* ipv4-addr
* domain-name

The connectors adds the following Entities:
* Malware
## Installation

### Requirements

- OpenCTI Platform >= 5.8.5

### Configuration

| Parameter            | Docker envvar        | Mandatory    | Description                                                                 |
|----------------------|----------------------| ------------ |-----------------------------------------------------------------------------|
| `opencti_url`        | `OPENCTI_URL`        | Yes          | The URL of the OpenCTI platform.                                            |
| `opencti_token`      | `OPENCTI_TOKEN`      | Yes          | The default admin token configured in the OpenCTI platform parameters file. |
| `connector_id`       | `CONNECTOR_ID`       | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.          |
| `connector_type`     | `CONNECTOR_TYPE`     | Yes          | Must be `EXTERNAL_IMPORT` (this is the connector type).                     |
| `connector_name`     | `CONNECTOR_NAME`     | Yes          | Option `ZeroFox`                                                            |
| `connector_scope`    | `CONNECTOR_SCOPE`    | Yes          | Supported scope: Template Scope (MIME Type or Stix Object)                  |
| `username`           | `ZEROFOX_USERNAME`   | Yes          | The username used to sign into zerofox and retrive the access tokens        
| `password`           | `ZEROFOX_PASSWORD`   | Yes          | The password used to sign into zerofox and retrive the access tokens        |


