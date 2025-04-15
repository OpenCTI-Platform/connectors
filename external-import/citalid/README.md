# OpenCTI Citalid Connector

The OpenCTI Citalid connector allows you to import latest Citaalid CTI dataset. The connector leverages the Citalid API to retrieve the latest dataset in stix bundle format.

**Disclaimer** You will need to have access to Citalid API. To learn more about our product you can book a demo on https://citalid.com/book-a-demo/. 

## Installation

Follow this guide to deploy the connector: https://github.com/OpenCTI-Platform/connectors

### Requirements

- OpenCTI Platform >= 5.12.15

### Configuration

| Parameter                         | Docker envvar                     | Mandatory | Description                                                                                   |
|-----------------------------------|-----------------------------------|-----------|-----------------------------------------------------------------------------------------------|
| `opencti_url`                     | `OPENCTI_URL`                     | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                   | `OPENCTI_TOKEN`                   | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                    | `CONNECTOR_ID`                    | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_type`                  | `CONNECTOR_TYPE`                  | Yes       | Must be `EXTERNAL_IMPORT` (this is the connector type).                                       |
| `connector_name`                  | `CONNECTOR_NAME`                  | Yes       | Option `Citalid`                                                                              |
| `connector_scope`                 | `CONNECTOR_SCOPE`                 | Yes       | Supported scope                                                                               |
| `connector_run_and_terminate`     | `CONNECTOR_RUN_AND_TERMINATE`     | Yes       | Option `false` ensures continuous rerun of the connector                                      |
| `connector_log_level`             | `CONNECTOR_LOG_LEVEL`             | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `citalid_customer_sub_domain_url` | `CITALID_CUSTOMER_SUB_DOMAIN_URL` | Yes       | URL of your Citalid instance.                                                                 |
| `citalid_user`                    | `CITALID_USER`                    | Yes       | User that has access to Citalid instance.                                                     |
| `citalid_password`                | `CITALID_PASSWORD`                | Yes       | The user's password.                                                                          |
| `citalid_interval`                | `CITALID_INTERVAL`                | Yes       | The interval (in hours) between each run.                                                     |
