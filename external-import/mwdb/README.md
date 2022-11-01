# OpenCTI MWDB Connector

## Description

MWDB is an opensource malware collector and databases.  https://mwdb.readthedocs.io/en/latest/user-guide/1-Introduction-to-MWDB.html

This connector ingests malware feeds in order to import Observables and Indicator related to malwares and their configurations.

* MWDB Documentation: [https://mwdb.readthedocs.io/en/latest/user-guide/1-Introduction-to-MWDB.html](https://mwdb.readthedocs.io/en/latest/user-guide/1-Introduction-to-MWDB.html)
* MWDB Repository: [https://github.com/CERT-Polska/mwdb-core](https://github.com/CERT-Polska/mwdb-core)

This connector was built using the TAXII2 connector for [OpenCTI](https://github.com/OpenCTI-Platform/opencti) as a base.

### Prerequisites

A MWDB instance and user with a token who could query the API and use `older_than` parameter.

If you are using it independently, remember that the connector will try to connect to
the RabbitMQ on the port configured in the OpenCTI platform.

## Installation

Please refer to [these](https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8) [three](https://filigran.notion.site/Introduction-9a614638a75746a391cd93a45fe3dc6c) [articles](https://filigran.notion.site/HowTo-Build-your-first-connector-06b2690697404b5ebc6e3556a1385940) in OpenCTI's documentation as the authoritative source on installing connectors.


### Configuration

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

| Docker Env variable       | config variable      | mandatory |Description
|---------------------------|----------------------|-----------|-----------
| MWDB_URL                  | url                  | X         |MWDB endpoint where API are exposed
| MWDB_CONFIDENCE_LEVEL     | confidence_level     |           |Confidence of hte injested data from 0-100
| MWDB_INTERVAL             | interval             | X         |In day when the connector will run
| MWDB_TOKEN                | token                | X         |MWDB user Token
| MWDB_IMPORT_CONFIG        | import_config        |           |True or False , enable the ijection of the malware configs
| MWDB_CREATE_INDICATORS    | create_indicators    |           |True or False , enable the creation of indicators
| MWDB_CREATE_OBSERVABLES   | create_observables   |           |True or False , enable the creation of observables
| MWDB_UPDATE_EXISTING_DATA | update_existing_data |           |True or False , updates the data
| MWDB_ORG_DESCRIPTION      | org_description      | X         |Organization name, which will be refered to data injected
| MWDB_ORG_NAME             | org_name             | X         |Organization description
| MWDB_START_DATE           | start_date           |           |A Starting date used to run the first time. ex 2022-06-27T00:00:00.000Z
| MWDB_TAG_FILTER           | collections          |           |A regex used to filter tags which could be related to malwares ex `virusshare.*|bazaar-.*|malshare-.*|apt20\d{2}`
| MWDB_MAX_START_RETENTION  | start_retention      | X         |A default retention if MWDB_START_DATE isn't configured is an INT and it reflects months , 6 is defualt.

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as any other Connector. You should consult the OpenCTI Connector documentation for questions about these values here: [https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8](https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8)._


### Docker

Build a Docker Image using the provided `Dockerfile`. Example: `docker build . -t opencti-mwdb-import:latest`. Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`

### Manual/VM Deployment

Create a file `config.yml` based off the provided `config.yml.sample`. Replace the configuration variables (especially the "ChangeMe" variables) with the appropriate configurations for you environment. Install the required python dependencies (preferably in a virtual environment) with `pip3 install -r requirements.txt` Then, run the `python3 rf_feeds.py` command to start the connector

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at the hourly interval specified in your `docker-compose.yml` or `config.yml`. However, if you would like to force an immediate poll of the MWDB instance, navigate to Data management -> Connectors and Workers in the OpenCTI platform. Find the "MWDB" connector, and click on the refresh button to reset the connector's state and force a new poll of the Collections. Please note that this will be considered a "first" poll and thus will use the `MWDB_START_DATE` variable

## Verification

To verify the connector is working, you can navigate to Data->Data Curation in the OpenCTI platform and see the new imported data there. For troubleshooting or additional verification, please view the Connector logs.
