# OpenCTI Vulmatch Connector

## Description

Vulmatch is an app that allows you to view disclosed vulnerabilities, providing an alert mechanism if a vulnerability is identified in a product you use.

Vulmatch serves data over a TAXII 2.1 server.

This connector ingests STIX 2.1 objects from alerts triggered in your Group from the Vulmatch TAXII 2.1 server.

* Vulmatch Website: [https://www.vulmatch.com/](https://www.vulmatch.com/)
* Vulmatch Website TAXII 2.1 Docs: [https://docs.vulmatch.com/developers/api-intro](https://docs.vulmatch.com/developers/api-intro)

This connector was built using the TAXII2 connector for [OpenCTI](https://github.com/OpenCTI-Platform/opencti) as a base.

## Configuration

### Prerequisites 

A Vulmatch account with API access enabled.

More on Vulmatch account plans here: [https://www.vulmatch.com/pricing/](https://www.vulmatch.com/pricing/)

### Install

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

| Docker Env variable | config variable | Description
| --------------------|-----------------|------------
| TAXII2_USERNAME     | username        | Your Vulmatch username
| TAXXI2_PASSWORD     | password        | Your Vulmatch API key (NOT password). Can be obtained on the Integration page here: [https://app.vulmatch.com/integrations](https://app.vulmatch.com/integrations)
| TAXII2_COLLECTIONS  | collections     | Specify what `<API Root>.<Collection Name>` you want to poll. Syntax Detailed below

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as any other Connector. You should consult the OpenCTI Connector documentation for questions about these values here: [https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8](https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8)._

### Collections and API roots

The value for `TAXII2_COLLECTIONS` should be defined as `<API Root>.<Collection Name>`.

In Vulmatch the `<API Root>` is your Vulmatch Group UUID. This can be obtained on the Group Management page here: [https://app.vulmatch.com/user/manage_group](https://app.vulmatch.com/user/manage_group).

The `<Collection Name>` is also your Vulmatch Group UUID. All alert objects for your Group are reported in your Group's collection.

An example `TAXII2_COLLECTIONS` value, assuming;

* Group UUID=`58267908-8861-4bfe-81c4-0f6ec4bf1c8`

Would be (in `config.yml`)

```
collections: '58267908-8861-4bfe-81c4-0f6ec4bf1c8.58267908-8861-4bfe-81c4-0f6ec4bf1c8'
```

## Installation

Please refer to [these](https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8) [three](https://filigran.notion.site/Introduction-9a614638a75746a391cd93a45fe3dc6c) [articles](https://filigran.notion.site/HowTo-Build-your-first-connector-06b2690697404b5ebc6e3556a1385940) in OpenCTI's documentation as the authoritative source on installing connectors.

### Docker

Build a Docker Image using the provided `Dockerfile`. Example: `docker build . -t opencti-vulmatch-import:latest`. Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`

### Manual/VM Deployment

Create a file `config.yml` based off the provided `config.yml.sample`. Replace the configuration variables (especially the "ChangeMe" variables) with the appropriate configurations for you environment. Install the required python dependencies (preferably in a virtual environment) with `pip3 install -r requirements.txt` Then, run the `python3 rf_feeds.py` command to start the connector

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at the hourly interval specified in your `docker-compose.yml` or `config.yml`. However, if you would like to force an immediate poll of the Vulmatch TAXII server, navigate to Data management -> Connectors and Workers in the OpenCTI platform. Find the "Vulmatch" connector, and click on the refresh button to reset the connector's state and force a new poll of the Collections. Please note that this will be considered a "first" poll and thus will use the `TAXII2_INITIAL_HISTORY` variable

## Verification

To verify the connector is working, you can navigate to Data->Data Curation in the OpenCTI platform and see the new imported data there. For troubleshooting or additional verification, please view the Connector logs.

**Pro-tip**: Creating a new user and API Token for the Connector can help you more easily track which STIX2 objects were created by the Connector.