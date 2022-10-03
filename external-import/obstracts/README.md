# OpenCTI Obstracts Connector

## Description

Obstracts is an RSS reader that extracts structure intelligence (in STIX 2.1 format) from blog posts.

Obstracts serve data over a TAXII 2.1 server.

This connector ingests STIX 2.1 objects from the Obstracts TAXII 2.1 server.

* Obstracts Website: [https://www.obstracts.com/](https://www.obstracts.com/)
* Obstracts Website TAXII 2.1 Docs: [https://docs.obstracts.com/developers/api-intro](https://docs.obstracts.com/developers/api-intro)

This connector was built using the TAXII2 connector for [OpenCTI](https://github.com/OpenCTI-Platform/opencti) as a base.

## Configuration

### Prerequisites 

An Obstracts account with API access enabled.

More on Obstracts account plans here: [https://www.obstracts.com/pricing/](https://www.obstracts.com/pricing/)

### Install

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

| Docker Env variable | config variable | Description
| --------------------|-----------------|------------
| TAXII2_USERNAME     | username        | Your Obstracts username
| TAXXI2_PASSWORD     | password        | Your Obstracts API key (NOT password). Can be obtained on the Integration page here: [https://app.obstracts.com/integrations](https://app.obstracts.com/integrations)
| TAXII2_COLLECTIONS  | collections     | Specify what `<API Root>.<Collection Name>` you want to poll. Syntax Detailed below

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as any other Connector. You should consult the OpenCTI Connector documentation for questions about these values here: [https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8](https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8)._

### Collections and API roots

The value for `TAXII2_COLLECTIONS` should be defined as `<API Root>.<Collection Name>`.

In Obstracts the `<API Root>` is your Obstracts Group UUID. This can be obtained on the Group Management page here: [https://app.obstracts.com/user/manage_group](https://app.obstracts.com/user/manage_group).

The `<Collection Name>` is an Obstracts Feed UUID. This can be obtained on the Feed List page here: [https://app.obstracts.com/feed/list/](https://app.obstracts.com/feed/list/).

An example `TAXII2_COLLECTIONS` value, assuming;

* Group UUID=`58267908-8861-4bfe-81c4-0f6ec4bf1c8`
* Feed UUID=`57b712a4-80ba-40fc-b2c4-3fa89a5c9ac5`

Would be (in `config.yml`)

```
collections: '58267908-8861-4bfe-81c4-0f6ec4bf1c8.57b712a4-80ba-40fc-b2c4-3fa89a5c9ac5'
```

If you want to ingest multiple collections (Obstracts feeds) you can pass as a comma separated list, e.g.

```
collections: '58267908-8861-4bfe-81c4-0f6ec4bf1c8.57b712a4-80ba-40fc-b2c4-3fa89a5c9ac5,58267908-8861-4bfe-81c4-0f6ec4bf1c8.4792093a-a543-41ed-9d7b-d7a2052e64f6'
```

Furthermore, this argument supports the use of `*` as a wildcard operator. To Poll all collections (Obstracts feeds) in your Group, you could use the syntax `GROUP_UUID.*`. e.g.

```
collections: '58267908-8861-4bfe-81c4-0f6ec4bf1c8.*'
```

## Installation

Please refer to [these](https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8) [three](https://filigran.notion.site/Introduction-9a614638a75746a391cd93a45fe3dc6c) [articles](https://filigran.notion.site/HowTo-Build-your-first-connector-06b2690697404b5ebc6e3556a1385940) in OpenCTI's documentation as the authoritative source on installing connectors.

### Docker

Build a Docker Image using the provided `Dockerfile`. Example: `docker build . -t opencti-obstracts-import:latest`. Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`

### Manual/VM Deployment

Create a file `config.yml` based off the provided `config.yml.sample`. Replace the configuration variables (especially the "ChangeMe" variables) with the appropriate configurations for you environment. Install the required python dependencies (preferably in a virtual environment) with `pip3 install -r requirements.txt` Then, run the `python3 rf_feeds.py` command to start the connector

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at the hourly interval specified in your `docker-compose.yml` or `config.yml`. However, if you would like to force an immediate poll of the Obstracts TAXII server, navigate to Data management -> Connectors and Workers in the OpenCTI platform. Find the "Obstracts" connector, and click on the refresh button to reset the connector's state and force a new poll of the Collections. Please note that this will be considered a "first" poll and thus will use the `TAXII2_INITIAL_HISTORY` variable

## Verification

To verify the connector is working, you can navigate to Data->Data Curation in the OpenCTI platform and see the new imported data there. For troubleshooting or additional verification, please view the Connector logs.

**Pro-tip**: Creating a new user and API Token for the Connector can help you more easily track which STIX2 objects were created by the Connector.