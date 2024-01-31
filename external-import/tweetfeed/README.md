# Tweetfeed

## Description

Tweetfeed connect is a project aimed to collect evidences from Tweetfeed project.  

This connector ingests [Tweetfeed](https://tweetfeed.live/) IOC in order to import Observables and Indicator collected from different researchers. Tweetfeed was developed by [Daniel López](https://twitter.com/0xDanielLopez).  
This connector was built using the TAXII2 connector for [OpenCTI](https://github.com/OpenCTI-Platform/opencti) as a base.
> **IMPORTANT**: Due to changes in the Twitter/X API, TweetFeed is no longer maintainable. Be aware that no new information beyond July 19, 2023 will be retrieved via this connector.


### Prerequisites

An openCTI instance.

## Installation

Please refer to [these](https://docs.opencti.io/latest/deployment/connectors/) [three](https://docs.opencti.io/latest/deployment/troubleshooting/) [articles](https://docs.opencti.io/latest/development/connectors/) in OpenCTI's documentation as the authoritative source on installing connectors.

### Configuration

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

| Docker Env variable            | config variable      | mandatory |Description
|--------------------------------|----------------------|------|-----------
| TWEETFEED_CONFIDENCE_LEVEL     | confidence_level     |      |Confidence of hte injested data from 0-100
| TWEETFEED_INTERVAL             | interval             | X    |In day when the connector will run
| TWEETFEED_CREATE_INDICATORS    | create_indicators    |      |True or False , enable the creation of indicators default is True
| TWEETFEED_CREATE_OBSERVABLES   | create_observables   |      |True or False , enable the creation of observables default is True
| TWEETFEED_UPDATE_EXISTING_DATA | update_existing_data |      |True or False , updates the data
| TWEETFEED_ORG_DESCRIPTION      | org_description      | X    |Organization description, which will be refered to data injected
| TWEETFEED_ORG_NAME             | org_name             | X    |Organization name, which will be refered to data injected

The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as any other Connector. You should consult the OpenCTI Connector documentation for questions about these values here: [https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8](https://filigran.notion.site/Connectors-4586c588462d4a1fb5e661f2d9837db8)._

### Docker

Build a Docker Image using the provided `Dockerfile`. Example: `docker build . -t opencti-tweetfeed:latest`. Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`

### Manual/VM Deployment

Create a file `config.yml` based off the provided `config.yml.sample`. Replace the configuration variables (especially the "ChangeMe" variables) with the appropriate configurations for you environment. Install the required python dependencies (preferably in a virtual environment) with `pip3 install -r requirements.txt` Then, run the `python3 tweetfeed.py` command to start the connector.

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at the hourly interval specified in your `docker-compose.yml` or `config.yml`. However, if you would like to force an immediate poll from the configured sources, navigate to Data management -> Connectors and Workers in the OpenCTI platform. Find the "Tweetfeed" connector, and click on the refresh button to reset the connector's state and force a new poll of the Collections. 

## Verification

To verify the connector is working, you can navigate to Data->Data Curation in the OpenCTI platform and see the new imported data there. For troubleshooting or additional verification, please view the Connector logs.
