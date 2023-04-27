# OpenCTI Recorded Future Feeds Connector
*Contact jonah.feldman@recordedfuture.com with questions*
## Description

This connector converts Recorded Future Analyst Notes to STIX2 and imports them into OpenCTI at regular intervals

## Data Model

Each Analyst Note is converted into a a STIX2 report. The report contains STIX2 SDOs that are converted as per below

- Note Title and Content -> STIX2 report content
- Topic-> STIX2 report labels
- Validation Urls -> STIX2 report external references
- Note Entities -> Indicator, Observables, Threat Actors or other corresponding SDOs
- Detection Rules -> Indicators

Currently context entities are not converted into entities. For Note entities, only the following Recorded Future Entity types are supported

- IpAddress
- InternetDomainName
- URL
- Hash
- MitreAttackIdentifier
- Company
- Person
- Organization
- Malware
- Vulnerability




## Installation

Please refer to [these](https://www.notion.so/Connectors-4586c588462d4a1fb5e661f2d9837db8) [three](https://www.notion.so/Introduction-9a614638a75746a391cd93a45fe3dc6c) [articles](https://www.notion.so/HowTo-Build-your-first-connector-06b2690697404b5ebc6e3556a1385940) in OpenCTI's documentation as the authoritative source on installing connectors.

### Docker
Build a Docker Image using the provided `Dockerfile`. Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`

### Manual/VM Deployment
Create a file `config.yml` based off the provided `config.yml.sample`. Replace the configuration variables (especially the "ChangeMe" variables) with the appropriate configurations for you environment. Install the required python dependencies (preferably in a virtual environment) with `pip3 install -r requirements.txt` Then, run the `python3 rf_notes.py` command to start the connector

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment). Since the `opencti` and `connector` options are the same as any other Connector, this doc only addresses the `rf-notes` options

Please note that if you don't want to use an optional variable, best practice is to remove it from `config.yml` or `docker-compose.yml`

| Docker Env variable | config variable | Description
| --------------------|-----------------|------------
| RECORDED_FUTURE_TOKEN   | token      | API Token for Recorded Future. Required
| RECORDED_FUTURE_INITIAL_LOOKBACK     | initial_lookback        | The numeric timeframe the connector will search for Analyst Notes on the first run, in hours. Required
| RECORDED_FUTURE_INTERVAL          | interval            | The numeric interval (in hours) between scheduled executions of the connector. Required
| RECORDED_FUTURE_TLP | TLP | TLP marking of the report. One of White, Green, Amber, Red
| RECORDED_FUTURE_PULL_SIGNATURES     | pull_signatures        | A boolean flag of whether to pull YARA, SIGMA, and SNORT rules from hunting packages into OpenCTI. Defaults to False
| RECORDED_FUTURE_INSIKT_ONLY     | insikt_only        | A boolean flag of whether to pull analyst notes only from the Insikt research team, or whether to include notes written by Users. Defaults to True
| RECORDED_FUTURE_TOPIC     | topic        | Filter Analyst Notes on a specific topic. Topics can be found [here](https://support.recordedfuture.com/hc/en-us/articles/360006361774-Analyst-Note-API). You **must** use the topic RFID, for example aUyI9M. Only one topic per connector is allowed. Optional
| RECORDED_FUTUTRE_PERSON_TO_TA | person_to_TA | Converts all Recorded Future entities of type person to STIX object "Threat Actor" instead of individual. DO NOT USE unless you **really** know what you're doing
| RECORDED_FUTURE_TA_TO_INTRUSION_SET| TA_to_intrusion_set | Converts all Recorded Future Threat Actors to STIX Object "Intrusion Set" instead of "Threat Actor". DO NOT USE unless you **really** know what you're doing






## Usage
After Installation, the connector should require minimal interaction to use, and should update automatically at the hourly interval specified in your `docker-compose.yml` or `config.yml`. However, if you would like to force an immediate download of a new batch of Analyst notes, navigate to Data management -> Connectors and Workers in the OpenCTI platform. Find the "Recorded Future Notes" connector, and click on the refresh button to reset the connector's state and force a new download of Analyst Notes.

WARNING: manually  triggering a new run of the connector is likely to lead to duplicate Analyst Notes

## Verification
To verify that Analyst Notes have downloaded, navigate to the reports tab in the OpenCTI Platform. You should see new reports authored by the Identity Recorded Future. Click on those reports to see the indicators, Attack Patterns, and Notes imported in that Note

## Known Issues and Workarounds

### Issue: Version de-synchronization

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever version of OpenCTI you're running. Example, `pycti==5.3.1`. If you don't, the OpenCTI SDK will likely fail to initialize


### Issue: IPV6 support

Currently IPv6 IP entity types are not supported. This will be fixed in a future update
