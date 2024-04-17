# OpenCTI Recorded Future Connector

The Recorded Future connector is a standalone Python process that collect data from Recorded Future which collects data from a wide range of sources to provide comprehensive threat intelligence.

Summary

- [OpenCTI Recorded Future Connector](#opencti-recorded-future-connector)
  - [Introduction](#introduction)
  - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Recorded Future connector environment variables](#recorded-future-connector-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
    - [Analyst notes](#analyst-notes)
      - [Initial population](#initial-population)
      - [Verification](#verification)
    - [Risk Lists](#risk-lists)
      - [Initial population](#initial-population-1)
      - [Verification](#verification-1)
    - [Threat Maps](#threat-maps)
      - [Initial population](#initial-population-2)
      - [Verification](#verification-2)
  - [Known Issues and Workarounds](#known-issues-and-workarounds)
    - [Importing risk lists](#importing-risk-lists)
  - [Useful Resources](#useful-resources)

---

## Introduction

[Recorded Future](https://www.recordedfuture.com/) is a cybersecurity company that specializes in providing real-time threat intelligence to help organizations anticipate, identify, and mitigate cyber threats.

The company's platform leverages machine learning and natural language processing to analyze a vast array of source:

- **Open Web Sources**: This includes publicly accessible websites, news outlets, blogs, and forums where threat actors might discuss vulnerabilities, exploits, or plan attacks.

- **Technical Data Sources**: These include data from internet infrastructure such as domain name registries, IP address allocations, and SSL certificate logs, which can be analyzed to identify malicious activity or infrastructure.

- **Dark Web Sources**: Recorded Future also scans parts of the dark web, including forums, marketplaces, and chat services where cybercriminals often operate and trade tools, services, and stolen data.

- **Social Media**: Public posts and discussions on social media platforms can sometimes reveal information about cybersecurity threats or be used by threat actors for communication.

- **Government and Industry Reports**: Reports and bulletins from cybersecurity agencies, industry groups, and security companies often contain valuable data on recent threats, vulnerabilities, and incidents.

- **Proprietary Data Sources**: Recorded Future may also use proprietary data sources or data obtained through partnerships with other cybersecurity entities.

By aggregating and analyzing data from these diverse sources, Recorded Future can identify patterns, trends, and indicators of compromise (IoCs) that help organizations understand and mitigate cyber threats more effectively.

This connector imports _Recorded Future Analyst Notes_, the _Risk Lists_ (IP, URL, Domain Name and Hash), and _Malware_ and _Threat Actors_ from Threats Maps, converts to STIX2 and imports them into OpenCTI at regular intervals.

## Requirements

To use the connector, you need to have a Recorded Future account.

- OpenCTI Platform version 5.12.0 or higher
- An API Key for accessing

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |


### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter            | config.yml           | Docker environment variable      | Default                                                                     | Mandatory | Description                                                                                                                                 |
| -------------------- | -------------------- | -------------------------------- | --------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Connector ID         | id                   | `CONNECTOR_ID`                   | /                                                                           | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                   |
| Connector Type       | type                 | `CONNECTOR_TYPE`                 | EXTERNAL_IMPORT                                                             | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                                                                               |
| Connector Name       | name                 | `CONNECTOR_NAME`                 | Recorded Future                                                             | Yes       | Name of the connector.                                                                                                                      |
| Connector Scope      | scope                | `CONNECTOR_SCOPE`                | ipv4-addr,ipv6-addr,vulnerability,domain,url,file-sha256,file-md5,file-sha1 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.                                                    |
| Update existing data | update_existing_data | `CONNECTOR_UPDATE_EXISTING_DATA` | False                                                                       | No        | If an entity already exists, update its attributes with information provided by this connector. Takes 2 available values: `True` or `False` |
| Log Level            | log_level            | `CONNECTOR_LOG_LEVEL`            | info                                                                        | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                      |

### Recorded Future connector environment variables

Below are the parameters you'll need to set for Recorded Future connector:

| Parameter                       | config.yml                | Docker environment variable                 | Default                                               | Mandatory | Description                                                                                                                                                                                                                                                    |
| ------------------------------- | ------------------------- | ------------------------------------------- |-------------------------------------------------------| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RF Token                        | token                     | `RECORDED_FUTURE_TOKEN`                     |                                                       | Yes       | Token for the RF API.                                                                                                                                                                                                                                          |
| RF Initial lookback             | initial_lookback          | `RECORDED_FUTURE_INITIAL_LOOKBACK`          | 240                                                   | Yes       | The numeric timeframe the connector will search for Analyst Notes on the first run, required, in hours.                                                                                                                                                        |
| RF Analyst notes interval       | interval                  | `RECORDED_FUTURE_INTERVAL`                  | 240                                                   | Yes       | Interval in hours to check and import new Analyst Notes. Must be strictly greater than 1                                                                                                                                                                       |
| RF Topic                        | topic                     | `RECORDED_FUTURE_TOPIC`                     | VTrvnW,g1KBGl,ZjnoP0,aDKkpk,TXSFt5,UrMRnT,TXSFt3      | No        | Filter Analyst Notes on a specific topic. Topics can be found [here](https://support.recordedfuture.com/hc/en-us/articles/360006361774-Analyst-Note-API). You **must** use the topic RFID, for example aUyI9M. Multiple topics are allowed (separated by ','). |
| RF Marking                      | TLP                       | `RECORDED_FUTURE_TLP`                       | white                                                 | Yes       | TLP Marking for data imported, possible values: white, green, amber, red                                                                                                                                                                                       |
| RF Notes from Insikt Group      | insikt_only               | `RECORDED_FUTURE_INSIKT_ONLY`               | True                                                  | No        | A boolean flag of whether to pull analyst notes only from the Insikt research team, or whether to include notes written by Users. Default to True.                                                                                                             |
| RF Pull signatures              | pull_signatures           | `RECORDED_FUTURE_PULL_SIGNATURES`           | False                                                 | No        | Pull Yara/Snort/Sigma rules into OpenCTI                                                                                                                                                                                                                       |
| RF Person to Threat Actor       | person_to_TA              | `RECORDED_FUTURE_PERSON_TO_TA`              | False                                                 | No        | Converts all Recorded Future entities of type person to STIX object "Threat Actor" instead of individual when import Analyst Notes. DO NOT USE unless you **really** know what you're doing                                                                    |
| RF Theat Actor to Intrusion Set | TA_to_intrusion_set       | `RECORDED_FUTURE_TA_TO_INTRUSION_SET`       | False                                                 | No        | Converts all Recorded Future Threat Actors to STIX Object "Intrusion Set" instead of "Threat Actor" when Analyst Notes are imported. DO NOT USE unless you **really** know what you're doing                                                                   |
| RF Risk as score                | risk_as_score             | `RECORDED_FUTURE_RISK_AS_SCORE`             | True                                                  | No        | Use Recorded Future "risk" as a score for STIX when Analyst Notes are imported                                                                                                                                                                                 |
| RF Risk threshold               | risk_threshold            | `RECORDED_FUTURE_RISK_THRESHOLD`            | 60                                                    | No        | A threshold under which related indicators are not taken into account. Indicators related to Analyst Notes.                                                                                                                                                    |
| RF Pull risk list               | pull_risk_list            | `RECORDED_FUTURE_PULL_RISK_LIST`            | False                                                 | No        | A boolean flag of whether to pull risk lists into OpenCTI.                                                                                                                                                                                                     |
| RF Risk list interval           | risk_list_interval        | `RECORDED_FUTURE_RISK_LIST_INTERVAL`        | 48                                                    | Yes       | Interval in hours to check and import Risk Lists. Must be strictly greater than 1                                                                                                                                                                              |
| RF Risk list threshold          | risk_list_threshold       | `RECORDED_FUTURE_RISK_LIST_THRESHOLD`       | 70                                                    | No        | A threshold under which related indicators are not taken into account. Indicators from Risk Lists.                                                                                                                                                             |
| RF Risk list related entities   | risklist_related_entities | `RECORDED_FUTURE_RISKLIST_RELATED_ENTITIES` | 'Malware,Hash,URL,Threat Actor,MitreAttackIdentifier' | Yes       | Related entities to an indicator from Risk List when it's imported. Required if pull_risk_list is True, possible values: Malware,Hash,URL,Threat Actor,MitreAttackIdentifier. Multiple related entities are allowed (separated by ',')                         |
| RF Pull threat maps             | pull_threat_maps          | `RECORDED_FUTURE_PULL_THREAT_MAPS`          | False                                                 | No        | A boolean flag of whether to pull entities from Threat Maps into OpenCTI.                                                                                                                                                                                      |
| RF Threat maps interval         | threat_maps_interval      | `RECORDED_FUTURE_THREAT_MAPS_INTERVAL`      | 24                                                    | Yes       | Interval in hours to check and import entities from Threat Maps. Must be strictly greater than 1                                                                                                                                                               |


## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from recorded-future/src:

```shell
python3 main.py
```
## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at the hourly interval specified in your `docker-compose.yml` or `config.yml`.

However, if you would like to force an immediate download of a new batch of Analyst Notes, Risk Lists (when it is configured to `True`) or entities from Threat Maps (when it is configured to `True`), navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform. 

Find the "Recorded Future" connector, and click on the refresh button to reset the connector's state and force a new download of data by re-running the connector.

![Reset the connector state](./__docs__/media/rf-reset-connector.gif)


## Behavior

### Analyst notes

Analyst Notes are notes which include analysis and insights from Insikt Group research or the organization's notes.

#### Initial population

For the first run of the connector, the connector will import Analyst Notes from Recorded Future's [Insikt Group research](https://www.recordedfuture.com/research).

Example of connector logs:

_TLP: green_

_pull_signatures: True_

_insikt_only: True_

![RF logs](./__docs__/media/rf-logs.png)

Each Analyst Note is converted into a STIX2 report. The report contains STIX2 SDOs that are converted as per below

- Note Title and Content -> STIX2 report content
- Topic-> STIX2 report labels
- Validation Urls -> STIX2 report external references
- Note Entities -> Indicator, Observables, Threat Actors or other corresponding SDOs
- Detection Rules -> Indicators

For Note entities, the following Recorded Future Entity types are supported:

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
- Software
- Location: Country, City, Administrative-Area
- Sector
- Campaign
- Threat Actor

The context have been added now following the relationships below:

![mapping relationships](./__docs__/media/mapping-relationships.png)

Example of result in the OpenCTI platform Report knowledge graph:

![Knowledge graph](./__docs__/media/analystnote-graph.png)

Give a value for the `interval` (config.yml for local deployment) or `RECORDED_FUTURE_INTERVAL` (docker-compose.yml file for deployment with Docker containers) allows you to pull Analyst Notes at regular intervals and retrieve notes from the last published date.

#### Verification

To verify that Analyst Notes have downloaded, navigate to the `Analyses` -> `Reports` tab in the OpenCTI Platform. You should see new reports authored by the Identity Recorded Future. Click on those reports to see the details and on `Knowledge` to see the context for that Note.

Example of result in the OpenCTI platform `Analyses` -> `Reports` and selecting one report:

![Example of report](./__docs__/media/rf-reports.png)

### Risk Lists

Recorded Future comes equipped with five Recorded Future Risk Lists, which serve to correlate and enhance event data. These lists include:

- IP addresses
- Domain names
- URLs
- File hashes
- Vulnerabilities (primarily CVEs)

Subscribers who have API access can retrieve lists of entities that have been assigned risk scores by Recorded Future by utilizing the Connect API calls.

Every item in a Risk List, whether it's an IP address, domain, or another element, comes with a risk score and the details that influenced that score. Additionally, having Fusion access enables the customization of Risk Lists.

Vulnerabilities are not handled by the connector.

#### Initial population

The connector allows you to pull STIX formatted risk lists selected by risk score and indicators with risk score >= 65 are included in the list.

The following fields are included with each Risk List:

- `Name` as the value for OpenCTI IoC
- `Risk` as the score of IoC
- `RiskRules` and `RuleCriticality` will be added ***in description*** of IoC, they define the ruletriggered by the IoC and the severity of the criticality score
- `FirstSeen` as the date when the IoC was first seen
- `LastSeen` as the date when the IoC was last seen
- `Links` as related entities to the IoC

One notable aspect of `RiskRules` and `RuleCriticality` is that while rule severity ranges from 1 to 4, the connector specifically includes in its descriptions only those rules rated as 3-Malicious and 4-Very Malicious.

Example of the result in the description for an Indicator:

*pull_risk_list: True*

![IOC description](./__docs__/media/rf-ioc-description.png)

If `pull_risk_list` is `True`, the `risk_list_interval` is **REQUIRED** and the `risk_list_related_entities` is **REQUIRED** (at least one value must be set). This configuration allows you to choose the context that you would like to import related to the targetting IP, Domain, Hash file or URL between: "Malware", "Hash", "URL", "Threat Actor", "MitreAttackIdentifier".

For example, if you want to perform an investigation on an indicator:

![RF IOC related entities](./__docs__/media/rf-risklist-related-entities.png)

Risk Lists and Analyst Notes can be retrieved simultaneously by the connector.

Give a value for the `risk_list_interval` (config.yml for local deployment) or `RECORDED_FUTURE_RISK_LIST_INTERVAL` (docker-compose.yml file for deployment with Docker containers) allows you to pull Risk Lists at regular intervals.

#### Verification

To verify that Risk Lists have been imported, navigate to the `Observations` -> `Indicators` tab in the OpenCTI Platform. You should see new indicators authored by the Identity Recorded Future. Click on those indicators to see the details, and on `Knowledge` to see the relationships with the related entities configured.

An example of the expected result:

![RF IOC knowledge](./__docs__/media/rf-risklist-knowledge.png)

### Threat Maps

Threat Maps provides a structured, repeatable method of identifying and prioritizing Threat Actors or Malware relevant to your enterprise and plotting them based on their values for potential intent and estimated opportunity.

These Threat Maps are based on your configured watchlist for example for the Industry Watch List check industry entities associated with the organization per Recorded Future ontologies.

The connector will import all `Threat Actors` and all `Malware` from the related threat maps.

#### Initial population

Pulling threat maps is Optional. If `pull_threat_maps` is `True`, the `threat_maps_interval` is **REQUIRED**.

Give a value for the `threat_maps_interval` (config.yml for local deployment) or `RECORDED_FUTURE_THREAT_MAPS_INTERVAL` (docker-compose.yml file for deployment with Docker containers) allows you to pull Threat Maps at regular intervals.

The connector will import all Malware and Threat Actors with their context.

Threat Actors will be registered as in `Intrusion Set`.

Example of result for an Intrusion Set:

![RF Threat Maps Intrusion Set](./__docs__/media/rf-threatmaps-is.png)

Example of result if you want to perform an investigation on an intrusion set and see the context:

![RF Threat Maps relationships](./__docs__/media/rf-threatmaps-relationship.png)

#### Verification

To verify that Risk Lists have been imported, navigate to the `Threats` -> `Intrusion Set` tab in the OpenCTI Platform. You should see new intrusion sets authored by the Identity Recorded Future. Click on those intrusion sets to see the details, and on `Knowledge` to see the relationships with the related entities configured.

## Known Issues and Workarounds

### Importing risk lists

Importing risk lists along with their associated entities can result in a large amount of data. Currently, you can use the `risklist_related_entities` configuration to apply filters.

For example, importing risk list with related IP Address:

![RF Risk List volume](./__docs__/media/rf-risklist-volume.png)

You need to have a minimum of 2 workers if `pull_risk_list` is `True` to ingest properly all data in queue before the end of the interval and an interval of 48 hours is highly recommended to avoid stacking a lot of data in the RabbitMQ Recorded Future connector queue.

---

## Useful Resources

OpenCTI documentation for connectors:

- [OpenCTI Ecosystem](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76)
- [Connectors Deployment](https://docs.opencti.io/latest/deployment/connectors/)
- [Connectors Development](https://docs.opencti.io/latest/development/connectors/)
