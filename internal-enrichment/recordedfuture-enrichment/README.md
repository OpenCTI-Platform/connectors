# OpenCTI Recorded Future Enrichment Connector
*Contact: support@recordedfuture.com*
## Description

This connector enriches individual OpenCTI Observables with Recorded Future Information. Currently enrichment of IP Address (ipv4 and ipv6), URLs, Domains, and Hashes (MD5, SHA1, and SHA256) is supported.

## Data Model
Each enrichment pulls down an Indicator's Recorded Future Risk Score, any triggered Risk Rules, and Strings of Evidence to justify a rule being triggered. Their equivalents in OpenCTI's STIX2 model is

- Indicator -> Indicator
- Risk Score -> Note attached to Indicator
- Risk Rule -> Attack Pattern, the relationship defined as Indicator "indicates" Attack Pattern
- Evidence String -> Note Attached to Indicator
- Links:
    Mitre T codes-> Attack Patterns
    Indicators -> Indicators and Observables
    Malware -> Malware
    Threat Actors -> Threat Actors
    Organization-> Organization

Please note that not every link type from Recorded Future is supported at this time

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment). Since the `opencti` and `connector` options are the same as any other Connector, this doc only addresses the `recordedfuture-enrichment` options

Please note that if you don't want to use an optional variable, best practice is to remove it from `config.yml` or `docker-compose.yml`

| Docker Env variable | config variable | Description
| --------------------|-----------------|------------
| RECORDED_FUTURE_TOKEN   | token      | API Token for Recorded Future. Required
| RECORDED_FUTURE_TLP | TLP | TLP marking of the report. One of White, Green, Amber, Red
| RECORDED_FUTURE_CREATE_INDICATOR_THRESHOLD| create_indicator_threshold | The risk score threshold at which an indicator will be created for enriched observables. If set to zero, all enriched observables will automatically create an indicator. If set to 100, no enriched observables will create an indicator. Reccomended thresholds are: 0, 25, 65, 100


Also note that the Indicator's STIX2 confidence field is set to the Risk Score. However, at this time OpenCTI does not automatically import the STIX2 confidence field as the OpenCTI score, it's logical equivalent


## Installation

Please refer to [these](https://www.notion.so/Connectors-4586c588462d4a1fb5e661f2d9837db8) [three](https://www.notion.so/Introduction-9a614638a75746a391cd93a45fe3dc6c) [articles](https://www.notion.so/HowTo-Build-your-first-connector-06b2690697404b5ebc6e3556a1385940) in OpenCTI's documentation as the authoritative source on installing connectors.

### Docker
Build a Docker Image using the provided `Dockerfile`. Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`
### Manual/VM Deployment
Create a file `config.yml` based off the provided `config.yml.sample`. Replace the configuration variables (especially the "ChangeMe" variables) with the appropriate configurations for you environment. The `id` attribute of the `connector` should be a freshly generated UUID. Install the required python dependencies (preferably in a virtual environment) with `pip3 install -r requirements.txt` Then, run the `python3 rf_enrichment.py` command to start the connector


## Usage
To enrich an observable, first click on it in the Observations->Observables tab of the OpenCTI platform (or navigate to an observable another way). Click on the cloud in the upper right, and under "Enrichment Connectors", select the Recorded Future Enrichment connector. Depending on your configuraiton, the connector may have already run automatically. If not (or if you want to re-enrich the indicator), click on the refresh button next to the indicator to enrich
## Verification
After enriching the indicator, you should now see it has a number of notes, as well as relationships with Attack Patterns, Malware, and Indicators. Those Notes from Recorded Future contain Evidence Strings and the Risk Score. Depending on your configuration, it will also have created an Indicator, which can be seen under "Indicators composed with this observable"



