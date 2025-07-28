# OpenCTI Recorded Future Enrichment Connector

_Contact: support@recordedfuture.com_

## Description

This connector enriches individual OpenCTI Observables and Vulnerabilities with Recorded Future Information.  
For observables, currently enrichment of IP Address (ipv4 and ipv6), URLs, Domains, and Hashes (MD5, SHA1, and SHA256) only is supported.

## Dependency

- `external-import/mitre` - Maps TTPs to Existing Mitre Att&ck IDs. If the ID does not exist the relationship does not occur.

## Data Model

### Observables

Each enrichment pulls down an Indicator's Recorded Future Risk Score, any triggered Risk Rules, and Strings of Evidence to justify a rule being triggered.
Their equivalent OpenCTI models are

- Indicator -> Indicator
- Risk Score -> Note attached to Indicator
- Risk Rule:
  - Attack Pattern, the relationship defined as Indicator "indicates" Attack Pattern
  - Risk Rules are added as notes and attached to Observable
- Evidence String -> Note Attached to Indicator
- Links:
  - Mitre T codes-> Attack Patterns
  - Indicators -> Indicators and Observables
  - Malware -> Malware
  - Threat Actors -> Threat Actors
  - Organization-> Organization

Please note that not every link type from Recorded Future is supported at this time

### Vulnerabilities

Each vulnerability pulls down a RecordedFuture's Enriched Vulnerability with its common names, its lifecycle stage, a reference to the vulnerability's page on RecordedFuture and its CVSS properties.
Their equivalent OpenCTI models are

- Vulnerability:
  - common names are added as aliases
  - lifecycle stage is added as label
  - reference to RecordedFuture's page is added as external reference
  - CVSS properties are added as CVSS properties, depending on CVSS version

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment). Since the `opencti` and `connector` options are the same as any other Connector, this doc only addresses the `recordedfuture-enrichment` options

Please note that if you don't want to use an optional variable, best practice is to remove it from `config.yml` or `docker-compose.yml`

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | Config variable (`config.yml`) | Env variable (`docker-compose.yml` or `.env`) | Default | Mandatory | Description                                          |
| ------------- | ------------------------------ | --------------------------------------------- | ------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url                            | `OPENCTI_URL`                                 | /       | yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token                          | `OPENCTI_TOKEN`                               | /       | yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running an internal-enrichment connector properly:

| Parameter           | Config variable (`config.yml`) | Env variable (`docker-compose.yml` or `.env`) | Default                                                      | Mandatory | Description                                                                                                                                                |
| ------------------- | ------------------------------ | --------------------------------------------- | ------------------------------------------------------------ | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Connector ID        | id                             | `CONNECTOR_ID`                                | /                                                            | yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                                  |
| Connector Name      | name                           | `CONNECTOR_NAME`                              | `Recorded Future Enrichment`                                 | no        | Name of the connector.                                                                                                                                     |
| Connector Scope     | scope                          | `CONNECTOR_SCOPE`                             | `ipv4-addr,ipv6-addr,domain-name,url,stixfile,vulnerability` | no        | Comma-separated list of OCTI entities the connector is enriching. Options are `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `stixfile`, `vulnerability`. |
| Connector log Level | log_level                      | `CONNECTOR_LOG_LEVEL`                         | `error`                                                      | no        | Determines the verbosity of the logs. Options are `debug`, `info`, `warning`, or `error`.                                                                  |
| Connector Auto      | connector_auto                 | `CONNECTOR_AUTO`                              | `False`                                                      | no        | Must be `true` or `false` to enable or disable auto-enrichment of observables                                                                              |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for this connector:

| Parameter                                | Config variable (`config.yml`)           | Env variable (`docker-compose.yml` or `.env`)              | Default     | Mandatory | Description                                                                                                                                                                                                                                                                                   |
| ---------------------------------------- | ---------------------------------------- | ---------------------------------------------------------- | ----------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Recorded Future API token                | token                                    | `RECORDED_FUTURE_TOKEN`                                    | /           | yes       | API Token for Recorded Future.                                                                                                                                                                                                                                                                |
| Max TLP                                  | info_max_tlp                             | `RECORDED_FUTURE_INFO_MAX_TLP`                             | `TLP:AMBER` | no        | Max TLP marking of the entity to enrich (inclusive). One of `TLP:CLEAR`, `TLP:WHITE`, `TLP:GREEN`, `TLP:AMBER`, `TLP:AMBER+STRICT`, `TLP:RED`.                                                                                                                                                |
| Indicator creation threshold             | create_indicator_threshold               | `RECORDED_FUTURE_CREATE_INDICATOR_THRESHOLD`               | `0`         | no        | The risk score threshold at which an indicator will be created for enriched observables. If set to zero, all enriched observables will automatically create an indicator. If set to 100, no enriched observables will create an indicator. Reccomended thresholds are: `0`, `25`, `65`, `100` |
| Vulnerability enrichment optional fields | vulnerability_enrichment_optional_fields | `RECORDED_FUTURE_VULNERABILITY_ENRICHMENT_OPTIONAL_FIELDS` | `''`        | no        | A comma-separated list of optional fields to enrich vulnerabilities with. Currently, available fields are `analystNotes`, `aiInsights`, `risk`. See [RecordedFuture enrichment fields doc](https://docs.recordedfuture.com/reference/enrichment-field-attributes) for more details.           |

Notes:

- the Indicator's STIX2 confidence field is set to the Risk Score. However, at this time OpenCTI does not automatically import the STIX2 confidence field as the OpenCTI score, it's logical equivalent.
- the following fields are _always_ queried during vulnerabilities enrichment: `commonNames`, `cpe`, `cvss`, `cvssv3`, `cvssv4`, `intelCard`, `lifecycleStage`, `nvdDescription`, `nvdReferences`, `relatedLinks`.
  The connector supports some other optional fields, see `RECORDED_FUTURE_VULNERABILITY_ENRICHMENT_OPTIONAL_FIELDS` environment variable's description.
- the optional field `aiInsights` for vulnerability enrichment can result in a few seconds delay in requesting RecordedFuture API

## Installation

Please refer to [these](https://www.notion.so/Connectors-4586c588462d4a1fb5e661f2d9837db8) [three](https://www.notion.so/Introduction-9a614638a75746a391cd93a45fe3dc6c) [articles](https://www.notion.so/HowTo-Build-your-first-connector-06b2690697404b5ebc6e3556a1385940) in OpenCTI's documentation as the authoritative source on installing connectors.

### Docker

Build a Docker Image using the provided `Dockerfile`. Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your environment. Then, start the docker container with the provided `docker-compose.yml`

### Manual/VM Deployment

Create a file `config.yml` based off the provided `config.yml.sample`. Replace the configuration variables (especially the "ChangeMe" variables) with the appropriate configurations for you environment.
The `id` attribute of the `connector` should be a freshly generated UUID.
Install the required python dependencies (preferably in a virtual environment) with `pip3 install -r src/requirements.txt`
Then, run the `python3 src/main.py` command to start the connector

## Usage

To enrich an observable, first click on it in the Observations->Observables tab of the OpenCTI platform (or navigate to an observable another way). Click on the cloud in the upper right, and under "Enrichment Connectors", select the Recorded Future Enrichment connector. Depending on your configuraiton, the connector may have already run automatically. If not (or if you want to re-enrich the indicator), click on the refresh button next to the indicator to enrich

## Verification

After enriching the indicator, you should now see it has a number of notes, as well as relationships with Attack Patterns, Malware, and Indicators. Those Notes from Recorded Future contain Evidence Strings and the Risk Score. Depending on your configuration, it will also have created an Indicator, which can be seen under "Indicators composed with this observable"
