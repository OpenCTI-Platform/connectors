# OpenCTI Feedly Connector

The OpenCTI Feedly connector allows you to import data from Feedly boards and folders. The connector leverages the Feedly API to retrieve the latest articles, and ingest them in OpenCTI with the relevant entities, indicators, detection rules, and relationships between the entities mentioned.

**Disclaimer** You will need the Feedly for Threat Intelligence package to enable this integration. You can learn more about our product here: https://feedly.com/i/landing/threatIntelligence

## Installation

1. Go to [this page](https://feedly.com/i/team/api) and click on `NEW API TOKEN` to generate a Feedly API key
2. For each stream (board/folder) you want to integrate with OpenCTI, you can find its stream id by:
   1. Selecting the stream
   2. Clicking on the 3 dots `...` at the top right of the page
   3. Clicking on `Sharing`
   4. Clicking on `Copy ID` in the `Feedly API Stream ID` section.
3. Follow this guide to deploy the connector: https://github.com/OpenCTI-Platform/connectors


### Requirements

- OpenCTI Platform >= 6.2.9

### Configuration

| Parameter                    | Docker envvar                | Mandatory    | Description                                                                                   |
|------------------------------|------------------------------| ------------ |-----------------------------------------------------------------------------------------------|
| `opencti_url`                | `OPENCTI_URL`                | Yes          | The URL of the OpenCTI platform.                                                              |
| `opencti_token`              | `OPENCTI_TOKEN`              | Yes          | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`               | `CONNECTOR_ID`               | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_name`             | `CONNECTOR_NAME`             | Yes          | Option `Feedly`                                                                               |
| `connector_scope`            | `CONNECTOR_SCOPE`            | Yes          | Supported scope: Template Scope (MIME Type or Stix Object)                                    |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | Yes          | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`        | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `feedly_source_ids`          | `FEEDLY_SOURCE_IDS`          | Yes          | A comma separated list of source ids you want to integrate                                    |
| `feedly_api_key`             | `FEEDLY_API_KEY`             | Yes          | The API key of your Feedly account, to generate here https://feedly.com/i/team/api            |
| `feedly_days_to_back_fill`   | `FEEDLY_DAYS_TO_BACK_FILL`   | Yes          | The number of days to back fill for new stream ids                                            |
| `feedly_interval`            | `FEEDLY_INTERVAL`            | Yes          | The interval (in minutes) between each run                                                    |
