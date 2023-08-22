# OpenCTI GPT Enrichment Connector

This connector enriches report by fetching the external reference blogs and feeding them to OpenAI models.

<!--
General description of the connector
* What it does
* How it works
* Special requirements
* Use case description
* ...
-->

## Installation

### Requirements

- OpenCTI Platform >= 5.8.2

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `INTERNAL_ENRICHMENT` (this is the connector type).                                                                                                      |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | Option `GPT-Enrichment`                                                                                                                                          |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope: Template Scope (MIME Type or Stix Object)                                                                                                 |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                                                                             |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `gpt_enrichment_temperature`         | `GPT_ENRICHMENT_TEMPERATURE`        | Yes          | The temperature parameter                                                                                                                |
| `gpt_enrichment_model`               | `GPT_ENRICHMENT_MODEL`              | Yes          | The gpt model to use       
| `gpt_enrichment_api_key`             | `GPT_ENRICHMENT_API_KEY`            | Yes          | OpenAI API key

### Debugging ###

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

### Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->

