# OpenCTI GreyNoise Feed

The connector uses the GreyNoise API to collect Internet Scanner IPs based on Classification or Tag Name(s).
You must have a GreyNoise subscription to use this feature.

## Installation

### Requirements

- OpenCTI Platform >= 5.9.6

### Configuration

| Parameter                    | Docker envvar                | Mandatory | Description                                                                                   |
|------------------------------|------------------------------|-----------|-----------------------------------------------------------------------------------------------|
| `opencti_url`                | `OPENCTI_URL`                | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`              | `OPENCTI_TOKEN`              | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`               | `CONNECTOR_ID`               | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_type`             | `CONNECTOR_TYPE`             | Yes       | Select if list will pull from `feed` or `tags`                                                    |
| `connector_name`             | `CONNECTOR_NAME`             | Yes       |                                                                                               |
| `connector_scope`            | `CONNECTOR_SCOPE`            | Yes       |                                                                                               |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL` | Yes       | The default confidence level for created sightings (a number between 1 and 100).              |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`        | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `GREYNOISE_API_KEY`          | `GREYNOISE_API_KEY`          | Yes       | Your GreyNoise API KEY                                                                        |
| `GREYNOISE_SOURCE`           | `GREYNOISE_SOURCE`     | Yes       | Indicates if IPs will be FEED or Tag Based                                                    |
| `GREYNOISE_FEED_TYPE`        | `GREYNOISE_FEED_TYPE`     | No        | Type of Feed to import (benign, malicious, all)                                               |
| `GREYNOISE_TAG_LIST`         | `GREYNOISE_TAG_LIST`     | No        | List of GreyNoise Tag names to import from                                                    |
| `GREYNOISE_LIMIT`            | `GREYNOISE_LIMIT`            | Yes       | Max number of indicators to ingest                                                            |
| `GREYNOISE_INTERVAL`         | `GREYNOISE_INTERVAL`            | Yes       | interval between 2 collect itself                                                             |
### Debugging ###

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

### Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->

