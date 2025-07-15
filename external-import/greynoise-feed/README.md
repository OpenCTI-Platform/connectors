# OpenCTI GreyNoise Feed

The connector uses the GreyNoise API to collect Internet Scanner IPs using a GreyNoise Feed.
You must have a GreyNoise subscription to use this feature.

## Installation

### Requirements

- OpenCTI Platform >= 5.9.6
- GreyNoise Subscription with Feed

### Configuration

| Parameter                                  | Docker envvar                          | Mandatory | Description                                                                                                                         |
|--------------------------------------------|----------------------------------------|-----------|-------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                              | `OPENCTI_URL`                          | Yes       | The URL of the OpenCTI platform.                                                                                                    |
| `opencti_token`                            | `OPENCTI_TOKEN`                        | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                         |
| `connector_id`                             | `CONNECTOR_ID`                         | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                  |
| `connector_type`                           | `CONNECTOR_TYPE`                       | Yes       | Indicates this is an EXTERNAL_IMPORT connector                                                                                      |
| `connector_name`                           | `CONNECTOR_NAME`                       | Yes       | Indicates the name is `GreyNoise Feed`                                                                                              |
| `connector_scope`                          | `CONNECTOR_SCOPE`                      | Yes       | Indicates the scope is `greynoisefeed`                                                                                              |
| `connector_log_level`                      | `CONNECTOR_LOG_LEVEL`                  | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                       |
| `greynoisefeed_api_key`                    | `GREYNOISE_API_KEY`                    | Yes       | Your GreyNoise API KEY                                                                                                              |
| `greynoisefeed_feed_type`                  | `GREYNOISE_FEED_TYPE`                  | No        | Type of Feed to import (benign, malicious, suspicious, benign+malicious, malicious+suspicious, benign+suspicious+malicious, or all) |
| `greynoisefeed_indicator_score_malicious`  | `GREYNOISE_INDICATOR_SCORE_MALICIOUS`  | No        | Default indicator score for malicious indicators                                                                                    |
| `greynoisefeed_indicator_score_suspicious` | `GREYNOISE_INDICATOR_SCORE_SUSPICIOUS` | No        | Default indicator score for suspicious indicators                                                                                   |
| `greynoisefeed_indicator_score_benign`     | `GREYNOISE_INDICATOR_SCORE_BENIGN`     | No        | Default indicator score for benign indicators                                                                                       |
| `greynoisefeed_limit`                      | `GREYNOISE_LIMIT`                      | Yes       | Max number of indicators to ingest                                                                                                  |
| `greynoisefeed_import_metadata`            | `GREYNOISE_IMPORT_METADATA`            | No        | Import metadata (cities, sightings, etc.) (can generate a lot!)                                                                     |
| `greynoisefeed_interval`                   | `GREYNOISE_INTERVAL`                   | Yes       | Number of hours between runs                                                                                                        |
| `greynoise_name`                           | `GREYNOISE_NAME`                       | Yes       | The GreyNoise organization name                                                                                                     |
| `greynoise_description`                    | `GREYNOISE_DESCRIPTION`                | Yes       | The GreyNoise organization description                                                                                              |

### Debugging ###

Ensure that the GreyNoise API is reachable from the OpenCTI system. Check logs for details on where failures may occur and feel free to reach out to [support@greynoise.io](mailto:support@greynoise.io) for assistance

### Additional information

This feed will ingest a list of IPv4 indicators observed by GreyNoise and create an appropriate Indicator and Observable record. Additional vulnerability records will also be created when an associated tag is directly tied to that vulnerability.

Additional enrichment information can be retrieved using the GreyNoise enrichment integration in conjunction with this integration.