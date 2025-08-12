# OpenCTI GreyNoise Feed

The connector uses the GreyNoise API to collect Internet Scanner IPs using a GreyNoise Feed.
You must have a GreyNoise subscription to use this feature.

## Installation

### Requirements

- OpenCTI Platform >= 5.9.6
- GreyNoise Subscription with Feed

### Configuration

| Parameter                                     | Docker envvar                                 | Mandatory | Description                                                                                                                         |
| --------------------------------------------- | --------------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                                 | `OPENCTI_URL`                                 | Yes       | The URL of the OpenCTI platform.                                                                                                    |
| `opencti_token`                               | `OPENCTI_TOKEN`                               | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                         |
| `connector_id`                                | `CONNECTOR_ID`                                | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                  |
| `connector_name`                              | `CONNECTOR_NAME`                              | Yes       | Indicates the name is `GreyNoise Feed`                                                                                              |
| `connector_scope`                             | `CONNECTOR_SCOPE`                             | Yes       | Indicates the scope is `greynoisefeed`                                                                                              |
| `connector_log_level`                         | `CONNECTOR_LOG_LEVEL`                         | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                       |
| `connector_duration_period`                   | `CONNECTOR_DURATION_PERIOD`                   | No        | The number of hours between two runs of the connector (default: 24H)                                                                |
| `greynoise_feed_api_key`                      | `GREYNOISE_FEED_API_KEY`                      | Yes       | Your GreyNoise API KEY                                                                                                              |
| `greynoise_feed_feed_type`                    | `GREYNOISE_FEED_FEED_TYPE`                    | No        | Type of Feed to import (benign, malicious, suspicious, benign+malicious, malicious+suspicious, benign+suspicious+malicious, or all) |
| `greynoise_feed_limit`                        | `GREYNOISE_FEED_LIMIT`                        | No        | Max number of indicators to ingest                                                                                                  |
| `greynoise_feed_import_metadata`              | `GREYNOISE_FEED_IMPORT_METADATA`              | No        | Import metadata (cities, sightings, etc.) (can generate a lot!)                                                                     |
| `greynoise_feed_import_destination_sightings` | `GREYNOISE_FEED_IMPORT_DESTINATION_SIGHTINGS` | No        | Import indicator's countries (from metadata) as a Sighting.                                                                         |
| `greynoise_feed_indicator_score_malicious`    | `GREYNOISE_FEED_INDICATOR_SCORE_MALICIOUS`    | No        | Default indicator score for malicious indicators                                                                                    |
| `greynoise_feed_indicator_score_suspicious`   | `GREYNOISE_FEED_INDICATOR_SCORE_SUSPICIOUS`   | No        | Default indicator score for suspicious indicators                                                                                   |
| `greynoise_feed_indicator_score_benign`       | `GREYNOISE_FEED_INDICATOR_SCORE_BENIGN`       | No        | Default indicator score for benign indicators                                                                                       |
| ~~`greynoise_feed_interval`~~                 | ~~`GREYNOISE_FEED_INTERVAL`~~                 | ~~Yes~~   | ~~Number of hours between runs~~ (Deprecated, use `connector_duration_period` instead)                                              |

### Debugging

Ensure that the GreyNoise API is reachable from the OpenCTI system. Check logs for details on where failures may occur and feel free to reach out to [support@greynoise.io](mailto:support@greynoise.io) for assistance

### Additional information

This feed will ingest a list of IPv4 indicators observed by GreyNoise and create an appropriate Indicator and Observable record. Additional vulnerability records will also be created when an associated tag is directly tied to that vulnerability.

Additional enrichment information can be retrieved using the GreyNoise enrichment integration in conjunction with this integration.
