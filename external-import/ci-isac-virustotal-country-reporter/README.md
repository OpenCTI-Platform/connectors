# CI-ISAC OpenCTI VirusTotal Country Reporter

The connector uses the VirusTotal API to scrape recent risky files and their relationships from a country of your choice. It compiles the findings into a report that is published based on your given `duration_period`, daily works well.

**Example**

```
docker run \
  -d \
  --name="connector-virustotal-reporter" \
  -e TZ="Australia/Sydney" \
  -e OPENCTI_URL="https://ci-isac.octi.filigran.io/" \
  -e OPENCTI_TOKEN="ChangeMe" \
  -e QUEUE_PROTOCOL="api" \
  -e CONNECTOR_ID="0968ce24-c882-4a2a-842c-80a4466b5910" \
  -e CONNECTOR_NAME="CI-ISAC VirusTotal Country Reporter" \
  -e CONNECTOR_SCOPE="vtreporter" \
  -e CONNECTOR_LOG_LEVEL="info" \
  -e CONNECTOR_DURATION_PERIOD="P1D" \
  -e VTREPORTER_API_URL="https://virustotal.com/api/v3" \
  -e VTREPORTER_API_KEY="ChangeMe" \
  -e VTREPORTER_COUNTRY="AU" \
  -e VTREPORTER_THREAT_TYPES="THREAT-REPORT" \
  -e VTREPORTER_CONFIDENCE="75" \
  -e VTREPORTER_REPORT_LABELS="ci-isac-nio-feed,Australia" \
  -e VTREPORTER_RELIABILITY="B - Usually Reliable" \
  -e VTREPORTER_REPORT_MARKINGS="TLP_AMBER" \
  -e VTREPORTER_FILE_LABELS="ci-isac-nio-feed,Australia" \
  -e VTREPORTER_FILE_MARKINGS="TLP_AMBER" \
  atunnecliffe/connector-virustotal-reporter:latest
```

## Installation

### Requirements

- OpenCTI Platform >= 6.5.1

## Configuration Variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI Environment Variables

Below are the parameters you'll need to set so our connector can communicate with OpenCTI.

| Parameter | config.yml | Docker envvar | Mandatory | Description |
| -         | -          |  -            | -         | -           |
| `opencti_url` | `url` | `OPENCTI_URL` | Yes | The URL of the OpenCTI platform. |
| `opencti_token` | `token` | `OPENCTI_TOKEN` | Yes | The default admin token set in the OpenCTI platform. |


### Base Connector Environment Variables

Below are the parameters you'll need to set so OpenCTI can understand and represent our connector.

| Docker envvar | config.yml | Mandatory | Description |
| -             | -          | -         | -           |
| `CONNECTOR_ID` | `id` | Yes | A valid arbitrary `UUIDv4` that must be unique for this connector. |
| `CONNECTOR_NAME` | `name` | Yes | Name of the connector |
| `CONNECTOR_TYPE` | `type` | Yes | Should always be set to `EXTERNAL_IMPORT` for this connector |
| `CONNECTOR_DURATION_PERIOD` | `duration_period` | Yes | Interval between runs in ISO-8601
| `CONNECTOR_SCOPE`| `scope` | Yes | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| `CONNECTOR_LOG_LEVEL` | `log_level` | Yes | The log level for this connector, could be `debug`, `info`, `warn` or `error`. |

### Extra Connector Environment Variables

Below are the parameters you'll need to set so the connector can function.

| Docker envvar | config.yml | Mandatory | Default | Description |
| -             | -          | -         | -       | -           |
| `VTREPORTER_API_URL` | `api_url` | Yes | https://virustotal.com/api/v3 | VirusTotal URI Base |
| `VTREPORTER_API_KEY` | `api_key` | Yes | none | Your VirusTotal API Key |
| `VTREPORTER_COUNTRY` | `country` | Yes | AU | ISO country code you want to report on |
| `VTREPORTER_THREAT_TYPES` | `threat_types` | Yes | THREAT-REPORT | Populate field in OpenCTI interface |
| `VTREPORTER_CONFIDENCE` | `confidence` | Yes | 75 | Populate field in OpenCTI interface |
| `VTREPORTER_REPORT_LABELS` | `report_labels` | Yes | ci-isac-vt-feed,Australia | Populate field in OpenCTI interface, comma-separated makes multiple labels. |
| `VTREPORTER_RELIABILITY` | `reliability` | Yes | B - Usually Reliable | Populate field in OpenCTI interface |
| `VTREPORTER_REPORT_MARKINGS` | `report_markings` | Yes | TLP_AMBER | Populate field in OpenCTI interface |
| `VTREPORTER_FILE_LABELS` | `file_labels` | Yes | ci-isac-vt-feed,Australia | Populate field in OpenCTI interface, comma-separated makes multiple labels. |
| `VTREPORTER_FILE_MARKINGS` | `file_markings` | Yes | TLP_AMBER | Populate field in OpenCTI interface |

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior

<!--
Describe how the connector functions:
* What data is ingested, updated, or modified
* Important considerations for users when utilizing this connector
* Additional relevant details
-->

## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

<!--
Any additional information about this connector
* What information is ingested/updated/changed
* What should the user take into account when using this connector
* ...
-->