# ReversingLabs Spectra Intelligence Submission

Connector supports enrichment of observables and creation of indicators based on the result received from ReversingLabs Spectra Intelligence. Connector enables file submission to the Spectra Intelligence and file analysis. Based on the result, connector creates indicators, malwares, calculates score, adds labels, adds MITRE tactics and techniques and creates relationships between created objects for submitted observable.

Connector enables `file` and `url` submission to the ReversingLabs Spectra Intelligence.

The connector works for the following observable types:
- Artifact
- Url
- StixFile
- File

## Installation

### Requirements

- OpenCTI Platform >= 6.5.6
- Verified and tested on 6.0.10 and 6.5.6

### Configuration

Configuration parameters are provided using environment variables as described below. Some of them are placed directly in the `docker-compose.yml` since they are not expected to be modified by final users once they have been defined by the developer of the connector.

Expected environment variables to be set in the  `docker-compose.yml` that describe the connector itself.
Most of the times, these values are NOT expected to be changed.

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | A connector name to be shown in OpenCTI.                                                                                                                   |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope. E. g., `text/html`.                                                                                                                       |

However, there are other values which are expected to be configured by end users.
The following values are expected to be defined in the `.env` file or `/etc/environments` file.
This file is included in the `.gitignore` to avoid leaking sensitive date). 
Note tha the `.env.sample` file can be used as a reference.

The ones that follow are connector's generic execution parameters expected to be added for export connectors.

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080`                                               |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created sightings (a number between 1 and 4).                                                                             |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `connector_auto`                     | `CONNECTOR_AUTO`                    | Yes          | Enable or disable auto-enrichment on observable (default: false)                                                                                           |
| `reversinglabs_spectra_intelligence_url`    | `REVERSINGLABS_SPECTRA_INTELLIGENCE_URL`   | Yes          | Default is data.reversinglabs.com                                                                                                            |
| `reversinglabs_spectra_intelligence_username`     | `REVERSINGLABS_SPECTRA_INTELLIGENCE_USERNAME`     | Yes       | User used to connect to the ReversingLabs Spectra Intelligence APIs                                                                |
| `reversinglabs_spectra_intelligence_password`     | `REVERSINGLABS_SPECTRA_INTELLIGENCE_PASSWORD`     | Yes       | Password for user used to connect to the ReversingLabs Spectra Intelligence APIs                                                   |
| `reversinglabs_max_tlp`              | `REVERSINGLABS_MAX_TLP`             | Yes          | Maximum TLP for entity that connector can enrich                                                                                                           |
| `reversinglabs_sandbox_os`           | `REVERSINGLABS_SANDBOX_OS`          | Yes          | The platform to execute the sample on. Supported values are `windows11`, `windows10`, `windows7`, `macos11`, `linux`                                       |
| `reversinglabs_sandbox_internet_sim` | `REVERSINGLABS_SANDBOX_INTERNET_SIM` | No          | If internet simulation is set to `true`, analysis will be performed without connecting to the internet and will use a simulated network instead            |
| `reversinglabs_create_indicators`    | `REVERSINGLABS_CREATE_INDICATORS`   | Yes          | Default: `true`. Create indicators from observable based on the results received from APIs                                                                 | 
| `reversinglabs_poll_interval`        | `REVERSINGLABS_POLL_INTERVAL`       | Yes          | Default: `250`. Interval in seconds which is used to obtain result of the analysis in for loop                                                             | 


### Debugging ###

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.log_{LOG_LEVEL}("Sample message")`, i. e., `self.helper.log_error("An error message")`.

### Additional information
