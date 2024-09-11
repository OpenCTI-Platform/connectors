# VirusTotal Connector

* This connector checks files, IP addresses, domains, and URLs against the VirusTotal API for enrichment.
* It requires a VirusTotal API Key.

* The following outputs are enabled by default, and are configurable:
  * Full findings are reported as a table in a new note that is attached to the entity being enriched
  * The score of the indicator will be adjusted to the count of VT engines that find the entity to be a positive
  * If an observable has a count of positive findings over 10, a corresponding indicator will be created.
  * For the corresponding indicator, the **Detection** flag will be set to TRUE
  * If a sample of the artifact is available and not yet in OpenCTI, it will be imported (if under 32MB)

  

## Installation

### Requirements

- OpenCTI Platform >= 6.0.6

### Configuration

Configuration parameters are provided using environment variables as described below.

#### Common OpenCTI Parameters

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform. No trailing `/`. Example: `http://opencti:8080`.                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token from OpenCTI platform settings.                                                                                                    |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | A connector name to be shown in OpenCTI.                                                                                                                   |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope. E.g., `file`, `domain`, `ip`, `url`.                                                                                                       |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A unique `UUIDv4` for this connector.                                                                                                                      |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | Default confidence level for created indicators (1-4).                                                                                                     |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | Log level: `debug`, `info`, `warn`, or `error`.                                                                                                           |

---

## File/Artifact Specific Config Settings

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `file_create_note_full_report`       | `FILE_CREATE_NOTE_FULL_REPORT`      | No           | Whether or not to include the full report as a Note (default: `true`).                                                                                      |
| `file_upload_unseen_artifacts`       | `FILE_UPLOAD_UNSEEN_ARTIFACTS`      | No           | Whether to upload artifacts (smaller than 32MB) that VirusTotal has no record of for analysis (default: `true`).                                            |
| `file_indicator_create_positives`    | `FILE_INDICATOR_CREATE_POSITIVES`   | No           | Create an indicator for File/Artifact based observables once this positive threshold is reached (default: `10`).                                            |
| `file_indicator_valid_minutes`       | `FILE_INDICATOR_VALID_MINUTES`      | No           | How long the indicator is valid for in minutes (default: `2880`).                                                                                           |
| `file_indicator_detect`              | `FILE_INDICATOR_DETECT`             | No           | Whether or not to set detection for the indicator to true (default: `true`).                                                                                |
| `file_import_yara`                   | `FILE_IMPORT_YARA`                  | No           | Whether or not to import Crowdsourced YARA rules (default: `false`).                                                                                        |

---

## IP Specific Config Settings

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ip_indicator_create_positives`      | `IP_INDICATOR_CREATE_POSITIVES`     | No           | Create an indicator for IPv4 based observables once this positive threshold is reached (default: `10`).                                                     |
| `ip_indicator_valid_minutes`         | `IP_INDICATOR_VALID_MINUTES`        | No           | How long the indicator is valid for in minutes (default: `2880`).                                                                                           |
| `ip_indicator_detect`                | `IP_INDICATOR_DETECT`               | No           | Whether or not to set detection for the indicator to true (default: `true`).                                                                                |
| `ip_add_relationships`               | `IP_ADD_RELATIONSHIPS`              | No           | Whether or not to add ASN and location resolution relationships (default: `true`).                                                                          |

---

## Domain Specific Config Settings

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `domain_indicator_create_positives`  | `DOMAIN_INDICATOR_CREATE_POSITIVES` | No           | Create an indicator for Domain based observables once this positive threshold is reached (default: `10`).                                                   |
| `domain_indicator_valid_minutes`     | `DOMAIN_INDICATOR_VALID_MINUTES`    | No           | How long the indicator is valid for in minutes (default: `2880`).                                                                                           |
| `domain_indicator_detect`            | `DOMAIN_INDICATOR_DETECT`           | No           | Whether or not to set detection for the indicator to true (default: `true`).                                                                                |
| `domain_add_relationships`           | `DOMAIN_ADD_RELATIONSHIPS`          | No           | Whether or not to add IP resolution relationships (default: `true`).                                                                                        |

---

## URL Specific Config Settings

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `url_upload_unseen`                  | `URL_UPLOAD_UNSEEN`                 | No           | Whether to upload URLs that VirusTotal has no record of for analysis (default: `true`).                                                                     |
| `url_indicator_create_positives`     | `URL_INDICATOR_CREATE_POSITIVES`    | No           | Create an indicator for URL based observables once this positive threshold is reached (default: `10`).                                                      |
| `url_indicator_valid_minutes`        | `URL_INDICATOR_VALID_MINUTES`       | No           | How long the indicator is valid for in minutes (default: `2880`).                                                                                           |
| `url_indicator_detect`               | `URL_INDICATOR_DETECT`              | No           | Whether or not to set detection for the indicator to true (default: `true`).                                                                                |

---

### Debugging

Set the appropriate log level for debugging. Use `self.helper.log_{LOG_LEVEL}("Message")` for logging, e.g., `self.helper.log_error("Error message")`.

### Additional Information

The VirusTotal connector performs enrichment for files, IP addresses, domains, and URLs. It sends observables to the VirusTotal API and creates indicators in OpenCTI based on threat intelligence from VirusTotal.
