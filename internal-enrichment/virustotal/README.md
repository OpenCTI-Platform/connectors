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

| Parameter `opencti` | config.yml | Docker environment variable | Mandatory | Description                                                                       |
|---------------------|------------|-----------------------------|-----------|-----------------------------------------------------------------------------------|
| OpenCTI URL         | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform. No trailing `/`. Example: `http://opencti:8080`. |
| OpenCTI Token       | `token`    | `OPENCTI_TOKEN`             | Yes       | The default admin token from OpenCTI platform settings.                           |

---

#### Base connector environment variables

| Parameter `connector` | config.yml  | Docker environment variable | Default               | Mandatory | Description                                                                              |
|-----------------------|-------------|-----------------------------|-----------------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID          | `id`        | `CONNECTOR_ID`              | /                     | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type        | `type`      | `CONNECTOR_TYPE`            | `INTERNAL_ENRICHMENT` | Yes       | Should always be set to `INTERNAL_ENRICHMENT` for this connector.                        |
| Connector Name        | `name`      | `CONNECTOR_NAME`            | `VirusTotal`          | Yes       | Name of the connector.                                                                   |
| Connector Scope       | `scope`     | `CONNECTOR_SCOPE`           | /                     | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Connector Log Level   | `log_level` | `CONNECTOR_LOG_LEVEL`       | `info`                | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Connector Auto        | `auto`      | `CONNECTOR_AUTO`            | `True`                | Yes       | Must be `true` or `false` to enable or disable auto-enrichment of observables            |

---

## File/Artifact Specific Config Settings

| Parameter `virustotal`          | config.yml                        | Docker environment variable                  | Default | Mandatory | Description                                                                                     |
|---------------------------------|-----------------------------------|----------------------------------------------|---------|-----------|-------------------------------------------------------------------------------------------------|
| File create note full report    | `file_create_note_full_report`    | `VIRUSTOTAL_FILE_CREATE_NOTE_FULL_REPORT`    | `True`  | No        | Whether or not to include the full report as a Note                                             |
| File upload unseen artifacts    | `file_upload_unseen_artifacts`    | `VIRUSTOTAL_FILE_UPLOAD_UNSEEN_ARTIFACTS`    | `True`  | No        | Whether to upload artifacts (smaller than 32MB) that VirusTotal has no record of for analysis   |
| File indicator create positives | `file_indicator_create_positives` | `VIRUSTOTAL_FILE_INDICATOR_CREATE_POSITIVES` | `10`    | No        | Create an indicator for File/Artifact based observables once this positive threshold is reached |
| File indicator valid minutes    | `file_indicator_valid_minutes`    | `VIRUSTOTAL_FILE_INDICATOR_VALID_MINUTES`    | `2880`  | No        | How long the indicator is valid for in minutes                                                  |
| File indicator detect           | `file_indicator_detect`           | `VIRUSTOTAL_FILE_INDICATOR_DETECT`           | `True`  | No        | Whether or not to set detection for the indicator to true                                       |
| File import yara                | `file_import_yara`                | `VIRUSTOTAL_FILE_IMPORT_YARA`                | `True`  | No        | Whether or not to import Crowdsourced YARA rules                                                |

---

## IP Specific Config Settings

| Parameter `virustotal`        | config.yml                      | Docker environment variable                | Default | Mandatory | Description                                                                            |
|-------------------------------|---------------------------------|--------------------------------------------|---------|-----------|----------------------------------------------------------------------------------------|
| IP indicator create positives | `ip_indicator_create_positives` | `VIRUSTOTAL_IP_INDICATOR_CREATE_POSITIVES` | `10`    | No        | Create an indicator for IPv4 based observables once this positive threshold is reached |
| IP indicator valid minutes    | `ip_indicator_valid_minutes`    | `VIRUSTOTAL_IP_INDICATOR_VALID_MINUTES`    | `2880`  | No        | How long the indicator is valid for in minutes                                         |
| IP indicator detect           | `ip_indicator_detect`           | `VIRUSTOTAL_IP_INDICATOR_DETECT`           | `True`  | No        | Whether or not to set detection for the indicator to true                              |
| IP add relationships          | `ip_add_relationships`          | `VIRUSTOTAL_IP_ADD_RELATIONSHIPS`          | /       | No        | Whether or not to add ASN and location resolution relationships                        |

---

## Domain Specific Config Settings

| Parameter `virustotal`            | config.yml                          | Docker environment variable                    | Default | Mandatory | Description                                                                              |
|-----------------------------------|-------------------------------------|------------------------------------------------|---------|-----------|------------------------------------------------------------------------------------------|
| Domain indicator create positives | `domain_indicator_create_positives` | `VIRUSTOTAL_DOMAIN_INDICATOR_CREATE_POSITIVES` | `10`    | No        | Create an indicator for Domain based observables once this positive threshold is reached |
| Domain indicator valid minutes    | `domain_indicator_valid_minutes`    | `VIRUSTOTAL_DOMAIN_INDICATOR_VALID_MINUTES`    | `2880`  | No        | How long the indicator is valid for in minutes                                           |
| Domain indicator detect           | `domain_indicator_detect`           | `VIRUSTOTAL_DOMAIN_INDICATOR_DETECT`           | `True`  | No        | Whether or not to set detection for the indicator to true                                |
| Domain add relationships          | `domain_add_relationships`          | `VIRUSTOTAL_DOMAIN_ADD_RELATIONSHIPS`          | /       | No        | Whether or not to add IP resolution relationships                                        |

---

## URL Specific Config Settings

| Parameter `virustotal`         | config.yml                       | Docker environment variable                 | Default | Mandatory | Description                                                                           |
|--------------------------------|----------------------------------|---------------------------------------------|---------|-----------|---------------------------------------------------------------------------------------|
| URL upload unseen              | `url_upload_unseen`              | `VIRUSTOTAL_URL_UPLOAD_UNSEEN`              | `True`  | No        | Whether to upload URLs that VirusTotal has no record of for analysis                  |
| URL indicator create positives | `url_indicator_create_positives` | `VIRUSTOTAL_URL_INDICATOR_CREATE_POSITIVES` | `10`    | No        | Create an indicator for URL based observables once this positive threshold is reached |
| URL indicator valid minutes    | `url_indicator_valid_minutes`    | `VIRUSTOTAL_URL_INDICATOR_VALID_MINUTES`    | `2880`  | No        | How long the indicator is valid for in minutes                                        |
| URL indicator detect           | `url_indicator_detect`           | `VIRUSTOTAL_URL_INDICATOR_DETECT`           | `True`  | No        | Whether or not to set detection for the indicator to true                             |

---

## Generic Config Settings for File, Artifact IP, Domain, URL

| Parameter `virustotal`         | config.yml                       | Docker environment variable                 | Default | Mandatory | Description                                                                           |
|--------------------------------|----------------------------------|---------------------------------------------|---------|-----------|---------------------------------------------------------------------------------------|
| Include Attributes in Note              | `include_attributes_in_note`              | `VIRUSTOTAL_INCLUDE_ATTRIBUTES_IN_NOTE`              | `False`  | No        | Whether or not to include the attributes info in Note                 |


---

### Debugging

Set the appropriate log level for debugging. Use `self.helper.log_{LOG_LEVEL}("Message")` for logging, e.g., `self.helper.log_error("Error message")`.

### Additional Information

The VirusTotal connector performs enrichment for files, IP addresses, domains, and URLs. It sends observables to the VirusTotal API and creates indicators in OpenCTI based on threat intelligence from VirusTotal.
Information when creating a note full report ‘Last Analysis Results’ any value returned by virustotal that is falsy will return ‘N/A’.
