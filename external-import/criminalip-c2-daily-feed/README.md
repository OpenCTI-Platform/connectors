# OpenCTI criminalip C2-Daily-Feed

The connector uses the [criminalip C2-Daily-Feed](https://github.com/criminalip/C2-Daily-Feed) to collect the malicious IP addresses derived from Criminal IP (https://www.criminalip.io/).

## Installation

### Requirements

- OpenCTI Platform >= 6.7.4

### Configuration

| Parameter                            | Docker envvar                | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ |------------------------------| ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`              | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`               | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_name`                     | `CONNECTOR_NAME`             | Yes          |                                                                                                                                           |
| `connector_scope`                    | `CONNECTOR_SCOPE`            | Yes          |                                                                                                 |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`        | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `CRIMINALIP_CSV_URL`                      | `CRIMINALIP_CSV_URL`              | Yes          | https://raw.githubusercontent.com/criminalip/C2-Daily-Feed/refs/heads/main                                                                                                               |
| `CRIMINALIP_CONFIDENCE_SCORE`         | `CRIMINALIP_CONFIDENCE_SCORE`     | Yes          | CriminalIP Score Limitation                                                                                                                |
| `CRIMINALIP_INTERVAL`                 | `ABUSEIPDB_LIMIT`            | Yes          | interval between 2 collect itself                                                                                                                |

### Notes

* CriminalIP offers a daily sample of 50 malicious IP addresses identified by the Criminal IP real-time threat hunting search engine, specializing in OSINT-based Cyber Threat Intelligence (CTI).
* This connector gets the daily feeds csv file and ingests into OpenCTI.
