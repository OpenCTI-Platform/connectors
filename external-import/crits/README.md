# OpenCTI CRITs Connector

This connector is intended to provide a mechanism for synchronizing data from a CRITs CTI database instance
([https://crits.github.io](https://crits.github.io/)) into OpenCTI. The primary use case for this is to help
ease the migration from CRITs (a largely unmaintained platform, as of 2022) to OpenCTI. Inspiration from the
MISP connector, as well as some of the other connectors.

The CRITs project has some documentation on their Authenticated API available here:
* [https://github.com/crits/crits/wiki/Authenticated-API](https://github.com/crits/crits/wiki/Authenticated-API)

## Installation

Very few. The CRITs API calls will all be performed via the HTTP(S) REST API, which only needs the Python
requests library to function.

### Requirements

- OpenCTI Platform >= 5.3.15
- CRITs instance with API enabled
- CRITs username and API key for user authenticating for the sync

### Configuration

| Parameter                            | Docker envvar                       | Mandatory    | Description                                                                                                                                                |
| ------------------------------------ | ----------------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `opencti_url`                        | `OPENCTI_URL`                       | Yes          | The URL of the OpenCTI platform.                                                                                                                           |
| `opencti_token`                      | `OPENCTI_TOKEN`                     | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                                                |
| `connector_id`                       | `CONNECTOR_ID`                      | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                         |
| `connector_type`                     | `CONNECTOR_TYPE`                    | Yes          | Must be `EXTERNAL_IMPORT` (this is the connector type).                                                                                                    |
| `connector_name`                     | `CONNECTOR_NAME`                    | Yes          | The descriptive name for this connector                                                                                                                    |
| `connector_scope`                    | `CONNECTOR_SCOPE`                   | Yes          | Supported scope: Default is 'crits'                                                                                                                        |
| `connector_confidence_level`         | `CONNECTOR_CONFIDENCE_LEVEL`        | Yes          | The default confidence level for created entities (a number between 1 and 100).                                                                            |
| `connector_log_level`                | `CONNECTOR_LOG_LEVEL`               | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                              |
| `crits_url`                          | `CRITS_URL`                         | Yes          | The URL of the CRITs instance (leave off the trailing `/`)                                                                                                 |
| `crits_reference_url`                | `CRITS_REFERENCE_URL`               | No           | The URL to embed as an "external reference" to link imported data to the external CRITs instance                                                           |
| `crits_user`                         | `CRITS_USER`                        | Yes          | The login username for CRITs                                                                                                                               |
| `crits_api_key`                      | `CRITS_API_KEY`                     | Yes          | The API Key used for authentication (not the user's password, but an API Key that's creatable/viewable in the user's profile in CRITs)                     |
| `crits_event_type`                   | `CRITS_EVENT_TYPE`                  | Yes          | When importing CRITs Events as Analysis Reports, what Report Type to give them                                                                             |
| `crits_interval`                     | `CRITS_INTERVAL`                    | Yes          | The interval to delay between updates, in minutes                                                                                                          |
| `crits_import_campaign_as`           | `CRITS_IMPORT_CAMPAIGN_AS`          | No           | 'Campaign' or 'IntrusionSet': What STIX2.1 type to import Campaigns as. Default: IntrusionSet                                                              |

### Behavior ###

Below will be notes explaining how this connector goes about performing the data import

### Debugging ###

### Additional information

