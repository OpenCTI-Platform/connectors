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

| Parameter                        | Docker envvar                    | Mandatory    | Description                                                                                                                            |
|----------------------------------|----------------------------------| ------------ |----------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                    | `OPENCTI_URL`                    | Yes          | The URL of the OpenCTI platform.                                                                                                       |
| `opencti_token`                  | `OPENCTI_TOKEN`                  | Yes          | The default admin token configured in the OpenCTI platform parameters file.                                                            |
| `connector_id`                   | `CONNECTOR_ID`                   | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                     |
| `connector_name`                 | `CONNECTOR_NAME`                 | Yes          | The descriptive name for this connector                                                                                                |
| `connector_scope`                | `CONNECTOR_SCOPE`                | Yes          | Supported scope: Default is 'crits'                                                                                                    |
| `connector_log_level`            | `CONNECTOR_LOG_LEVEL`            | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                          |
| `crits_url`                      | `CRITS_URL`                      | Yes          | The URL of the CRITs instance (leave off the trailing `/`)                                                                             |
| `crits_reference_url`            | `CRITS_REFERENCE_URL`            | No           | The URL to embed as an "external reference" to link imported data to the external CRITs instance                                       |
| `crits_user`                     | `CRITS_USER`                     | Yes          | The login username for CRITs                                                                                                           |
| `crits_api_key`                  | `CRITS_API_KEY`                  | Yes          | The API Key used for authentication (not the user's password, but an API Key that's creatable/viewable in the user's profile in CRITs) |
| `crits_event_type`               | `CRITS_EVENT_TYPE`               | Yes          | When importing CRITs Events as Analysis Reports, what Report Type to give them                                                         |
| `crits_interval`                 | `CRITS_INTERVAL`                 | Yes          | The interval to delay between updates, in minutes                                                                                      |
| `crits_import_campaign_as`       | `CRITS_IMPORT_CAMPAIGN_AS`       | No           | 'Campaign' or 'IntrusionSet': What STIX2.1 type to import Campaigns as. Default: IntrusionSet                                          |
| `crits_timestamp_field`          | `CRITS_TIMESTAMP_FIELD`          | No           | Which fieldin the CRITs objects to use for the timestamp (default: modified)                                                           |
| `crits_chunk_size`               | `CRITS_CHUNK_SIZE`               | No           | Ingests non-event-related observables in chunks of this size, helps with memory consumption. Adjust experimentally (default: 100)      |
| `crits_default_marking`          | `CRITS_DEFAULT_MARKING`          | No           | Marking definition to use, case insensitive, one of ["TLP:RED", "TLP:GREEN", "TLP:AMBER", "TLP:WHITE"] (default: TLP:GREEN)            |
| `crits_default_score`            | `CRITS_DEFAULT_SCORE`            | No           | Default_score allows you to add a default score for an indicator and its observable (a number between 1 and 100, default: 50)          |

### Behavior ###

This connector is intended to help migrate data from a CRITs CTI database into OpenCTI, on a regular basis. It
is not designed to update CRITs with data from OpenCTI. The connector will, the first time it is run, import all
of the compatible data in the target CRITs database. Then, on subsequent runs, it will only import when things
have changed since the last run.

Each run, the connector first starts by looking for new Events to import, and imports them with their first-degree
object relationships as contents of the report. The connector will then look for CRITs objects that are related, and
both contained in the same Event, and it will upload a STIX relationship capturing this relationship into the
report as well. The campaign associated with the Event, either by a first-degree relationship, or use of the
"campaign" field on the report, will also be uploaded as a content. The connector will ignore the "campaign" field
on other non-Event object types. In its final phase, the connector will scan for all objects and relationships that
aren't related to an Event, and will upload those without an analysis report relationship into OpenCTI.

Campaigns will be auto-created (defaulting to use the IntrusionSet type, unless specified otherwise), and Organization
entities for each encountered Source will also be auto-created. The source.*.instances.*.reference id's will
all be imported as external references, with additional references created to point back at CRITs. Where they are
identified as well-formed URLs, they'll be stored as such, otherwise they'll be imported as UIDs.

There are a handful of datatypes that could not be imported, due to CRITs itself not exposing their contents via
the (never completed) REST API:
PCAP, Certificate, Screenshot

Similarly, original raw email content isn't capable of being reconstructed from the CRITs API. However, the most
significant metadata, headers, and portions of multipart contents are capable of being imported.

### Debugging ###

The connector logs useful statistics and debbuging data to the console at run-time

### Additional information

