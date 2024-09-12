# OpenCTI Jira connector

This connector allows to consume an OpenCTI Stream and open JIRA issues.

## Compatible types of entity

- Incidents
- Reports
- Groupings
- Cases
    - Incidents
    - RFIs
    - RFTs


## Installation

### Requirements

- OpenCTI Platform >= 6.2.16

### Configuration

| Parameter                               | Docker envvar                           | Mandatory | Description                                                                                   |
|-----------------------------------------|-----------------------------------------| --------- |-----------------------------------------------------------------------------------------------|
| `opencti_url`                           | `OPENCTI_URL`                           | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                         | `OPENCTI_TOKEN`                         | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                          | `CONNECTOR_ID`                          | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_live_stream_id`              | `CONNECTOR_LIVE_STREAM_ID`              | Yes       | ID of the OpenCTI stream for the JIRA connector from the OpenCTI console                      |
| `connector_id`                          | `CONNECTOR_ID`                          | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_live_stream_listen_delete`   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | Yes       | Whether entity deletions should be processed (not currently implemented)                      |
| `connector_live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | Yes       | tbc                                                                                           |
| `connector_name`                        | `CONNECTOR_NAME`                        | Yes       | Name of connector (eg. "CONNECTOR_NAME=JIRA", including the "")                               |
| `connector_scope`                       | `CONNECTOR_SCOPE`                       | Yes       | Must be `jira`                                                                                |
| `connector_confidence_level`            | `CONNECTOR_CONFIDENCE_LEVEL`            | Yes       | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`                   | `CONNECTOR_LOG_LEVEL`                   | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `jira_url`                              | `JIRA_URL`                              | Yes       | URL to the JIRA server (eg. https://<your_instance_name>.atlassian.net).                      |
| `jira_ssl_verify`                       | `JIRA_SSL_VERIFY`                       | Yes       | Whether to verify SSL (default=`true`).                                                       |
| `jira_login_email`                      | `JIRA_LOGIN_EMAIL`                      | Yes       | The email for the JIRA account with API access that the connector will use to create issues   |
| `jira_api_token`                        | `JIRA_API_TOKEN`                        | Yes       | The API key for the JIRA account (currently ~175 chars in length)                             |
| `jira_project_key`                      | `JIRA_PROJECT_KEY`                      | Yes       | JIRA Project Key (not name) where the issues will be created  [1]                             |
| `jira_issue_type_name`                  | `JIRA_ISSUE_TYPE_NAME`                  | Yes       | Issue type that the connector will create (default=`Epic`, other types of Task, etc           |
| `jira_custom_fields_keys`               | `JIRA_CUSTOM_FIELDS_KEYS`               | Yes*      | System generated key (not ID [2]) as a CSV list for custom fields in issue to be populated    |
| `jira_custom_fields_values`             | `JIRA_CUSTOM_FIELDS_VALUES`             | Yes*      | Static values to go into the custom fields (same order)                                       |


### Configuration notes
- The JIRA connector receives events from an OCTI stream, which you must generate in the OCTI UI (currently under Data > Sharing)
- After creating a stream, the stream ID (connector_live_stream_id) is shown in the UI
-   Note that you can view the live output of the stream by clicking on the entry in the OCTI UI (Chromium browsers only)
- A default JIRA instance currently includes Issue types of `Epic` and `Task`, which goes into `jira_issue_type_name`. Others are supported

- [1] Note that `jira_project_key` is not the project name, but the typically 3-character system-generated ID that typically appears in the JIRA URL
- [2] The `jira_custom_fields_keys` parameter is actually the Custom Field ID from JIRA. These are system-generated, and typically take the form `customfield_10039`.
-  You can identify the custom fields defined in JIRA and retrieve the ID for a given name using the command:
      `curl -u <email>:<api_token> -X GET -H "Content-Type: application/json" https://<your_jira_instance>.atlassian.net/rest/api/2/field`


### Usage
- Create a Stream in OpenCTI
- Adjust the filter in OpenCTI to trigger off the entities that you wish to send to JIRA. Examples might be:
    Entity = Incident Response  AND  Status = NEW
    Entity = Report  AND  Creator = CrowdStrike


### Further notes
- Currently, although updating or deleting an entity in OCTI triggers an update or delete event in the stream, the connector only supports creation events.
- This connector is currently one-way
