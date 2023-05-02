# OpenCTI Mandiant Connector

This connector connects to the Mandiant Advantage API V4 and gather all data from a given date.

## Configuration

The connector can be configured with the following variables:

| Config Parameter | Docker env var | Default | Description |
| ---------------------------- | ---------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `api_url` | `MANDIANT_API_URL` | `https://api.intelligence.mandiant.com` | The base URL for the Mandiant API. |
| `api_v4_key_id` | `MANDIANT_API_V4_KEY_ID` | `ChangeMe` | The Mandiant API client ID. |
| `api_v4_key_secret` | `MANDIANT_API_V4_KEY_SECRET` | `ChangeMe` | The Mandiant API client secret. |
| `collections` | `MANDIANT_COLLECTIONS` | `actor,malware,indicator,vulnerability,report` | Specify what Collections you want to pull. |
| `threat_actor_as_intrusion_set` | `MANDIANT_THREAT_ACTOR_AS_INTRUSION_SET` | `true` | If true, then threat actors will be added to intrusion set. |
| `import_start_date` | `MANDIANT_IMPORT_START_DATE` | `2023-02-03` | The Mandiant API limits the import start date to be 90 days. |
| `interval` | `MANDIANT_INTERVAL` | `60` | In minutes, the amount of time between each run of the connector. |
| `update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | `false` | If true, then the connector will update existing data. |
| `report_types_ignored` | `MANDIANT_REPORT_TYPES_IGNORED` | `Vulnerability Report` | This ignores certain report types, the amount of reports daily and the amount of repetitive software creating extensive delay processing reports. |
| `mscore` | `MANDIANT_MSCORE` | `0` | Defines the minimum Indicator Confidence Score to return. |