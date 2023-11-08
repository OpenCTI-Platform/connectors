# Recorded Future Feed Connector for OpenCTI

The **Recorded Future Feed Connector** integrates Recorded Future threat intelligence feeds into OpenCTI. This enhances the capability of OpenCTI by providing real-time threat intelligence data, allowing users to make informed decisions based on the latest information from Recorded Future.

## Key Features:

- **Comprehensive Feed Retrieval**: Retrieves threat intelligence data from various Recorded Future feeds.
- **OpenCTI Integration**: Seamlessly integrates the fetched data into OpenCTI's database.
- **Customizable Data Ingestion**: Users can specify which types of threat intelligence data to ingest, allowing for targeted data acquisition.

By leveraging the detailed threat intelligence provided by Recorded Future, this connector provides users with a richer and more comprehensive view of the threat landscape.

## Requirements:
- OpenCTI Platform version 5.11.13 or higher.
- An API Key for accessing Recorded Future.

## Configuration:

Configuration of the connector is straightforward. Below are the parameters you'll need to set:

| Parameter | Docker envvar | Mandatory | Description |
| --- | --- | --- | --- |
| OpenCTI URL | `OPENCTI_URL` | Yes | The URL of the OpenCTI platform. |
| OpenCTI Token | `OPENCTI_TOKEN` | Yes | The default admin token set in the OpenCTI platform. |
| Connector ID | `CONNECTOR_ID` | Yes | A unique `UUIDv4` identifier for this connector instance. |
| Connector Type | `CONNECTOR_TYPE` | Yes | Should always be set to `EXTERNAL_IMPORT` for this connector. |
| Connector Name | `CONNECTOR_NAME` | Yes | Name of the connector. E.g., "Recorded Future Feed". |
| Connector Scope | `CONNECTOR_SCOPE` | Yes | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Confidence Level | `CONNECTOR_CONFIDENCE_LEVEL` | Yes | The default confidence level for created sightings. It's a number between 1 and 100, with 100 being the most confident. |
| Log Level | `CONNECTOR_LOG_LEVEL` | Yes | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |
| Run and Terminate | `CONNECTOR_RUN_AND_TERMINATE` | Yes | If set to true, the connector will terminate after a successful run. Useful for debugging or one-time runs. |
| Update Existing Data | `CONFIG_UPDATE_EXISTING_DATA` | Yes | Decide whether the connector should update already existing data in the database. |
| Interval | `CONFIG_INTERVAL` | Yes | Determines how often the connector will run, set in hours. |
| Recorded Future API Key | `RF_API_KEY` | Yes | Your API Key for accessing Recorded Future. |
| Labels | `RF_LABELS` | No | Labels that should be applied to Stix Objects. Example: "recordedfuture". |
| Days Threshold | `RF_DAYS_THRESHOLD` | No | Specify the number of days to pull indicators from. Example: "7". |

### Enable Feeds:

You can selectively choose which threat intelligence feeds to pull from Recorded Future. Each feed corresponds to a different type of threat data:

- Domains Prevent: `ENABLE_DOMAINS_PREVENT`
- Domains Detect: `ENABLE_DOMAINS_DETECT`
- URLs Prevent: `ENABLE_URLS_PREVENT`
- Command & Control IPs Detect: `ENABLE_C2_IPS_DETECT`
- Command & Control IPs Prevent: `ENABLE_C2_IPS_PREVENT`
- Vulnerabilities Patch: `ENABLE_VULNS_PATCH`
- Hashes Prevent: `ENABLE_HASHES_PREVENT`
- TOR IPs: `ENABLE_TOR_IPS`
- Emerging Malware Hashes: `ENABLE_EMERGING_MALWARE_HASHES`
- RAT Controller IPs: `ENABLE_RAT_CONTROLLERS_IPS`
- Fast Flux IPs: `ENABLE_FFLUX_IPS`
- Dynamic DNS IPs: `ENABLE_DDNS_IPS`
- Low Detection Malware Hashes: `ENABLE_LOW_DETECT_MALWARE_HASHES`

Each of the above feeds can be enabled by setting its corresponding Docker environment variable to `true`.
