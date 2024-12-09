# RST Report Hub Connector for OpenCTI by RST Cloud

The **RST Report Hub Connector** integrates various APT reports from security companies, research groups, cyber communities, and individuals into OpenCTI. RST Cloud manages the conversion of human-readable reports into STIX bundles. This connector retrieves data from RST Cloud, importing the PDF version of each report along with a corresponding summary, key ideas, and facts into OpenCTI. It also includes extracted objects and relationships between them, such as Intrusion Sets (threat actors), campaigns, malware, TTPs, tools, geographic data, sectors, CVEs, indicators, and other relevant objects. This integration enhances the capabilities of OpenCTI by providing valuable threat intelligence data, enabling CTI analysts to streamline APT report processing through automation via the [RST Report Hub](https://www.rstcloud.com/rst-report-hub/) integration, ultimately saving time.

## Key Features

- **Brilliant Time Saver**: Manual import of threat reports is a time consuming activity that does not need to happen anymore.
- **Threat Report Library**: Keep all APT reports and their metadata, extracted objects in one place. 
- **OpenCTI Integration**: Seamlessly integrates the fetched data into OpenCTI's database.

This connector provides users with an enhanced and comprehensive understanding of the cybersecurity threat landscape by leveraging the detailed threat intelligence provided by RST Cloud.

## Requirements
- OpenCTI Platform version 5.10.x or higher.
- An API Key for accessing RST Cloud.

## Recommended connectors
This connector is aligned with data populated by common OpenCTI connectors. We recommend to install the following connectors alongside with RST Report Hub Connector:
 - MITRE Datasets (https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/mitre)
 - Malpedia (https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/malpedia)
 - OpenCTI Datasets (https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/opencti)
 - CISA Known Exploited Vulnerabilities (https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/cisa-known-exploited-vulnerabilities)


## Configuration

Configuration of the connector is straightforward. The minimal configuration requires you just enter the RST Cloud API key to be provided and OpenCTI connection settings specified. Below is the full list of parameters you can set:

| Parameter | Docker envvar | Mandatory | Description |
| --- | --- | --- | --- |
| OpenCTI URL | `OPENCTI_URL` | Yes | The URL of the OpenCTI platform. |
| OpenCTI Token | `OPENCTI_TOKEN` | Yes | The default admin token set in the OpenCTI platform. |
| Connector ID | `CONNECTOR_ID` | Yes | A unique `UUIDv4` identifier for this connector instance. |
| Connector Name | `CONNECTOR_NAME` | Yes | Name of the connector. For example: `RST Report Hub`. |
| Connector Scope | `CONNECTOR_SCOPE` | Yes | The scope or type of data the connector is importing, either a MIME type or Stix Object. E.g. application/json |
| Log Level | `CONNECTOR_LOG_LEVEL` | Yes | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |
| RST Report Hub Base URL | `RST_REPORT_HUB_BASE_URL` | No | By default, use https://api.rstcloud.net/v1/. In some cases, you may want to use a local API endpoint |
| RST Report Hub API Key | `RST_REPORT_HUB_API_KEY` | Yes | Your API Key for accessing RST Cloud. |
| RST Report Hub Connection Timeout | `RST_REPORT_HUB_CONNECTION_TIMEOUT` | No | Connection timeout to the API. Default (sec): `30` |
| RST Report Hub Read Timeout | `RST_REPORT_HUB_READ_TIMEOUT` | No | Read timeout for each feed. If the connector is unable to fetch a report in time, increase the read timeout. Default (sec): `60` |
| RST Report Hub Retry Delay | `RST_REPORT_HUB_RETRY_DELAY` | No | Specifies how long to wait in seconds before next attempt to connect to the API. Default (sec): `30` |
| RST Report Hub Download Retry Count | `RST_REPORT_HUB_RETRY_ATTEMPTS` | No | Default (attempts): `5` |
| RST Report Hub Fetch Interval | `RST_REPORT_HUB_FETCH_INTERVAL` | No | Default (sec): `300` |
| RST Report Hub Date to start pulling data from | `RST_REPORT_HUB_IMPORT_START_DATE` | No | Specify the date from which you want to retrieve the reports in the format "%Y%m%d" (for example, 20240527). Data import for each day will occur with a delay equal to the RST_REPORT_HUB_FETCH_INTERVAL. By default, this start date is calculated as 7 days ago. |
| RST Report Hub Language | `RST_REPORT_HUB_LANGUAGE` | No | Reach out to support@rstcloud.net if you want to update this parameter. Default: `eng` |
| RST Report Hub Connector is to create observables | `RST_REPORT_HUB_CREATE_OBSERVABLES` | No | A user can select if observables are to be created in addition to indicators. Options are `true`, `false`. Default: `false` |
| RST Report Hub Connector is to create related-to relationships | `RST_REPORT_HUB_CREATE_RELATED_TO` | No | A user can select if `related-to` relationships are to be created or not. Options are `true`, `false`. Default: `true` |
| RST Report Hub Connector is to create custom attack-pattern | `RST_REPORT_HUB_CREATE_CUSTOM_TTPS` | No | A user can select if `attack-pattern` objects with custom names that are still not present in the MITRE ATT&CK framework are to be created or not. Options are `true`, `false`. Default: `true` |