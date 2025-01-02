# RST Threat Feed Connector for OpenCTI by RST Cloud

The **RST Threat Feed Connector** integrates RST Cloud threat intelligence feeds into OpenCTI. This connector imports Indicators (IP, Domain, URL, Hash) with their relationships to malware, TTPs, tools, threat groups, sectors, CVE, and other objects. This enhances the capability of OpenCTI by providing actionable threat intelligence data, allowing users to make informed decisions based on the latest information from ([RST Threat Feed](https://www.rstcloud.com/rst-threat-feed/)).

## Key Features

- **Lots of contextual information**: Indicators come with additional info including threat category, malware name, threat actor names, tools and frameworks, TTPs, CVE, industry tags, reference to the source of the indicator and more.
- **OpenCTI Integration**: Seamlessly integrates the fetched data into OpenCTI's database.
- **Customizable Data Ingestion**: Users can specify a risk score threshold to control what indicators are being imported and also configure to import only new indicators.
- **Customizable Detection Flag**: Users can specify per each indicator type what is the risk score threshold to mark an Indicator as ready for detection (x_opencti_detection=true|false)

This connector empowers users with an expanded and in-depth insight into the cyber threat landscape by tapping into the detailed threat intelligence delivered by RST Cloud.

## Requirements
- OpenCTI Platform version 5.10.x or higher.
- An API Key for accessing RST Cloud.

## Recommended connectors
This connector is aligned with data populated by common OpenCTI connectors. We recommend to install the following connectors alongside with RST Threat Feed Connector:
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
| Connector Name | `CONNECTOR_NAME` | Yes | Name of the connector. For example: `RST Threat Feed`. |
| Connector Scope | `CONNECTOR_SCOPE` | Yes | The scope or type of data the connector is importing, either a MIME type or Stix Object. E.g. application/json |
| Log Level | `CONNECTOR_LOG_LEVEL` | Yes | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |
| Run and Terminate | `CONNECTOR_RUN_AND_TERMINATE` | Yes | If set to true, the connector will terminate after a successful run. Useful for debugging or one-time runs. |
| Interval | `CONFIG_INTERVAL` | Yes | Determines how often the connector will run, set in hours. |
| RST Threat Feed API Key | `RST_THREAT_FEED_API_KEY` | Yes | Your API Key for accessing RST Cloud. |
| RST Threat Feed Base URL | `RST_THREAT_FEED_BASEURL` | No | By default, use https://api.rstcloud.net/v1/. In some cases, you may want to use a local API endpoint |
| RST Threat Feed Connection Timeout | `RST_THREAT_FEED_CONTIMEOUT` | No | Connection timeout to the API. Default (sec): `30` |
| RST Threat Feed Read Timeout | `RST_THREAT_FEED_READTIMEOUT` | No | Read timeout for each feed. Our API redirects the connector to download data from AWS S3. If the connector is unable to fetch the feed in time, increase the read timeout. Default (sec): `60` |
| RST Threat Feed Download Retry Count | `RST_THREAT_FEED_RETRY` | No | Default (attempts): `5` |
| RST Threat Feed Fetch Interval | `RST_THREAT_FEED_INTERVAL` | No | Default (sec): `86400` |
| RST Threat Feed Minimal Score to Import | `RST_THREAT_FEED_MIN_SCORE_IMPORT` | No | Import only indicators with risk score more than X. The objects that are related to these indicators will also be imported with corresponding relations. Default (score): `20` |
| RST Threat Feed Minimal Score for IP to be marked for Detection | `RST_THREAT_FEED_MIN_SCORE_DETECTION_IP` | No | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45` |
| RST Threat Feed Minimal Score for Domain to be marked for Detection | `RST_THREAT_FEED_MIN_SCORE_DETECTION_DOMAIN` | No | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45` |
| RST Threat Feed Minimal Score for URL to be marked for Detection | `RST_THREAT_FEED_MIN_SCORE_DETECTION_URL` | No | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45` |
| RST Threat Feed Minimal Score for Hash to be marked for Detection | `RST_THREAT_FEED_MIN_SCORE_DETECTION_HASH` | No | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45` |
| RST Threat Feed Import only New Indicators | `RST_THREAT_FEED_ONLY_NEW` | No | Defines if you only want to import indicators with recent "First Seen" or also want to re-import changes to the indicators with "Last Seen" >= yesterday. Default: `true` |
