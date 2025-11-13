# RST Threat Feed Connector for OpenCTI by RST Cloud

The **RST Threat Feed Connector** integrates RST Cloud threat intelligence feeds into OpenCTI. This connector imports Indicators (IP, Domain, URL, Hash) with their relationships to malware, TTPs, tools, threat groups, sectors, CVE, and other objects. This enhances the capability of OpenCTI by providing actionable threat intelligence data, allowing users to make informed decisions based on the latest information from ([RST Threat Feed](https://www.rstcloud.com/rst-threat-feed/)).

The feed delivers approximately 200K indicators daily, with the ability to filter by score. Each indicator has an individual score, allowing OpenCTI to keep indicator scores updated when inactive indicators become active again (c2 went offline, a domain had no A DNS entry, a phishing website was not active, etc). Scoring is aligned with OpenCTI scoring algorithms and allows you to set a custom decay speed in your platform.

![RST Cloud and OpenCTI Scoring and Decay algorithms integration](scoring.png "RST Cloud and OpenCTI Scoring and Decay algorithms integration")

Data scored between 0 and 20 is typically considered noisy. Data with a score of 45+ is used in SIEMs for real-time detection, while data scored 55+ is used for active blocking. However, everyone can set their own thresholds to find the optimal balance for their needs.

Data can be retrieved every hour or daily, depending on the use case. The feed includes multiple threat categories, such as:
 - backdoor
 - banker
 - bootkit
 - botnet
 - c2
 - cryptomining
 - downloader
 - drainer
 - dropper
 - fraud
 - keylogger
 - malware
 - phishing
 - proxy
 - raas
 - ransomware
 - rat
 - rootkit
 - scam
 - scan
 - screenshotter
 - shellprobe
 - spam
 - spyware
 - stealer
 - tor_exit
 - trojan
 - vpn
 - vulndriver
 - webattack
 - wiper

## Key Features

- **Lots of contextual information**: Indicators come with additional info including threat category, malware name, threat actor names, tools and frameworks, TTPs, CVE, industry tags, reference to the source of the indicator and more.
- **OpenCTI Integration**: Seamlessly integrates the fetched data into OpenCTI's database.
- **Customizable Data Ingestion**: Users can specify a score threshold to control what indicators are being imported and also configure to import only new indicators.
- **Customizable Detection Flag**: Users can specify per each indicator type what is the score threshold to mark an Indicator as ready for detection (x_opencti_detection=true|false)

This connector empowers users with an expanded and in-depth insight into the cyber threat landscape by tapping into the detailed threat intelligence delivered by RST Cloud.

## Requirements
- OpenCTI Platform version 5.10.x or higher.
- An API Key for accessing RST Cloud (trial@rstcloud.net).

## Recommended connectors
This connector is aligned with data populated by common OpenCTI connectors. We recommend to install the following connectors alongside with RST Threat Feed Connector:
 - MITRE Datasets (https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/mitre)
 - OpenCTI Datasets (https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/opencti)
 - CISA Known Exploited Vulnerabilities (https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/cisa-known-exploited-vulnerabilities)


## Configuration

Configuring the connector is straightforward. The minimal setup requires entering the RST Cloud API key and specifying the OpenCTI connection settings. Below is the full list of parameters you can configure:

| Parameter                                          | Docker envvar                                | Mandatory | Description                                                                                                                                                                                    |
| -------------------------------------------------- | -------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenCTI URL                                        | `OPENCTI_URL`                                | Yes       | The URL of the OpenCTI platform.                                                                                                                                                               |
| OpenCTI Token                                      | `OPENCTI_TOKEN`                              | Yes       | The default admin token set in the OpenCTI platform.                                                                                                                                           |
| Connector ID                                       | `CONNECTOR_ID`                               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                                                                      |
| Connector Name                                     | `CONNECTOR_NAME`                             | Yes       | Name of the connector. For example: `RST Threat Feed`.                                                                                                                                         |
| Connector Scope                                    | `CONNECTOR_SCOPE`                            | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. E.g. application/json                                                                                 |
| Log Level                                          | `CONNECTOR_LOG_LEVEL`                        | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                                                                         |
| Run and Terminate                                  | `CONNECTOR_RUN_AND_TERMINATE`                | Yes       | If set to true, the connector will terminate after a successful run. Useful for debugging or one-time runs.                                                                                    |
| Interval                                           | `CONFIG_INTERVAL`                            | Yes       | Determines how often the connector will run, set in hours.                                                                                                                                     |
| RST Threat Feed API Key                            | `RST_THREAT_FEED_API_KEY`                    | Yes       | Your API Key for accessing RST Cloud.                                                                                                                                                          |
| RST Threat Feed Base URL                           | `RST_THREAT_FEED_BASEURL`                    | No        | By default, use https://api.rstcloud.net/v1/. In some cases, you may want to use a local API endpoint                                                                                          |
| SSL Verification                                   | `RST_THREAT_FEED_SSL_VERIFY`                 | No        | Default: `true`. If set to `false`, SSL verification is disabled (use with caution, sometimes needed when SSL inspection is enabled).                                                          |
| Enable IP Threat Feed                              | `RST_THREAT_FEED_IP`                         | No        | Default: `true`. If `true`, the connector retrieves threat intelligence data for IP addresses.                                                                                                 |
| Enable Domain Threat Feed                          | `RST_THREAT_FEED_DOMAIN`                     | No        | Default: `true`. If `true`, the connector retrieves threat intelligence data for domains.                                                                                                      |
| Enable URL Threat Feed                             | `RST_THREAT_FEED_URL`                        | No        | Default: `true`. If `true`, the connector retrieves threat intelligence data for URLs.                                                                                                         |
| Enable Hash Threat Feed                            | `RST_THREAT_FEED_HASH`                       | No        | Default: `true`. If `true`, the connector retrieves threat intelligence data for file hashes (MD5, SHA1, SHA256).                                                                              |
| Threat Feed Data Fetch Interval                    | `RST_THREAT_FEED_LATEST`                     | No        | Default: `day`. Defines how often the latest threat feed data is fetched. Options: `1h`, `4h`, `12h`, or `day`.                                                                                |
| RST Threat Feed Connection Timeout                 | `RST_THREAT_FEED_CONTIMEOUT`                 | No        | Connection timeout to the API. Default (sec): `30`                                                                                                                                             |
| RST Threat Feed Read Timeout                       | `RST_THREAT_FEED_READTIMEOUT`                | No        | Read timeout for each feed. Our API redirects the connector to download data from AWS S3. If the connector is unable to fetch the feed in time, increase the read timeout. Default (sec): `60` |
| RST Threat Feed Download Retry Count               | `RST_THREAT_FEED_RETRY`                      | No        | Default (attempts): `5`                                                                                                                                                                        |
| RST Threat Feed Fetch Interval                     | `RST_THREAT_FEED_INTERVAL`                   | No        | Default (sec): `86400`. If you choose to fetch data hourly, please update this interval accordingly.                                                                                           |
| RST Threat Feed Minimal Score to Import            | `RST_THREAT_FEED_MIN_SCORE_IMPORT`           | No        | Import only indicators with risk score more than X. The objects that are related to these indicators will also be imported with corresponding relations. Default (score): `20`                 |
| RST Threat Feed Minimum Score for IP Detection     | `RST_THREAT_FEED_MIN_SCORE_DETECTION_IP`     | No        | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45`                                                                                         |
| RST Threat Feed Minimum Score for Domain Detection | `RST_THREAT_FEED_MIN_SCORE_DETECTION_DOMAIN` | No        | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45`                                                                                         |
| RST Threat Feed Minimum Score for URL Detection    | `RST_THREAT_FEED_MIN_SCORE_DETECTION_URL`    | No        | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45`                                                                                         |
| RST Threat Feed Minimum Score for Hash Detection   | `RST_THREAT_FEED_MIN_SCORE_DETECTION_HASH`   | No        | Indicators with risk score more than X are marked with x_opencti_detection=true. Default (score): `45`                                                                                         |
| RST Threat Feed Import only New Indicators         | `RST_THREAT_FEED_ONLY_NEW`                   | No        | Defines if you only want to import indicators with recent "First Seen" or also want to re-import changes to the indicators with "Last Seen" >= yesterday. Default: `true`                      |
