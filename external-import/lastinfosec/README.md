# ![Image of LastInfoSec](LASTINFOSEC_LOGO_NOIR.png) LastInfoSec Connectors for OpenCTI !

OpenCTI LastInfoSec connectors.

Requirement : if you want to use LastInfoSec's intelligence, you need an API key. You could contact LastInfoSec's team here https://info.gatewatcher.com/en/lp/opencti

LastInfosec has been acquired by Gatewatcher => https://www.gatewatcher.com/en/our-solutions/lastinfosec/

## Configuration and Information

All LastInfoSec connectors must be configured with the following global variables:

| Config Parameter              | Docker env var                         | Default         | Description                                             |
| ------------------------------| -------------------------------------- | ----------------| --------------------------------------------------------|
| `connector.run_and_terminate` | `CONNECTOR_RUN_AND_TERMINATE`          | False           | Run the connector only once time                        |
| `opencti.url`                 | `OPENCTI_URL`                          | `ChangeMe`      | OpenCTI URL, example: `http://localhost:8080`           |
| `opencti.token`               | `OPENCTI_TOKEN`                        | `ChangeMe`      | token OpenCTI                                           |
| `opencti.proxy_http`          | `PROXY_HTTP`                           | None            | HTTP Proxy (Optional)                                   |
| `opencti.proxy_https`         | `PROXY_HTTPS`                          | None            | HTTPS Proxy (Optional)                                  |
| `connector.id`                | `CONNECTOR_ID`                         | `Changeme`      | ID Connector                                            |
| `lastinfosec.api_key`         | `CONFIG_LIS_APIKEY`                    | `ChangeMe`      | LastinfoSec CTI API Key                                 |

This LastInfosec's Threat Feed contains STIXv2.1 reports with Ip observables, URLs, Hashs, Domains Indicators with Relations to Indicator, Malware, Tool, Intrusion-set, Vulnerabilities, Attack-Pattern, Identity and Location.
It make it easier to detect threats within the information system. It contains enriched compromised evidences in order to reduce the time of threat analysis once detected.
The LastInfoSec `CTI` connector can be configured with the following global variables:

| Config Parameter                 | Docker env var                   | Default           | Description                                                                                                     |
| ---------------------------------| -------------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------- |
| `lastinfosec.cti.is_enabled`     | `CONFIG_LIS_CTI_ENABLED`         | False             | Set it to True to enable the LastInfoSec CTI connector                                                          |
| `lastinfosec.cti.interval`       | `CONFIG_LIS_CTI_INTERVAL`        | 30                | url minutes argument. Example: 30: The connector will run every 30 minutes to get IOCs for the last 30 minutes  |

This LastInfosec's CVE Feed is collected hourly. It contains STIXv2.1 bundles with new or updated vulnerability objects.
The LastInfoSec `CVE` connector can be configured with the following global variable(s):

| Config Parameter                 | Docker env var                   | Default           | Description                                                                                                     |
| ---------------------------------| -------------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------- |
| `lastinfosec.cve.is_enabled`     | `CONFIG_LIS_CVE_ENABLED`         | False             | Set it to True to enable the LastInfoSec CVE connector                                                          |

This LastInfosec's CTI TACTIC Feed is collected daily in order to add the intelligence about Malware and Intrusion-Set. It contains STIXv2.1 bundles with Malware or Intrusion-set objects with their relations to Malware, Intrusion-set, Vulnerabilities, Attack-Pattern and Identity objects.
The LastInfoSec `TACTIC` connector can be configured with the following global variable(s):

| Config Parameter                 | Docker env var                   | Default           | Description                                                                                                     |
| ---------------------------------| -------------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------- |
| `lastinfosec.tactic.is_enabled`  | `CONFIG_LIS_TACTIC_ENABLED`      | False             | Set it to True to enable the LastInfoSec Tactic connector                                                       |
