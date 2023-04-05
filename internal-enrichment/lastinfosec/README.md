# ![Image of LastInfoSec](LASTINFOSEC_LOGO_NOIR.png) LastInfoSec Connector for OpenCTI !

OpenCTI LastInfoSec connector will use the `/v2/stix21/search_hash/{hash}` and `/v2/stix21/search_host/{host}` API.

Requirement : if you want to use LastInfoSec's intelligence, you need an API key. You could contact LastInfoSec's team here https://info.gatewatcher.com/en/lp/opencti

LastInfosec has been acquired by Gatewatcher.
LastInfoSec's Threat Feed is a data feed that makes it easier to detect threats within the information system. It contains enriched compromised evidences in order to reduce the time of threat analysis once detected.
https://www.gatewatcher.com/en/our-solutions/lastinfosec/


## Configuration

The connector can be configured with the following variables:

| Config Parameter       | Docker env var                   | Default                                     | Description                                                 |
| -----------------------| -------------------------------- | ------------------------------------------- | ----------------------------------------------------------- |
| `url`             | `OPENCTI_URL`              | `ChangeMe` |    OpenCTI URL, example: `http://localhost:8080`    |
| `token`             | `OPENCTI_TOKEN`              | `ChangeMe`                                        | token OpenCTI      |
| `id`         | `CONNECTOR_ID`          | `Changeme`                                     | ID Connector     |
| `api_key_cti`        | `CONFIG_LIS_APIKEY_CTI`         | `ChangeMe`                                     | LastinfoSec API Key  |
| `proxy_http`        | `PROXY_HTTP`         | None                                     | HTTP Proxy (Optional)  |
| `proxy_https`        | `PROXY_HTTPS`         | None                                     | HTTPS Proxy (Optional)  |
