# RST WHOIS API Connector for OpenCTI by RST Cloud

The **RST WHOIS API Connector** enriches domain and URL observables and indicators with domain registration data. It enhances the capabilities of OpenCTI by providing an affordable way to retrieve WHOIS and RDAP data, depending on which protocol is applicable for the domain. If the observable is a subdomain, the connector returns the WHOIS data of the parent domain. ([RST WHOIS API](https://www.rstcloud.com/rst-whois-api/)).

## Key Features

- **Automatic or Manual Trigger**: Indicators and observables can be automatically checked each time they are updated, or users can initiate a check manually.  
- **Ease of Use**: No need to determine whether you need to choose RDAP or WHOIS to retrieve domain registration data, you always get the same JSON output.  
- **No Bans**: If you perform enrichment at scale, you might get banned by WHOIS servers. This API allows you to avoid that issue.  
- **Effective TLD Discovery**: If the requested domain is a subdomain that does not have registration data, the effective TLD is extracted, and domain registration data is returned for that TLD.  
- **Near-real Time**: Domain registration data is fetched from live servers in real time, with short-lived caching enabled.
- **RAW Response**: You can save the raw response if needed.  
- **Pay-as-you-go**: No need to commit to millions of requests or worry about limits. You can make as many requests as you need today.  


## Requirements

- OpenCTI Platform version 6.0.x or higher.
- An API Key for accessing RST Cloud (trial@rstcloud.net or via [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-bmd536bqonz22))

## Configuration

Configuring the connector is straightforward. The minimal setup requires entering the RST Cloud API key and specifying the OpenCTI connection settings. Below is the full list of parameters you can configure:


| Parameter                          | Docker Env Variable                  | Mandatory | Description                                                                                     |
| ---------------------------------- | ------------------------------------ | --------- | ----------------------------------------------------------------------------------------------- |
| OpenCTI URL                        | `OPENCTI_URL`                        | Yes       | The URL of the OpenCTI platform.                                                                |
| OpenCTI Token                      | `OPENCTI_TOKEN`                      | Yes       | The API token for authentication in OpenCTI.                                                    |
| Connector ID                       | `CONNECTOR_ID`                       | Yes       | A unique `UUIDv4` identifier for this connector instance.                                       |
| Connector Name                     | `CONNECTOR_NAME`                     | Yes       | Name of the connector (e.g., `RST WHOIS API`).                                                  |
| Connector Scope                    | `CONNECTOR_SCOPE`                    | Yes       | The scope/type of data the connector is handling (e.g., `Domain-Name,Url,indicator`).           |
| Log Level                          | `CONNECTOR_LOG_LEVEL`                | Yes       | Log verbosity level: `debug`, `info`, `warn`, or `error`.                                       |
| RST WHOIS API Key                  | `RST_WHOIS_API_API_KEY`              | Yes       | Your API Key for RST Cloud.                                                                     |
| RST WHOIS API Base URL             | `RST_WHOIS_API_BASE_URL`             | No        | Default: `https://api.rstcloud.net/v1/`. Can be changed if using a different endpoint.          |
| RST WHOIS API Max TLP              | `RST_WHOIS_API_MAX_TLP`              | No        | Default: `TLP:AMBER+STRICT`. Use appropriate TLP values.                                        |
| RST WHOIS API Timeout              | `RST_WHOIS_API_TIMEOUT`              | No        | Default: `10` seconds. Defines the response timeout.                                            |
| RST WHOIS API Update Output Action | `RST_WHOIS_API_UPDATE_OUTPUT_ACTION` | No        | Default: `overwrite`. Options: `overwrite`, `append`. Determines how existing data is updated.    |
| RST WHOIS API WHOIS Output Object  | `RST_WHOIS_API_WHOIS_OUTPUT_OBJECT`  | No        | Default: `note`. Options: `note`, `description`. Determines how WHOIS data is stored.           |
| RST WHOIS API Output Format        | `RST_WHOIS_API_OUTPUT_FORMAT`        | No        | Default: `standard`. Options: `standard`, `extended`. Specifies the format of the WHOIS output. |
| RST WHOIS API Include Raw Output   | `RST_WHOIS_API_OUTPUT_INCLUDE_RAW`   | No        | Default: `false`. If `true`, includes raw WHOIS response.                                       |
