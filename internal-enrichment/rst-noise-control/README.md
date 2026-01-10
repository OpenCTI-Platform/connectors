# RST Noise Control Connector for OpenCTI by RST Cloud

The **RST Noise Control Connector** allows OpenCTI to check if observables and indicators are benign or potentially noisy and not worth detecting. This connector performs a check of IP, Domain, URL, Hash values via RST Cloud API. This enhances the capability of OpenCTI by ensuring that well-known, popular, or benign values will not trigger thousands of FP detections or prevent actions in the connected security tools ([RST Noise Control](https://www.rstcloud.com/rst-noise-control/)).

## Key Features

- **Automatic or Manual Trigger**: Indicators and observables can be automatically checked each time they are updated or a user can initiate a check by themselves.
- **Trusted Filter List**: Trusted sources of IoCs can be added to a filter list to avoid consumption of the API key limits
- **Customizable Score Adjustments**: Users can specify how much score of indicators and observables should be decreased if an API response suggests action "Drop" or "Change Score" as the verified value is potentially found benign
- **Customizable Detection Flag**: Users can specify if the detection flag is to be unset when an API response includes the Noise Conrol action "Drop" (x_opencti_detection=true|false)
- **Pay-as-you-go**: No need to commit to millions of requests or worry about limits. You can make as many requests as you need today.  

## Requirements

- OpenCTI Platform version 6.0.x or higher.
- An API Key for accessing RST Cloud (trial@rstcloud.net or via [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-bmd536bqonz22)).

## Configuration
Configuring the connector is straightforward. The minimal setup requires entering the RST Cloud API key and specifying the OpenCTI connection settings. 

**NOTE**: 
At present, enriching all indicators is not always feasible, as performance considerations apply until batch lookup support becomes available in OpenCTI. In these situations, many users rely on scripts (for example, in Python) to retrieve data from OpenCTI via the API, perform batch lookups against the Noise Control API, and then apply custom logic to update indicators or observables.
Running multiple instances of the Noise Control Connector is another way to scale enrichment, and the connector itself remains very effective for targeted use cases when appropriate filters are defined for what is sent to Noise Control.
For example, if an indicator has a high score and carries a scan tag, and Noise Control identifies the IP as belonging to Censys or Shadowserver scanners, the indicator can be revoked or, alternatively, tagged so it is pushed to a firewall for automated handling, but not pushed to a SIEM for detection. Another example is domains that belong to large platforms such as Office 365: these can be marked as benign to prevent them from being used in automated response pipelines.
A further use case is dealing with noisy but valuable data sources. By applying Noise Control filtering to these feeds, it becomes possible to extract meaningful intelligence without being overwhelmed by false positives.


Below is the full list of parameters you can configure:

| Parameter                                      | Docker envvar                                  | Mandatory | Description                                                                                                    |
| ---------------------------------------------- | ---------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------- |
| OpenCTI URL                                    | `OPENCTI_URL`                                  | Yes       | The URL of the OpenCTI platform.                                                                               |
| OpenCTI Token                                  | `OPENCTI_TOKEN`                                | Yes       | The default connector (or admin) token set in the OpenCTI platform.                                            |
| Connector ID                                   | `CONNECTOR_ID`                                 | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                      |
| Connector Name                                 | `CONNECTOR_NAME`                               | Yes       | Name of the connector. For example: `RST Noise Control`.                                                       |
| Connector Scope                                | `CONNECTOR_SCOPE`                              | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. E.g. application/json |
| Log Level                                      | `CONNECTOR_LOG_LEVEL`                          | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                         |
| Auto Enrichment                                | `CONNECTOR_AUTO`                               | No        | Determines if the connector to be invoked automatically or by a user                                           |
| RST Noise Control API Key                      | `RST_NOISE_CONTROL_API_KEY`                    | Yes       | Your API Key for accessing RST Cloud.                                                                          |
| RST Noise Control Base URL                     | `RST_NOISE_CONTROL_BASE_URL`                   | No        | By default, use https://api.rstcloud.net/v1. In some cases, you may want to use a local API endpoint           |
| RST Noise Control Timeout                      | `RST_NOISE_CONTROL_TIMEOUT`                    | No        | By default, 10 seconds. API request timeout in seconds                                                        |
| RST Noise Control Max TLP                      | `RST_NOISE_CONTROL_MAX_TLP`                    | No        | By default, TLP:AMBER. Use correct TLP values+STRICT                                                           |
| RST Noise Control Change Score Action          | `RST_NOISE_CONTROL_CHANGE_ACTION_SCORE_CHANGE` | No        | By default, reduce score by subsctracting 10 from the x-opencti-score or drop to 0 if it is less               |
| RST Noise Control Drop Action                  | `RST_NOISE_CONTROL_DROP_ACTION_SCORE_CHANGE`   | No        | By default, reduce score by subsctracting 50 from the x-opencti-score or drop to 0 if it is less               |
| RST Noise Control Unset Detection Flag if Drop | `RST_NOISE_CONTROL_DROP_ACTION_DETECTION_FLAG` | No        | By default, true. If action is Drop, unset the detection flag                                                  |
