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

Configuring the connector is straightforward. The minimal setup requires entering the RST Cloud API key and specifying the OpenCTI connection settings. Below is the full list of parameters you can configure:

| Parameter                                      | Docker envvar                                  | Mandatory | Description                                                                                                    |
| ---------------------------------------------- | ---------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------- |
| OpenCTI URL                                    | `OPENCTI_URL`                                  | Yes       | The URL of the OpenCTI platform.                                                                               |
| OpenCTI Token                                  | `OPENCTI_TOKEN`                                | Yes       | The default connector (or admin) token set in the OpenCTI platform.                                            |
| Connector ID                                   | `CONNECTOR_ID`                                 | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                      |
| Connector Type                                 | `CONNECTOR_TYPE`                               | Yes       | Should always be set to `INTERNAL_ENRICHMENT` for this connector.                                              |
| Connector Name                                 | `CONNECTOR_NAME`                               | Yes       | Name of the connector. For example: `RST Noise Control`.                                                       |
| Connector Scope                                | `CONNECTOR_SCOPE`                              | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. E.g. application/json |
| Log Level                                      | `CONNECTOR_LOG_LEVEL`                          | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                         |
| Update Existing Data                           | `CONFIG_UPDATE_EXISTING_DATA`                  | Yes       | Decide whether the connector should update already existing data in the database.                              |
| Auto Enrichment                                | `CONNECTOR_AUTO`                               | No        | Determines if the connector to be invoked automatically or by a user                                           |
| RST Noise Control API Key                      | `RST_NOISE_CONTROL_API_KEY`                    | Yes       | Your API Key for accessing RST Cloud.                                                                          |
| RST Noise Control Base URL                     | `RST_NOISE_CONTROL_BASEURL`                    | No        | By default, use https://api.rstcloud.net/v1/. In some cases, you may want to use a local API endpoint          |
| RST Noise Control Max TLP                      | `RST_NOISE_CONTROL_MAX_TLP`                    | No        | By default, TLP:AMBER. Use correct TLP values+STRICT                                                           |
| RST Noise Control Change Score Action          | `RST_NOISE_CONTROL_CHANGE_ACTION_SCORE_CHANGE` | No        | By default, reduce score by subsctracting 10 from the x-opencti-score or drop to 0 if it is less               |
| RST Noise Control Drop Action                  | `RST_NOISE_CONTROL_DROP_ACTION_SCORE_CHANGE`   | No        | By default, reduce score by subsctracting 50 from the x-opencti-score or drop to 0 if it is less               |
| RST Noise Control Unset Detection Flag if Drop | `RST_NOISE_CONTROL_DROP_ACTION_DETECTION_FLAG` | No        | By default, true. If action is Drop, unset the detection flag                                                  |
