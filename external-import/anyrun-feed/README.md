<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="https://raw.githubusercontent.com/anyrun/anyrun-sdk/b3dfde1d3aa018d0a1c3b5d0fa8aaa652e80d883/static/logo.svg">
    </a>
</p>

______________________________________________________________________

## ANY.RUN Threat Intelligence Feeds connector for OpenCTI 

ANY.RUN’s [Threat Intelligence Feeds](https://any.run/threat-intelligence-feeds/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_feeds&utm_content=linktofeedslanding) (TI Feeds) is a continuously updated source of fresh network-based Indicators of Compromise (IOCs): IPs, domains, and URLs. 

The IOCs are extracted from real-time analyses done by experts from 15,000 companies in ANY.RUN’s Interactive Sandbox. 

### Connector’s functionality 

The connector for Threat Intelligence Feeds provides OpenCTI users with simple, automated access to uniquely sourced and accurate indicators of compromise. 

* Enrich OpenCTI artifacts with context from threat investigations
* Get access to pre-processed IOCs with minimum false positives
* Detect threats early and prevent attacks using high-quality indicators 

Key SOC benefits 

Integrate TI Feeds with OpenCTI for an easy access to all the benefits it brings:  

* Expanded Coverage: ANY.RUN’s exclusive IOCs come from Memory Dumps, Suricata IDS, in-browser data, and internal threat categorization systems, increasing the chance of detection of the most evasive threats.
* Reduced Workload: The indicators are pre-processed to avoid false positives and ready to be used for malware analysis or incident investigation.
* Informed Response: Rich metadata provided for IOCs gives you the context for in-depth threat investigations and faster response.  

### Installation 

To use the integration, ensure you have an active [ANY.RUN TI Feeds subscription](https://intelligence.any.run/plans/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_feeds&utm_content=linktotiplans ).
ANY.RUN TI Feeds connector for OpenCTI is a standalone Python service that requires access to both the OpenCTI platform and RabbitMQ.
RabbitMQ credentials and connection parameters are provided automatically by the OpenCTI API, based on the platform’s configuration. 

You can enable the connector in one of the following ways: 

* Run as a Python process: simply configure the config.yml file with the appropriate values and launch the connector directly.
* Run in Docker: use the ANY.RUN docker image anyrun/opencti-connector-anyrun-feed:latest 

ANY.RUN provides a sample docker-compose.yml file, which can be used as a standalone deployment or integrated into OpenCTI’s main docker-compose.yml. 

Note: 

* If you deploy the connector independently, make sure it can reach RabbitMQ on the port defined in your OpenCTI configuration.
* If you're experiencing issues or require an immediate update, ANY.RUN can provide an updated Docker image upon request. Please contact our support team at support@any.run. 

### Requirements 

* OpenCTI Platform >= 6.7.4
* ANY.RUN TI Feeds subscription  

### Generate your API KEY 

Please use ANY.RUN’s API key without a prefix. Prefixed API keys and Basic Authentication for TI Feeds won’t be supported in future releases.   
For assistance or access to ANY.RUN’s services, please reach out to our [sales team](https://any.run/enterprise/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_feeds&utm_content=linktoenterprise#contact-sales).
---

### Configuration

The connector can be configured with the following variables:  


| Parameter                        | Docker envvar                    | Mandatory | Description                                                                                                                                                                                 |
|----------------------------------|----------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                    | `OPENCTI_URL`                    | Yes       | The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080`                                                                                |
| `opencti_token`                  | `OPENCTI_TOKEN`                  | Yes       | The default admin token configured in the OpenCTI platform parameters file. We recommend setting up a separate ``OPENCTI_TOKEN`` named **ANY.RUN** to identify the work of our integrations. |
| `connector_id`                   | `CONNECTOR_ID`                   | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                                          |
| `connector_name`                 | `CONNECTOR_NAME`                 | Yes       | A connector name to be shown in OpenCTI.                                                                                                                                                    |
| `connector_scope`                | `CONNECTOR_SCOPE`                | Yes       | Supported scope. E. g., `text/html`.                                                                                                                                                        |
| `connector_log_level`            | `CONNECTOR_LOG_LEVEL`            | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                                               |
| `connector_update_existing_data` | `CONNECTOR_UPDATE_EXISTING_DATA` | Yes       | Update data already ingested into the platform.                                                                                                                                             |
| `api_key`                        | `ANYRUN_API_KEY`                 | Yes       | ANY.RUN TI Feeds API key. See "Generate your API KEY" section in the README file. Example: WmNfqnpo...2Sjon7mtvm8e                                                                          |
| `feed_fetch_interval`            | `ANYRUN_FEED_FETCH_INTERVAL`     | Yes       | Specify feed fetch interval in minutes                                                                                                                                                      |
| `feed_fetch_depth`               | `ANYRUN_FEED_FETCH_DEPTH`        | Yes       | Specify feed fetch depth in days                                                                                                                                                            |

## Support
This is an ANY.RUN’s supported connector. You can write to us for help with integration via [support@any.run](mailto:support@any.run). 

Contact us for a quote or demo via [this form](https://app.any.run/contact-us/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_feeds&utm_content=linktocontactus). 