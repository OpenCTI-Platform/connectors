<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="https://raw.githubusercontent.com/anyrun/anyrun-sdk/b3dfde1d3aa018d0a1c3b5d0fa8aaa652e80d883/static/logo.svg">
    </a>
</p>

______________________________________________________________________


## ANY.RUN Threat Intelligence Lookup connector for OpenCTI 

ANY.RUN’s [Threat Intelligence Lookup](https://any.run/threat-intelligence-lookup/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_lookup&utm_content=linktolookuplanding) (TI Lookup) is a service that allows you to browse IOCs and related threat data to simplify and enrich cyberattack investigations. 

### Connector’s functionality 

The Threat Intelligence Lookup сonnector enables OpenCTI users to browse various types of IOCs, from IPs and domains to URLs and hashes. 

* Browse indicators in TI Lookup without leaving OpenCTI
* Receive data related to your query to gain actionable insights
* Use them for incident response, to create new rules, train models, update playbooks, etc. 

### Key SOC benefits 

As a result of integration of TI Lookup with OpenCTI, you’ll achieve: 

* Early Threat Detection: Correlate IOCs to identify incidents before they escalate.
* Proactive Defense Enrichment: Collect indicators from attacks on other companies to update your detection systems.
* Reduced MTTR and Increased Detection Rate: Access to rich threat context enables SOCs to make informed decisions fast. 

 
### Installation 

To use this integration, make sure that you have an active [ANY.RUN TI Lookup license](https://intelligence.any.run/plans/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_lookup&utm_content=linktotiplans).
ANY.RUN TI Lookup connector for OpenCTI is a standalone Python service that requires access to both the OpenCTI platform and RabbitMQ.
RabbitMQ credentials and connection parameters are provided automatically by the OpenCTI API, based on the platform’s configuration. 

You can enable the connector in one of the following ways: 

* Run as a Python process: simply configure the config.yml file with the appropriate values and launch the connector directly.
* Run in Docker: use the OpenCTI docker image anyrun/opencti-connector-anyrun-ti-lookup:latest 

ANY.RUN provides a sample docker-compose.yml file, which can be used as a standalone deployment or integrated into OpenCTI’s main docker-compose.yml. 

Note: 

* If you deploy the connector independently, make sure it can reach RabbitMQ on the port defined in your OpenCTI configuration.
* If you're experiencing issues or require an immediate update, ANY.RUN can provide an updated Docker image upon request. Please contact our support team at support@any.run. 

### Requirements

- OpenCTI Platform >= 6.7.4
- ANY.RUN TI Lookup license

### Generate API key

* Go to [ANY.RUN Sandbox](https://app.any.run/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_sandbox&utm_content=linktoservice)
* Click Profile > API and Limits > Generate > Copy 

![ANY.RUN Generate API KEY](static/ANYRUN_API_TOKEN.png)


### Configuration


The connector can be configured with the following variables:

| Parameter                    | Docker env_var                   | Mandatory | Description                                                                                                                                                                                  |
|------------------------------|----------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                | `OPENCTI_URL`                    | Yes       | The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080`                                                                                 |
| `opencti_token`              | `OPENCTI_TOKEN`                  | Yes       | The default admin token configured in the OpenCTI platform parameters file. We recommend setting up a separate ``OPENCTI_TOKEN`` named **ANY.RUN** to identify the work of our integrations. |
| `connector_id`               | `CONNECTOR_ID`                   | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                                           |
| `connector_type`             | `CONNECTOR_TYPE`                 | Yes       | A connector type.                                                                                                                                                                            |
| `connector_name`             | `CONNECTOR_NAME`                 | Yes       | A connector name to be shown in OpenCTI.                                                                                                                                                     |
| `connector_scope`            | `CONNECTOR_SCOPE`                | Yes       | Supported scope. E. g., `text/html`.                                                                                                                                                         |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL`     | Yes       | The default confidence level for created sightings (a number between 1 and 4).                                                                                                               |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`            | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                                                |
| `auto`                       | `CONNECTOR_AUTO`                 | Yes       | Enable/disable auto-enrichment of observables.                                                                                                                                               |
| `token`                      | `ANYRUN_API_KEY`                   | Yes       | ANY.RUN Lookup API-KEY. See "Generate API KEY" section in the README file.                                                                                                                   |
| `lookup_depth`               | `ANYRUN_LOOKUP_DEPTH`                   | Yes       | Specify the number of days from the current date for which you want to lookup.                                                                                                               |

## Support
This is an ANY.RUN’s supported connector. You can write to us for help with integration via [support@any.run](mailto:support@any.run). 

Contact us for a quote or demo via [this form](https://app.any.run/contact-us/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_lookup&utm_content=linktocontactus ). 