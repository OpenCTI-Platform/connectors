<p align="center">
    <a href="#readme">
        <img alt="ANY.RUN logo" src="https://raw.githubusercontent.com/anyrun/anyrun-sdk/b3dfde1d3aa018d0a1c3b5d0fa8aaa652e80d883/static/logo.svg">
    </a>
</p>

______________________________________________________________________

# OpenCTI ANY.RUN Task Connector

| Status           | Date | Comment |
|------------------|------|---------|
| Partner Verified | -    | -       |

The ANY.RUN Task connector analyzes URL and StixFile observables in the ANY.RUN Interactive Online Malware Sandbox, enriching them with sandbox analysis results including threat scores, tags, and IOCs.

## Table of Contents

- [OpenCTI ANY.RUN Task Connector](#opencti-anyrun-task-connector)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
    - [Generate API-KEY](#generate-api-key)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Base ANY.RUN environment variables](#base-anyrun-environment-variables)
    - [ANY.RUN Windows environment variables](#anyrun-windows-environment-variables)
    - [ANY.RUN Linux environment variables](#anyrun-linux-environment-preferences)
    - [ANY.RUN Android environment variables](#anyrun-android-environment-preferences)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)
  - [Support](#support)

## Introduction

[ANY.RUN's Interactive Sandbox](https://any.run/features/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_sandbox&utm_content=linktosandboxlanding) is a cloud-based service that provides SOC teams with a simple way to analyze cyber threats, enabling rapid threat intelligence and deep analysis in a secure environment.  

The connector for the Interactive Sandbox enables OpenCTI users to quickly analyze and identify observables, such as files and URLs in the cloud sandbox. 

* Perform real-time analysis to make fast decisions
* Get detailed reports that include insights into network activity, dropped files, and MITRE ATT&CK techniques
* Enrich observables in OpenCTI 

As a result of the integration of ANY.RUN’s Interactive Sandbox with OpenCTI, you’ll achieve: 

* Streamlined Triage and Detection: Automate threat analysis to receive actionable verdicts and reports to prioritize incidents effectively.
* Shorter MTTD and MTTR: Lower response times by gaining a full understanding of the threat’s behavior in seconds.
* Higher Detection Rates: In-depth insights and advanced detection mechanisms provide deep visibility into complex threats.
* Minimized Workload: Reduce analyst workload by automating repetitive tasks.
* Stronger Security: Use sandbox reports and related data to refine rules, update playbooks, and train threat detection models. 


## Installation

To use this integration, make sure that you have an active [ANY.RUN Sandbox license](https://app.any.run/plans/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_sandbox&utm_content=linktopricing).
ANY.RUN connector for OpenCTI is a standalone Python service that requires access to both the OpenCTI platform and RabbitMQ.
RabbitMQ credentials and connection parameters are provided automatically by the OpenCTI API, based on the platform’s configuration. 

You can enable the connector in one of the following ways: 

* Run as a Python process: simply configure the config.yml file with the appropriate values and launch the connector directly.
* Run in Docker: use the OpenCTI docker image opencti/connector-anyrun-task


### Requirements

- OpenCTI Platform >= 6.0.0
- Available on ANY.RUN plans with API access, including trial

### Generate API-KEY

* Go to [ANY.RUN Sandbox](https://app.any.run/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_sandbox&utm_content=linktoservice)
* Click Profile > API and Limits > Generate > Copy
![img.png](static/ANYRUN_API_TOKEN.png)

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

#### OpenCTI environment variables
| Parameter                    | Docker envvar                    | Mandatory | Description                                                                                                                                                                                  |
|------------------------------|----------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`                | `OPENCTI_URL`                    | Yes       | The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080`                                                                                 |
| `opencti_token`              | `OPENCTI_TOKEN`                  | Yes       | The default admin token configured in the OpenCTI platform parameters file. We recommend setting up a separate ``OPENCTI_TOKEN`` named **ANY.RUN** to identify the work of our integrations. |

#### Base connector environment variables
| Parameter                    | Docker envvar                    | Mandatory | Description                                                                                                                                                                                  |
|------------------------------|----------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `connector_id`               | `CONNECTOR_ID`                   | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                                           |
| `connector_type`             | `CONNECTOR_TYPE`                 | Yes       | A connector type.                                                                                                                                                                            |
| `connector_name`             | `CONNECTOR_NAME`                 | Yes       | A connector name to be shown in OpenCTI.                                                                                                                                                     |
| `connector_scope`            | `CONNECTOR_SCOPE`                | Yes       | Supported scope. E. g., `text/html`.                                                                                                                                                         |                     
| `connector_auto`             | `CONNECTOR_AUTO`                 | Yes       | Enable/disable auto-enrichment of observables.                                                                                                                                               |
| `connector_confidence_level` | `CONNECTOR_CONFIDENCE_LEVEL`     | Yes       | The default confidence level for created sightings (a number between 0 and 100, where 0 = Unknown and 100 = Fully trusted).                                                                  |
| `connector_log_level`        | `CONNECTOR_LOG_LEVEL`            | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                                                |

#### Base ANY.RUN environment variables
| Parameter                    | Docker envvar                    | Mandatory | Description                                                                                                                                                                                  |
|------------------------------|----------------------------------|-----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `token`                      | `ANYRUN_API_KEY`                 | Yes       | ANY.RUN Sandbox API-KEY. See "Generate API KEY" section in the README file.                                                                                                                  |
| `opt_timeout`                      | `ANYRUN_OPT_TIMEOUT`                 | No        | Select analysis completion time. Size range: 10-660 seconds.                                                                                                                                 |
| `opt_network_connect`                      | `ANYRUN_OPT_NETWORK_CONNECT`                 | No        | Enable network connection.                                                                                                                                                                   |
| `opt_network_fakenet`                      | `ANYRUN_OPT_NETWORK_FAKENET`                 | No        | Enable FakeNet feature.                                                                                                                                                                      |
| `opt_network_tor`                      | `ANYRUN_TOR`                 | No        | Enable TOR using.                                                                                                                                                                            |
| `opt_network_geo`                      | `ANYRUN_GEO`                 | No        | TOR geolocation option. Example: US, AU                                                                                                                                                      |
| `opt_network_mitm`                      | `ANYRUN_MITM`                 | No        | Enable HTTPS MITM Proxy using.                                                                                                                                                               |
| `opt_network_residential_proxy`                      | `ANYRUN_RESIDENTIAL_PROXY`                 | No        | Residential proxy using.                                                                                                                                                                     |
| `opt_network_residential_proxy_geo`                      | `ANYRUN_RESIDENTIAL_PROXY_GEO`                 | No        | Residential proxy geolocation option. Example: US, AU.                                                                                                                                       |
| `opt_privacy_type`                      | `ANYRUN_PRIVACY_TYPE`                 | No        | Privacy settings. Supports: public, bylink, owner, byteam.                                                                                                                                   |
| `obj_ext_extension`                      | `ANYRUN_OBJ_EXT_EXTENSION`                 | No        | Automatically change file extension to valid.                                                                                                                                                |
| `env_locale`                      | `ANYRUN_ENV_LOCALE`                 | No        | Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case-insensitive.                                                                              |

#### ANY.RUN Windows environment variables
| Parameter                    | Docker envvar                    | Mandatory | Description                                                                                                   |
|------------------------------|----------------------------------|-----------|---------------------------------------------------------------------------------------------------------------|
|`os_type`                      | `ANYRUN_OS_TYPE`                 | Yes       | Must be `windows`|      
| `env_version`                | `ANYRUN_ENV_VERSION`                    | No       | Version of OS. Supports: 7, 10, 11.  |
| `env_bitness`              | `ANYRUN_ENV_BITNESS`                  | No       | Bitness of Operation System. Supports 32, 64.                                   |
| `env_type`               | `ANYRUN_ENV_TYPE`                   | No       | Environment preset type. You can select **development** env for OS Windows 10 x64. For all other cases, **complete** env is required.                                            |
| `obj_ext_startfolder`             | `ANYRUN_OBJ_EXT_STARTFOLDER`                 | No       | Supports: desktop, home, downloads, appdata, temp, windows, root.                                                                                             |
| `obj_ext_cmd`             | `ANYRUN_OBJ_EXT_CMD`                 | No       | Optional command-line arguments for the analyzed object. Use an empty string ("") to apply the default behavior. |
| `obj_force_elevation`            | `ANYRUN_OBJ_FORCE_ELEVATION`                | No       | Forces the file to execute with elevated privileges and an elevated token (for PE32, PE32+, PE64 files only). |                     
| `obj_ext_browser`             | `ANYRUN_OBJ_EXT_BROWSER`                 | No       | Browser name. Supports: Google Chrome, Mozilla Firefox, Internet Explorer, Microsoft Edge.                    |


#### ANY.RUN Linux environment preferences
| Parameter                    | Docker envvar                    | Mandatory | Description                                             |
|------------------------------|----------------------------------|-----------|---------------------------------------------------------|
|`os_type`                      | `ANYRUN_OS_TYPE`                 | Yes       | Must be `linux`| 
| `obj_ext_startfolder`             | `ANYRUN_OBJ_EXT_STARTFOLDER`                 | No        | Start object from. Supports: desktop, home, downloads, temp.                                       |
| `obj_ext_cmd`             | `ANYRUN_OBJ_EXT_CMD`                 | No       | Optional command-line arguments for the analyzed object. Use an empty string ("") to apply the default behavior. |
| `run_as_root`            | `ANYRUN_RUN_AS_ROOT`                | No       | Run file with superuser privileges.                     |                     
| `obj_ext_browser`             | `ANYRUN_OBJ_EXT_BROWSER`                 | No       | Browser name. Supports: Google Chrome, Mozilla Firefox. |


#### ANY.RUN Android environment preferences
| Parameter                    | Docker envvar                    | Mandatory | Description                                                                                                  |
|------------------------------|----------------------------------|-----------|--------------------------------------------------------------------------------------------------------------|
|`os_type`                      | `ANYRUN_OS_TYPE`                 | Yes       | Must be `android`| 
| `obj_ext_cmd`             | `ANYRUN_OBJ_EXT_CMD`                 | No       | Optional command-line arguments for the analyzed object. Use an empty string ("") to apply the default behavior. |

## Deployment

### Docker Deployment

Build the Docker image:

```bash
docker build -t opencti/connector-anyrun-task:latest .
```

Configure the connector in `docker-compose.yml`:

```yaml
connector-anyrun-task:
  image: anyrun/opencti-connector-anyrun-task:latest
  environment:
    # OpenCTI settings.
    - OPENCTI_URL=http://localhost # The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080`
    - OPENCTI_TOKEN=ChangeMe # The default admin token configured in the OpenCTI platform parameters file.

    # Connector settings.
    - CONNECTOR_ID=ChangeMe # A valid arbitrary `UUIDv4` that must be unique for this connector.
    - CONNECTOR_TYPE=INTERNAL_ENRICHMENT # A connector type.
    - CONNECTOR_NAME=ANY.RUN Sandbox # A connector name to be shown in OpenCTI.
    - CONNECTOR_SCOPE=StixFile,Url # Supported scope. E. g., `text/html`.
    - CONNECTOR_AUTO=false # Enable/disable auto-enrichment of observables.
    - CONNECTOR_CONFIDENCE_LEVEL=75 # From 0 (Unknown) to 100 (Fully trusted)
    - CONNECTOR_LOG_LEVEL=info # The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).
  
    # ANY.RUN base settings.
    - ANYRUN_API_KEY=ChangeMe # ANY.RUN Sandbox API-KEY. See "Generate API token" section in the README file.
    - ANYRUN_ENABLE_IOC=true # Add found indicators to the OpenCTI Indicators and Observables tab.

    # ANY.RUN analysis options.
    - ANYRUN_OPT_TIMEOUT=240 # Select analysis completion time. Size range: 10-660 seconds.
    - ANYRUN_OPT_NETWORK_CONNECT=true # Enable network connection.
    - ANYRUN_OPT_NETWORK_FAKENET=false # Enable FakeNet feature.
    - ANYRUN_TOR=false # Enable TOR using.
    - ANYRUN_GEO=fastest # TOR geolocation option. Example: US, AU
    - ANYRUN_MITM=false # Enable HTTPS MITM Proxy using.
    - ANYRUN_RESIDENTIAL_PROXY=false # Residential proxy using.
    - ANYRUN_RESIDENTIAL_PROXY_GEO=fastest # Residential proxy geolocation option. Example: US, AU.
    - ANYRUN_PRIVACY_TYPE=bylink # Privacy settings. Supports: public, bylink, owner, byteam.

    # ANY.RUN analysis object settings.
    - ANYRUN_OBJ_EXT_EXTENSION=true # Automatically change file extension to valid.

    # ANY.RUN analysis environment settings.
    - ANYRUN_ENV_LOCALE=en-US # Operation system's language. Use locale identifier or country name (Ex: "en-US" or "Brazil"). Case-insensitive.

    # Please use one of the following environments in the same time:

    # Windows analysis environment.
    - ANYRUN_OS_TYPE=windows # Type of OS. Must be windows
    - ANYRUN_ENV_VERSION=10 # Version of OS. Supports: 7, 10, 11
    - ANYRUN_ENV_BITNESS=64 # Bitness of Operation System. Supports 32, 64.
    - ANYRUN_ENV_TYPE=complete # Environment preset type. You can select **development** env for OS Windows 10 x64. For all other cases, **complete** env is required.
    - ANYRUN_OBJ_EXT_STARTFOLDER=temp # Supports: desktop, home, downloads, appdata, temp, windows, root.
    - ANYRUN_OBJ_EXT_CMD="" # Optional command-line arguments for the analyzed object. Use an empty string ("") to apply the default behavior.
    - ANYRUN_OBJ_FORCE_ELEVATION=false # Forces the file to execute with elevated privileges and an elevated token (for PE32, PE32+, PE64 file  s only).
    # Only for the Url analysis.
    # - ANYRUN_OBJ_EXT_BROWSER=Microsoft Edge # Browser name. Supports: Google Chrome, Mozilla Firefox, Internet Explorer, Microsoft Edge.

    # Linux analysis environment.
    # - ANYRUN_OS_TYPE=linux # Type of OS. Must be linux
    # - ANYRUN_OBJ_EXT_STARTFOLDER=temp # Start object from. Supports: desktop, home, downloads, appdata, temp, windows, root.
    # - ANYRUN_OBJ_EXT_CMD="" # Optional command-line arguments for the analyzed object. Use an empty string ("") to apply the default behavior.
    # - ANYRUN_RUN_AS_ROOT=true # Run file with superuser privileges.
    # Only for the Url analysis.
    # - ANYRUN_OBJ_EXT_BROWSER=Google Chrome # Browser name. Supports: Google Chrome, Mozilla Firefox.

    # Android analysis environment.
    # - ANYRUN_OS_TYPE=android # Type of OS. Must be android
    # - ANYRUN_OBJ_EXT_CMD="" # Optional command-line arguments for the analyzed object. Use an empty string ("") to apply the default behavior.
  restart: always
```

Start the connector:

```bash
docker compose up -d
```

### Manual Deployment

1. Copy and configure `config.yml` from the provided `config.yml.sample`.

2. Install dependencies:

```bash
pip3 install -r requirements.txt
```

3. Start the connector from the `src` directory:

```bash
python3 opencti_client.py
```

## Usage

The connector enriches URL and StixFile observables by submitting them to the ANY.RUN sandbox. Due to the time required for sandbox analysis, automatic mode is typically disabled.

**Observations → Observables**

Select a URL or StixFile observable, then click the enrichment button and choose ANY.RUN Task.

## Behavior

The connector submits observables to ANY.RUN for sandbox analysis and imports the results back into OpenCTI.

### Data Flow

```mermaid
graph LR
    subgraph OpenCTI Input
        URL[URL Observable]
        StixFile[StixFile Observable]
    end

    subgraph ANY.RUN Sandbox
        Task[Sandbox Analysis]
        Analysis[Behavioral Analysis]
    end

    subgraph OpenCTI Output
        EnrichedObs[Enriched Observable]
        Labels[Tags/Labels]
        ExtRef[External Reference]
        IOCs[IOC Observables]
        Indicators[Indicators]
        Note[Score Note]
        HTML[HTML report]
    end

    URL --> Task
    StixFile --> Task
    Task --> Analysis
    Analysis --> EnrichedObs
    Analysis --> Labels
    Analysis --> ExtRef
    Analysis --> IOCs
    Analysis --> Indicators
    Analysis --> Note
    Analysis --> HTML report
```

### Enrichment Mapping

| ANY.RUN Data         | OpenCTI Entity/Property | Description                       |
|----------------------|-------------------------|-----------------------------------|
| Task URL             | External Reference      | Link to the ANY.RUN analysis page |
| analysis.tags        | Labels                  | Tags assigned by ANY.RUN analysts |
| scores.verdict.score | Observable Score        | Threat verdict score from analysis |
| IOCs (domain)        | Domain-Name Observable  | Extracted domain IOCs with indicators |
| IOCs (url)           | URL Observable          | Extracted URL IOCs with indicators |
| IOCs (ip)            | IPv4-Addr Observable    | Extracted IP IOCs with indicators |
| IOCs (sha256)        | File Observable         | Extracted File IOCs with indicators 

### IOC Types Mapping

| ANY.RUN IOC Type | OpenCTI Observable Type |
|----------------|-------------------------|
| domain         | Domain-Name             |
| url            | Url                     |
| ip             | IPv4-Addr               |
| sha256         | File                    |


### Processing Details

1. **Analysis Submission**: Submits URL or StixFile to ANY.RUN with configured sandbox settings
2. **External Reference**: Creates link to the ANY.RUN analysis page
3. **Wait for Analysis**: Polls analysis status until completion (with timeout)
4. **Tags/Labels**: Imports analysis tags as labels on the observable
5. **Score Update**: Updates observable score with verdict score (or creates note if lower)
6. **IOCs**: Creates observables and indicators for malicious and suspiocus IOCs found during analysis

### Generated STIX Objects

| STIX Object Type      | Condition              | Description                                      |
|-----------------------|------------------------|--------------------------------------------------|
| External Reference    | Always                 | Link to ANY.RUN analysis                     |
| Labels                | When tags present      | Analysis tags applied to observable              |
| Note                  | When score is lower    | Records ANY.RUN score when lower than existing   |
| Domain-Name           | IOC enabled            | Extracted malicious domains                      |
| URL                   | IOC enabled            | Extracted malicious URLs                         |
| IPv4-Addr             | IOC enabled            | Extracted malicious IP addresses                 |
| Indicator             | IOC enabled            | STIX patterns for extracted IOCs                 |
| Process               | Processes enabled      | Malicious process information                    |
| Relationship          | Various                | `related-to`, `based-on` linking entities together |

### Relationships Created

- Original Observable → `related-to` → Extracted IOC Observables
- Indicator → `based-on` →  Extracted IOC Observables

## Debugging

Enable verbose logging by setting:

```env
CONNECTOR_LOG_LEVEL=debug
```

Log output includes:
- Analysis submission details
- Analysis status polling
- IOC extraction progress
- Relationship creation status

## Additional information

- **Analysis Time**: Sandbox analysis typically takes 1-3 minutes depending on the sample
- **Task Timer**: Configure `ANYRUN_OPT_TIMEOUT` based on expected analysis time
- **Privacy Settings**: Use `bylink` or `team` for sensitive samples
- **API Access Required**: Available on ANY.RUN plans with API access, including trial
- **Rate Limits**: API calls are subject to ANY.RUN rate limits based on subscription tier
- **Organization Identity**: The connector creates an "ANY.RUN" organization identity for attribution

## Support
This is an ANY.RUN’s supported connector. You can write to us for help with integration via [techsupport@any.run](mailto:techsupport@any.run) .
Contact us for a quote or demo via [this form](https://app.any.run/contact-us/?utm_source=anyrungithub&utm_medium=documentation&utm_campaign=opencti_sandbox&utm_content=linktocontactus). 
