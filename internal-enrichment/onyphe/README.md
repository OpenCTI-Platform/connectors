# OpenCTI ONYPHE Internal Enrichment Connector

## What is ONYPHE?

ONYPHE is a cyber threat intelligence and external attack surface monitoring platform that aggregates and enriches internet-wide data from open, commercial, and proprietary sources. It provides real-time and historical visibility into cyber exposure, threat indicators, and infrastructure intelligence via a powerful and flexible API.

ONYPHE enables analysts, red teams, and security operations teams to investigate and monitor a wide range of observables such as IP addresses, hostnames, domains, and certificates. Its core use cases span from threat enrichment to external attack surface management (ASM).

Key ONYPHE capabilities used by this connector include:

    Ctiscan: Provides high-level analytical summaries of activity and relationships for an observable — including the most common organizations, certificates, DNS domains, technologies, ports, and countries associated with it.

    Vulnscan: Supports ASM by identifying internet-facing systems with known vulnerabilities (CVEs), providing insight into exposed and potentially exploitable assets.

    Riskscan: Assesses internet-exposed assets for security misconfigurations and weak points, offering risk-based context to observables such as IPs or domains.

Through these data sources, ONYPHE enables deep context and pivoting across observables to reveal infrastructure, ownership, exposure, and threat correlations — making it an ideal enrichment backend for threat intelligence platforms like OpenCTI.

## What is scope for ONYPHE Connector ?

    Scope : 
      - Observables
        - IPv4,
        - IPv6,
        - x509-certificate,
        - hostname
        - text (selected analaytical pivots with labels describing the relevant fingerprint)
      - Indicator (pattern_type: stix)

## What does ONYPHE Connector do ?

This connector allows observables or indicators with a supported ‘stix’ pattern_type to be enriched. Other scopes are not currently supported but we welcome feature requests.

For an observable, it can be enriched with :

- Organisation + relationship
- DomainName + relationship
- HostName + relationship
- AutonomousSystem+ relationship
- X509Certificate + relationship
- Location (City & Country) + relationship
- Vulnerability + relationship
- Updating the observable enriched with a description, labels, external reference

For indicators, a note is created with a summary of key data points for the indicator value.

- Summary titles :
  - Global
  - Top 20 Organizations
  - Top 20 TLS Certificate Domains
  - Top 20 DNS Domains
  - Top 20 TCP Ports
  - Top 20 Application Protocols
  - Top 20 Autonomous Systems
  - Top 20 Countries
  - Top 20 Technologies

By default, the import_search_results environment variable is set to true, which means that for each enriched indicator, the connector will create stix cyber observables associated with that entity.

## Installation

### Requirements

- OpenCTI Platform >= 6.6.2

### Configuration variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter `OpenCTI` | config.yml  | Docker environment variable | Mandatory | Description                                          |
|---------------------|-------------|-----------------------------|-----------|------------------------------------------------------|
| URL                 | `url`       | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| Token               | `token`     | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter `Connector` | config.yml  | Docker environment variable  | Default | Mandatory  | Description                                                                             |
|-----------------------|-------------|------------------------------|---------|------------|-----------------------------------------------------------------------------------------|
| ID                    | `id`        | `CONNECTOR_ID`               | /       | Yes        | A unique `UUIDv4` identifier for this connector instance.                               |
| Name                  | `name`      | `CONNECTOR_NAME`             | ``      | Yes        | Full name of the connector : `ONYPHE`.                                                  |
| Scope                 | `scope`     | `CONNECTOR_SCOPE`            | /       | Yes        | Can be any of `ipv4-addr,ipv6-addr,indicator,hostname,x509-certificate,text`.           |
| Auto                  | `auto`      | `CONNECTOR_AUTO`             | False   | Yes        | Must be `true` or `false` to enable or disable auto-enrichment of observables.          |
| Log Level             | `log_level` | `CONNECTOR_LOG_LEVEL`        | /       | Yes        | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.  |

Below are the parameters you'll need to set for ONYPHE Connector:

| Parameter `onyphe`    | config.yml              | Docker environment variable    | Default     | Mandatory | Description                                                                                     |
|-----------------------|-------------------------|--------------------------------|-------------|-----------|-------------------------------------------------------------------------------------------------|
| api_key                 | `api_key`                 | `ONYPHE_API_KEY`                 | /           | Yes       | Your ONYPHE API Key ( available on profile page https://search.onyphe.io/profile)         |
| base_url                 | `base_url`                 | `ONYPHE_BASE_URL`                 | `https://www.onyphe.io/api/v2/`           | No       | The target ONYPHE API endpoint         |
| max_tlp               | `max_tlp`               | `ONYPHE_MAX_TLP`               | `TLP:AMBER` | No        | The maximal TLP of the observable being enriched.                                               |
| time_since               | `time_since`               | `ONYPHE_TIME_SINCE`               | `1w` | No        | The time range used for ONYPHE queries. Increase to match your license level                  |
| default_score         | `default_score`         | `ONYPHE_DEFAULT_SCORE`         | `50`        | No        | Default_score allows you to add a default score for an indicator and its observable             |
| text_pivots         | `text_pivots`         | `ONYPHE_TEXT_PIVOTS`         | `None`        | No        | CSV list. Text pivots filters text observables so that auto enrichment is limited to the list of defined labels |
| import_search_results | `import_search_results` | `ONYPHE_IMPORT_SEARCH_RESULTS` | `True`      | No        | Returns the observable results of the search against the enriched indicator. |
| create_note | `create_note` | `ONYPHE_CREATE_NOTE` | `False` | No        | Adds ONYPHE results to a note, otherwise it is saved in the description. |
| import_full_data | `import_full_data` | `ONYPHE_IMPORT_FULL_DATA` | `False` | No        | Full app.data.text field are imported from ONYPHE results for each enriched observable. |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.6.2`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from recorded-future/src:

```shell
python3 main.py
```

### Additional information

#### Warnings

- ⚠️ import_full_data = True : This setting could theoretically import 50MB per observable (max 100 ONYPHE results per enrichment, 500KB per result)
- ⚠️ text_pivots : Use with caution when the CONNECTOR_AUTO setting is set to True. Adding a widely used analytical pivot label here such as `ja4t-md5` could import thousands or millions of related observables.

Useful links

- ONYPHE Ctiscan data model : https://search.onyphe.io/docs/data-models/ctiscan
