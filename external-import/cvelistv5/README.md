# CVE Project Listv5 connector
An alternative connector for the CVE Connector wich fetches updates from NVD. 
This connector fetches updates from The CVE Project's github repo: [cvelistV5](https://github.com/CVEProject/cvelistV5).

## Summary

- [Introduction](#introduction)
- [Requirements](#requirements)
- [Configuration variables](#configuration-variables)
- [Deployment](#deployment)
  - [Docker Deployment](#docker-deployment)
  - [Manual Deployment](#manual-deployment)
- [Behavior](#behavior)
  - [Initial population](#initial-population)
  - [Pull CVEs updates](#pull-cves-updates)
  - [Maintaining data](#maintaining-data)
  - [Errors](#errors)
- [Usage](#usage)
- [Sources](#sources)

---

### Introduction

CVE are fetched from the CVE Project Github list: https://github.com/CVEProject/cvelistV5

CVEs follows a specific [schema](https://github.com/CVEProject/cve-schema/tree/main) which then is transformed into stix format.
Since not everything can be matched to the stix v2.x format, extra information are added as notes related to the vulnerability.

Extra infromation includes:
- Explanation of **Workarounds**
- Explanation of **Solutions**
- **Configurations** that make the vulnerability more severe
- Notes on detected **Exploits**


### Requirements

- OpenCTI Platform version 5.12.0 or higher


### Configuration variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter            | config.yml           | Docker environment variable      | Default                              | Mandatory | Description                                                                                                                                 |
|----------------------|----------------------|----------------------------------|--------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------|
| Connector ID         | id                   | `CONNECTOR_ID`                   | /                                    | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                   |
| Connector Name       | name                 | `CONNECTOR_NAME`                 | Common Vulnerabilities and Exposures | Yes       | Name of the connector.                                                                                                                      |
| Connector Scope      | scope                | `CONNECTOR_SCOPE`                | identity,vulnerability               | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object.                                                    |
| Run and Terminate    | run_and_terminate    | `CONNECTOR_RUN_AND_TERMINATE`    | False                                | No        | Launch the connector once if set to True. Takes 2 available values: `True` or `False`                                                       |
| Log Level            | log_level            | `CONNECTOR_LOG_LEVEL`            | info                                 | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                      |

Below are the parameters you'll need to set for the connector:

| Parameter              | config.yml         | Docker environment variable | Default                                      | Mandatory | Description                                                                                                                                                         |
|------------------------|--------------------|-----------------------------|----------------------------------------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| CVE Interval           | interval           | `CVE_INTERVAL`              | 10                                           | Yes       | Interval in minutes to check and import new CVEs.                                                   |
| CVE Maintain Data      | maintain_data      | `CVE_MAINTAIN_DATA`         | True                                         | No       | If set to `True`, import CVEs from the last run of the connector to the current time. Takes 2 values: `True` or `False`. NOT IMPLENTED YET                                           |
| CVE Pull History       | pull_history       | `CVE_PULL_HISTORY`          | True                                        | No        | If set to `True`, import all CVEs from start year define in history start year configuration and history start year is required. Takes 2 values: `True` or `False`. NOT IMPLEMENTED YET |
| CVE History Start Year | history_start_year | `CVE_HISTORY_START_YEAR`    | 2025                                         | No        | Year in number. Required when pull_history is set to `True`.  Minimum 2019 as CVSS V3.1 was released in June 2019, thus most CVE published before 2019 do not include the cvssMetricV31 object.                                                                                      |


### Deployment

#### Docker Deployment

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
docker build . -t opencti-cve-import:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

#### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Or if you have Make installed, in cve/src:

```shell
# Will install the requirements
make init
```

Then, start the connector from cve/src:

```shell
python3 main.py
```

### Behavior

#### Initial population

For the first run of the connector, the connector will clone the the github repo *cvelistv5* by CVEProject. 
Using the start_year it will start transforming the CVEs into stix format and push it to OpenCTI.

#### Pull CVEs updates

After the first run the connector will pause for the specified *interval* amount. And the next time it will fetch updates from the github repository, and using the commit log it will imported new and updated cve records.

#### Maintaining data

By default, `maintain_data` will be set to `True` to keep data updated. (NOT IMPLEMENTED - Changing this does not make a difference)

The connector will import the last CVEs added or modified, and the new metadata related to the record.

- [ ] Missing feature: Handle vulnerability relationship to software wich is inside the affected version range.

#### Errors

*Troubloshooting information will be added here as soon as error pops up.*

### Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at the interval specified in your `docker-compose.yml` or `config.yml`.

However, if you would like to force an immediate poll of the CVE instance, navigate to _Data_ -> _Connectors_ in the
OpenCTI platform.
Find the connector, and click on the refresh button to reset the connector's state and force a new poll of the CVEs.

The connector was build to support viewing organizations with vulnerable software. To accomplish that the organization need to have a relationship with a software object that has a specified version.


### Sources

- [The CVE Project](https://github.com/CVEProject/cvelistV5)
- [CVE Connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/cve)
- [CISA KEV Connector](https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/cisa-known-exploited-vulnerabilities)