# OpenCTI CrowdStrike Endpoint Security connector

The Crowdstrike Endpoint Security connector is a standalone Python process that monitors events from OpenCTI and executes related actions to create, update or delete a data in Crowdstrike.

Summary

- [OpenCTI CrowdStrike Endpoint Security connector](#opencti-crowdstrike-endpoint-security-connector)
  - [Introduction](#introduction)
  - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Crowdstrike Endpoint Security connector environment variables](#crowdstrike-endpoint-security-connector-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
    - [Search an IOC](#search-an-ioc)
      - [Specifications](#specifications)
      - [Method and API response](#method-and-api-response)
    - [Create an IOC](#create-an-ioc)
      - [Specifications](#specifications-1)
      - [Method and API response](#method-and-api-response-1)
    - [Update an IOC](#update-an-ioc)
      - [Specifications](#specifications-2)
      - [Method and API response](#method-and-api-response-2)
    - [Delete an IOC](#delete-an-ioc)
      - [Specifications](#specifications-3)
      - [Method and API response](#method-and-api-response-3)
  - [Known Issues and Workarounds](#known-issues-and-workarounds)
  - [Useful Resources](#useful-resources)

---

## Introduction

## Requirements

To use the connector, you need to have a Recorded Future account.

- OpenCTI Platform version 5.0.0 or higher
- An API Key for accessing

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
| ------------- | ---------- | --------------------------- | --------- | ---------------------------------------------------- |
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |


### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter                             | config.yml                  | Docker environment variable             | Default                           | Mandatory | Description                                                                                                                                            |
| ------------------------------------- | --------------------------- | --------------------------------------- | --------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Connector ID                          | id                          | `CONNECTOR_ID`                          | /                                 | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                              |
| Connector Type                        | type                        | `CONNECTOR_TYPE`                        | EXTERNAL_IMPORT                   | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                                                                                          |
| Connector Name                        | name                        | `CONNECTOR_NAME`                        | CrowdStrike Endpoint Security     | Yes       | Name of the connector.                                                                                                                                 |
| Connector Scope                       | scope                       | `CONNECTOR_SCOPE`                       | crowdstrike                       | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. Here it is a reserved scope for stream.                       |
| Log Level                             | log_level                   | `CONNECTOR_LOG_LEVEL`                   | info                              | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                                 |
| Connector Live Stream ID              | live_stream_id              | `CONNECTOR_LIVE_STREAM_ID`              | /                                 | Yes       | ID of the live stream created in the OpenCTI UI                                                                                                        |
| Connector Live Stream Listen Delete   | live_stream_listen_delete   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | true                              | Yes       | Listen to all delete events concerning the entity, depending on the filter set for the OpenCTI stream.                                                 |
| Connector Live Stream No dependencies | live_stream_no_dependencies | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | true                              | Yes       | Always set to `True` unless you are synchronizing 2 OpenCTI platforms and you want to get an entity and all context (relationships and related entity) |
| Consumer Count                        | consumer_count              | `CONNECTOR_CONSUMER_COUNT`              | 10                                | No        | Number of consumers/workers used to push data                                                                                                          |
| Ignore Types                          | ignore_types                | `CONNECTOR_IGNORE_TYPES`                | label,marking-definition,identity | No        | Ignoring types from OpenCTI                                                                                                                            |

### Crowdstrike Endpoint Security connector environment variables

Below are the parameters you'll need to set for Crowdstrike Endpoint Security connector:


| Parameter | config.yml                 | Docker environment variable            | Default | Mandatory | Description                                                                                                                                                                     |
| --------- | -------------------------- | -------------------------------------- | ------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|           | `api_base_url`             | `CROWDSTRIKE_API_BASE_URL`             | /       | Yes       | Crowdstrike base url.                                                                                                                                                           |
|           | `client_id`                | `CROWDSTRIKE_CLIENT_ID`                | /       | Yes       | Crowdstrike client ID used to connect to the API.                                                                                                                               |
|           | `client_secret`            | `CROWDSTRIKE_CLIENT_SECRET`            | /       | Yes       | Crowdstrike client secret used to connect to the API.                                                                                                                           |
|           | `permanent_delete`         | `CROWDSTRIKE_PERMANENT_DELETE`         | False   | Yes       | Select whether or not to permanently delete data in Crowdstrike when data is deleted in OpenCTI. If set to `True`, `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` must be set to `True`⚠️ |
|           | `falcon_for_mobile_active` | `CROWDSTRIKE_FALCON_FOR_MOBILE_ACTIVE` | False   | Yes       | Crowdstrike client secret used to connect to the API.                                                                                                                           |
|           | `enable`                   | `METRICS_ENABLE`                       | False   | No        | Whether or not Prometheus metrics should be enabled.                                                                                                                            |
|           | `addr`                     | `METRICS_ADDR`                         | /       | No        | Bind IP address to use for metrics endpoint.                                                                                                                                    |
|           | `port`                     | `METRICS_PORT`                         | /       | No        | Port to use for metrics endpoint.                                                                                                                                               |


## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever version of OpenCTI you're running. Example, `pycti==5.12.20`. If you don't, it will take the latest version, but sometimes the OpenCTI SDK fails to initialize.

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

Then, start the connector from crowdstrike-endpoint-security/src:

```shell
python3 main.py
```

## Usage

## Behavior

### Search an IOC

#### Specifications

#### Method and API response

**indicator_search method behavior**

Indicator does not exists:

```python
cs.indicator_search(filter=f'value:"doesnotexists.local"+created_by:"{client_id}"')

# API Crowdstrike response
{
    "status_code": 200,
    "headers": {
        "Server": "nginx",
        "Date": "Wed, 20 Dec 2023 15:13:08 GMT",
        "Content-Type": "application/json",
        "Content-Length": "199",
        "Connection": "keep-alive",
        "Content-Encoding": "gzip",
        "Strict-Transport-Security": "max-age=15724800; includeSubDomains, max-age=31536000; includeSubDomains",
        "X-Cs-Region": "eu-1",
        "X-Cs-Traceid": "61003bcd-xxxx-436a-939e-0d74bb9570c6",
        "X-Ratelimit-Limit": "6000",
        "X-Ratelimit-Remaining": "5997",
    },
    "body": {
        "meta": {
            "query_time": 0.013197571,
            "pagination": {"limit": 100, "total": 0, "offset": 0},
            "powered_by": "ioc-manager",
            "trace_id": "61003bcd-a5f3-436a-939e-0d74bb9570c6",
        },
        "resources": [],
        "errors": [],
    },
}
```

Indicator exists:

```python
cs.indicator_search(filter=f'value:"itexists.local"+created_by:"{client_id}"')

# API Crowdstrike response
{
    "status_code": 200,
    "headers": {
        "Server": "nginx",
        "Date": "Wed, 20 Dec 2023 15:18:34 GMT",
        "Content-Type": "application/json",
        "Content-Length": "366",
        "Connection": "keep-alive",
        "Content-Encoding": "gzip",
        "Strict-Transport-Security": "max-age=15724800; includeSubDomains, max-age=31536000; includeSubDomains",
        "X-Cs-Region": "eu-1",
        "X-Cs-Traceid": "ac585ad4-xxxx-4cee-9913-6e1edbd4e339",
        "X-Ratelimit-Limit": "6000",
        "X-Ratelimit-Remaining": "5995",
    },
    "body": {
        "meta": {
            "query_time": 0.083197836,
            "pagination": {
                "limit": 100,
                "total": 1,
                "offset": 1,
                "after": "WzE2OTI5NTQ...==",
            },
            "powered_by": "ioc-manager",
            "trace_id": "ac585ad4-xxxx-4cee-9913-6e1edbd4e339",
        },
        "resources": [
            "b595be8339d106fb9fd84366133e4bac557efbf8f5ca7f7a11b6e2524a57bf2d"
        ],
        "errors": [],
    },
}
```

### Create an IOC

#### Specifications

#### Method and API response

**indicator_create method behavior**

```python
cs.indicator_create(
    body={
        "comment": "OpenCTI IOC",
        "indicators": [
            {
                "source": "OpenCTI IOC",
                "applied_globally": True,
                "type": "domain",
                "value": "test.aztyop.local",
                "platforms": [
                    "windows",
                    "mac",
                    "linux",
                ],
            }
        ],
    }
)

# API Crowdstrike response
{
    "status_code": 201,
    "headers": {
        "Server": "nginx",
        "Date": "Wed, 20 Dec 2023 15:23:16 GMT",
        "Content-Type": "application/json",
        "Content-Length": "476",
        "Connection": "keep-alive",
        "Content-Encoding": "gzip",
        "Strict-Transport-Security": "max-age=15724800; includeSubDomains, max-age=31536000; includeSubDomains",
        "X-Cs-Region": "eu-1",
        "X-Cs-Traceid": "e3af1a02-xxxx-462a-8acd-b4f817252944",
        "X-Ratelimit-Limit": "6000",
        "X-Ratelimit-Remaining": "5995",
    },
    "body": {
        "meta": {
            "query_time": 0.335613776,
            "pagination": {"limit": 0, "total": 1},
            "powered_by": "ioc-manager",
            "trace_id": "e3af1a02-xxxx-462a-8acd-b4f817252944",
        },
        "resources": [
            {
                "id": "8de59b570d3fb6aecb0e872cc2dece513aa3f121e94be2803423372eef2023a5",
                "type": "domain",
                "value": "test.aztyop.local",
                "source": "OpenCTI IOC",
                "action": "no_action",
                "mobile_action": "no_action",
                "severity": "",
                "platforms": ["windows", "mac", "linux"],
                "expired": False,
                "deleted": False,
                "applied_globally": True,
                "from_parent": False,
                "created_on": "2023-12-20T15:23:16.135988021Z",
                "created_by": "ed578da6b8d84d1e9312e833e493773a",
                "modified_on": "2023-12-20T15:23:16.135988021Z",
                "modified_by": "ed578da6b8d84d1e9312e833e493773a",
            }
        ],
        "errors": [],
    },
}
```


### Update an IOC

#### Specifications

#### Method and API response

### Delete an IOC

#### Specifications

#### Method and API response


## Known Issues and Workarounds

---

## Useful Resources

OpenCTI documentation for connectors:

- [OpenCTI Ecosystem](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76)
- [Connectors Deployment](https://docs.opencti.io/latest/deployment/connectors/)
- [Connectors Development](https://docs.opencti.io/latest/development/connectors/)

You will find IOC on the web UI:
- [falcon.eu-1.crowdstrike.com/iocs/indicators](https://falcon.eu-1.crowdstrike.com/iocs/indicators).

Documentation references:
- [Crowdstrike OAuth2 API](https://falcon.eu-1.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis)
- [Swagger API spec](https://assets.falcon.eu-1.crowdstrike.com/support/api/swagger-eu.html)
- [crowdstrike-falconpy - Python SDK](https://pypi.org/project/crowdstrike-falconpy/)
