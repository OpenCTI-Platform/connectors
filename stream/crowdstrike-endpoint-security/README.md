# OpenCTI CrowdStrike Endpoint Security connector

This connector allows to push IOC from OpenCTI to CrowdStrike Endpoint Security.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0

### Configuration

| Parameter                              | Docker envvar                          | Mandatory    | Description                                                                                   |
| -------------------------------------- | -------------------------------------- | ------------ |-----------------------------------------------------------------------------------------------|
| `opencti_url`                          | `OPENCTI_URL`                          | Yes          | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                        | `OPENCTI_TOKEN`                        | Yes          | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                         | `CONNECTOR_ID`                         | Yes          | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_name`                       | `CONNECTOR_NAME`                       | Yes          | Connector name.       |
| `connector_scope`                      | `CONNECTOR_SCOPE`                      | Yes          | Must be `crowdstrike`, not used in this connector.                                            |
| `connector_confidence_level`           | `CONNECTOR_CONFIDENCE_LEVEL`           | Yes          | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`                  | `CONNECTOR_LOG_LEVEL`                  | Yes          | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `connector_consumer_count`             | `CONNECTOR_CONSUMER_COUNT`             | No           | Number of consumer/worker that will push data.                                      |
| `connector_live_stream_start_timestamp`| `CONNECTOR_LIVE_STREAM_START_TIMESTAMP`| No           | Start timestamp used on connector first start.                                                |
| `crowdstrike_client_id`                | `CROWDSTRIKE_CLIENT_ID`                | Yes          | Crowdstrike client ID used to connect to the API.                                             |
| `crowdstrike_client_secret`            | `CROWDSTRIKE_CLIENT_SECRET`            | Yes          | Crowdstrike client secret used to connect to the API.                                         |
| `metrics_enable`                       | `METRICS_ENABLE`                       | No           | Whether or not Prometheus metrics should be enabled.                                          |
| `metrics_addr`                         | `METRICS_ADDR`                         | No           | Bind IP address to use for metrics endpoint.                                                  |
| `metrics_port`                         | `METRICS_PORT`                         | No           | Port to use for metrics endpoint.                                                             |

## Useful dev information

You will find IOC on the web UI at [falcon.eu-1.crowdstrike.com/iocs/indicators](https://falcon.eu-1.crowdstrike.com/iocs/indicators).

Documentation references:
- [Crowdstrike OAuth2 API](https://falcon.eu-1.crowdstrike.com/documentation/page/a2a7fc0e/crowdstrike-oauth2-based-apis)
- [Swagger API spec](https://assets.falcon.eu-1.crowdstrike.com/support/api/swagger-eu.html)
- [crowdstrike-falconpy - Python SDK](https://pypi.org/project/crowdstrike-falconpy/)

**CrowdstrikeIOC.indicator_search behavior**

Indicator does not exists:

```python
cs.indicator_search(filter=f'value:"doesnotexists.local"+created_by:"{client_id}"')
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

**CrowdstrikeIOC.indicator_create behavior**

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
