# OpenCTI Silobreaker Connector

| Status            | Date       | Comment |
| ----------------- |------------| ------- |
| Filigran Verified | 2025-03-06 |    -    |

This connector connects to the Silobreaker and gather all data from a given date.

## Known issues

When token or account is expired, requests will returns empty dict and you will have a log with the following error:
```shell
"No data found, please check your account activation and API key"
```

Please ensure that your account and token is well active.

## Rate limit

The rate limit is 500 requests per minute.