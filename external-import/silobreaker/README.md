# OpenCTI Silobreaker Connector

| Status           | Date       | Comment |
|------------------|------------|---------|
| Partner Verified | 2025-03-06 | -       |

This connector connects to the Silobreaker and gather all data from a given date.

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding these variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

## Known issues

When token or account is expired, requests will returns empty dict and you will have a log with the following error:

```shell
"No data found, please check your account activation and API key"
```

Please ensure that your account and token is well active.

## Rate limit

The rate limit is 500 requests per minute.
