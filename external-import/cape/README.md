# OpenCTI CAPE Sandbox Connector

## Description
This is a connector for syncing CAPE sandbox analysis as reports and IOCs [OpenCTI](https://github.com/OpenCTI-Platform/opencti).

## Configuration
There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment). Since the `opencti` and `connector` options are the same as any other Connector, I'm only going to address the `CAPE` options

| Docker Env variable           | config variable          | Description
| ------------------------------|--------------------------|------------
| CAPE_API_URL                | api_url                  | The CAPE API server's Endpoint
| CAPE_BASE_URL               | base_url                 | The Sandbox's web address
| CAPE_INTERVAL               | interval                 | How oftern to poll for new jobs
| CAPE_CREATE_INDICATORS      | create_indicators        | Create Indicators for Observeables
| CAPE_ENABLE_REGISTRY_KEYS   | enable_registry_keys     | Create Registy Observeables for created registry keys
| CAPE_ENABLE_NETWORK_TRAFFIC | enable_network_traffic   | Create NetworkTraffic Observeables
| CAPE_START_TASK_ID          | start_task_id            | First CAPE Task ID to Sync From
| CAPE_REPORT_SCORE           | report_score             | Create a report for any score above this
| VERIFY_SSL                    | verify_ssl               | Boolean statement on whether to require an SSL/TLS connection with the CAPE API Server. Default to True

