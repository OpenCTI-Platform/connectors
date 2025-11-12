# OpenCTI Cuckoo Sandbox Connector

## Description
This is a connector for syncing Cuckoo snadbox analysis as reports and IOCs [OpenCTI](https://github.com/OpenCTI-Platform/opencti).

## Configuration
There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment). Since the `opencti` and `connector` options are the same as any other Connector, I'm only going to address the `cuckoo` options

| Docker Env variable           | config variable          | Description
| ------------------------------|--------------------------|------------
| CUCKOO_API_URL                | api_url                  | The Cuckoo API server's Endpoint
| CUCKOO_BASE_URL               | base_url                 | The Sandbox's web address
| CUCKOO_INTERVAL               | interval                 | How oftern to poll for new jobs
| CUCKOO_CREATE_INDICATORS      | create_indicators        | Create Indicators for Observeables
| CUCKOO_ENABLE_REGISTRY_KEYS   | enable_registry_keys     | Create Registy Observeables for created registry keys
| CUCKOO_ENABLE_NETWORK_TRAFFIC | enable_network_traffic   | Create NetworkTraffic Observeables
| CUCKOO_START_TASK_ID          | start_task_id            | First Cuckoo Task ID to Sync From
| CUCKOO_REPORT_SCORE           | report_score             | Create a report for any score above this
| VERIFY_SSL                    | verify_ssl               | Boolean statement on whether to require an SSL/TLS connection with the Cuckoo API Server. Default to True

