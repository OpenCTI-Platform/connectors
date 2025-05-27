# OpenCTI S3 Import connector

## Installation

### Configuration variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter `opencti` | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------------|------------|-----------------------------|-----------|------------------------------------------------------|
| URL                 | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| Token               | `token`    | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

Below are the parameters you'll need to set for running the connector properly:

| Parameter `connector`       | config.yml                    | Docker environment variable             | Default | Mandatory | Example                                | Description                                                                            |
|-----------------------------|-------------------------------|-----------------------------------------|---------|-----------|----------------------------------------|----------------------------------------------------------------------------------------|
| ID                          | `id`                          | `CONNECTOR_ID`                          | /       | Yes       | `fe418972-1b42-42c9-a665-91544c1a9939` | A unique `UUIDv4` identifier for this connector instance.                              |
| Name                        | `name`                        | `CONNECTOR_NAME`                        | /       | Yes       | `S3 Bucket`                            | Full name of the connector : `Microsoft Sentinel`.                                     |
| Log Level                   | `log_level`                   | `CONNECTOR_LOG_LEVEL`                   | `error` | No        | `error`                                | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

Below are the parameters you'll need to set for Sentinel Connector:

| Parameter `s3`    | config.yml          | Docker environment variable | Default        | Mandatory | Example        | Description                                      |
|-------------------|---------------------|-----------------------------|----------------|-----------|----------------|--------------------------------------------------|
| Region            | `region`            | `S3_REGION`                 | `us-east-1`    | No        | `us-east-1`    | S3 Region for Amazon                             |
| Endpoint URL      | `endpoint_url`      | `S3_ENDPOINT_URL`           | /              | No        | /              | S3 Endpoint                                      |
| Access Key ID     | `access_key_id`     | `S3_ACCESS_KEY_ID`          | /              | Yes       | /              | S3 Access Key ID                                 |
| Secret Access Key | `secret_access_key` | `S3_SECRET_ACCESS_KEY`      | /              | Yes       | /              | S3 Secret Access Key                             |
| Bucket name       | `bucket_name`       | `S3_BUCKET_NAME`            | /              | Yes       | /              | S3 Bucket Name                                   |
| Author            | `author`            | `S3_AUHOR`                  | /              | No        | /              | Put author (created by ref) if not exist in data |
| Marking           | `marking`           | `S3_MARKING`                | `TLP:GREEN`    | No        | `TLP:AMBER`    | Put marking if not exist in data                 |
| Interval          | `interval`          | `S3_INTERVAL`               | `5`            | No        | `5`            | Interval to pull files                           |