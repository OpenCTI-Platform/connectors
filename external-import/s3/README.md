# OpenCTI S3 Import connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

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
| Name                        | `name`                        | `CONNECTOR_NAME`                        | /       | Yes       | `S3 Bucket`                            | Full name of the connector : `S3`.                                                     |
| Log Level                   | `log_level`                   | `CONNECTOR_LOG_LEVEL`                   | `error` | No        | `error`                                | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`. |

Below are the parameters you'll need to set for s3 Connector:

| Parameter `s3`       | config.yml             | Docker environment variable | Default             | Mandatory | Example        | Description                                                        |
|----------------------|------------------------|-----------------------------|---------------------|-----------|----------------|--------------------------------------------------------------------|
| Region               | `region`               | `S3_REGION`                 | `us-east-1`         | No        | `us-east-1`    | S3 Region for Amazon                                               |
| Endpoint URL         | `endpoint_url`         | `S3_ENDPOINT_URL`           | /                   | No        | /              | S3 Endpoint                                                        |
| Access Key ID        | `access_key_id`        | `S3_ACCESS_KEY_ID`          | /                   | Yes       | /              | S3 Access Key ID                                                   |
| Secret Access Key    | `secret_access_key`    | `S3_SECRET_ACCESS_KEY`      | /                   | Yes       | /              | S3 Secret Access Key                                               |
| Bucket name          | `bucket_name`          | `S3_BUCKET_NAME`            | /                   | Yes       | /              | S3 Bucket Name                                                     |
| Bucket prefixes      | `bucket_prefixes`      | `S3_BUCKET_PREFIXES`        | `ACI_TI,ACI_Vuln`   | No        | /              | S3 Bucket Prefixes to process                                      |
| Author               | `author`               | `S3_AUTHOR`                 | /                   | No        | /              | Put author (created by ref) if not exist in data                   |
| Marking              | `marking`              | `S3_MARKING`                | `TLP:GREEN`         | No        | `TLP:AMBER`    | Put marking if not exist in data                                   |
| Interval             | `interval`             | `S3_INTERVAL`               | `30`                | No        | `30`           | Interval to poll S3 bucket (in seconds)                            |
| Attach Original File | `attach_original_file` | `S3_ATTACH_ORIGINAL_FILE`   | `false`             | No        | `true`         | Attach the original JSON file to vulnerabilities                   |
| Delete After Import  | `delete_after_import`  | `S3_DELETE_AFTER_IMPORT`    | `true`              | No        | `false`        | Delete files from S3 after processing (set to false for debugging) |
| No split bundles     | `no_split_bundles`     | `S3_NO_SPLIT_BUNDLES`       | `true`              | No        | `false`        | No split bundle                                                    |

## Behavior

### Processing Strategy

The connector uses a **fail-fast** strategy:

1. **List** all files in the S3 bucket with the configured prefix(es)
2. For each file:
   - **Fetch** the STIX bundle from S3
   - **Parse and validate** the bundle
   - **Send** to OpenCTI
   - **Delete** the file from S3 only after successful processing
3. If **any error occurs** at any step, the connector **crashes immediately**

### Multi-Platform Setup

For multi-platform deployments (multiple OpenCTI instances consuming from S3):

- **Use one dedicated bucket per connector/platform** to avoid race conditions
- Each connector processes and deletes files from its own bucket
- This ensures no data is lost due to concurrent access

### Error Handling

- If file fetching fails → connector crashes → file remains in S3
- If bundle parsing fails → connector crashes → file remains in S3
- If OpenCTI ingestion fails → connector crashes → file remains in S3
- If deletion fails → connector crashes → prevents inconsistent state

This design ensures your platform team is immediately alerted when issues occur, and no data is ever silently lost.

### Original File Attachment

When `S3_ATTACH_ORIGINAL_FILE=true`, the connector will attach the original JSON file from S3 to each vulnerability entity in OpenCTI. This is useful for:

- **Audit trails**: Keep the original source data alongside the processed vulnerability
- **Debugging**: Easily access the raw data that created a vulnerability
- **Compliance**: Maintain original evidence files

The file will be visible in the "Data" tab of each vulnerability in the OpenCTI UI.
