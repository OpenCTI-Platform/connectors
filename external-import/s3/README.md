# OpenCTI S3 Import connector

| Status | Date | Comment |
|--------|------|---------|
| Community | -    | -       |

## Installation

## Configuration variables

Find all the configuration variables available here: [Connector Configurations](./__metadata__/CONNECTOR_CONFIG_DOC.md)

_The `opencti` and `connector` options in the `docker-compose.yml` and `config.yml` are the same as for any other connector.
For more information regarding variables, please refer to [OpenCTI's documentation on connectors](https://docs.opencti.io/latest/deployment/connectors/)._

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
