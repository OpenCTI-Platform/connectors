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

1. **Wait** until the ingestion works sent by the previous run are complete
2. **List** the files of each configured prefix, **oldest upload first**, at most 1,000 files per prefix and per run. Since processed files are deleted (`S3_DELETE_AFTER_IMPORT=true`, the default), the next runs take the rest of the backlog; with `S3_DELETE_AFTER_IMPORT=false` (debug) the same 1,000 oldest files are processed again on every run and the others are never reached
3. **Fetch and parse** these files
4. **Resolve versions** across all the files of the run (see below) and **build** every bundle before the first one is sent
5. For each file:
   - **Send** its bundle to OpenCTI
   - **Delete** the file from S3 only after successful processing
6. If **any error occurs** at any step, the connector **crashes immediately**

### Versioning

The same entity, typically a vulnerability, can be published several times in a short window. OpenCTI workers apply bundles in parallel, and an upsert of equal confidence overwrites the fields of an entity whatever its `modified` date. The connector therefore makes sure that the newest version of an entity always wins:

- **Within a run**: all the versions of an entity found in the files of the run are merged, and every bundle that contains the entity carries the result. Single-valued fields come from the newest version (highest `modified`), multi-valued fields (labels, external references, aliases, history entries) keep the values of all versions, as OpenCTI does when the versions are applied in order; the source fields that the connector turns into labels and aliases (`x_zero_day`, `x_wormable`, `x_notable_vuln`, `x_and_prior_versions`, `x_alias`) follow the same rule, so a label or an alias of an older version is kept. The ID and the references of each copy (author, markings, object references) stay those of its own file, so every reference still resolves within its bundle. Whatever order the bundles are applied in, the entity ends up with its newest content.
- **Against the platform**: a vulnerability whose `modified` date is older than the `x_opencti_modified_at` already stored in OpenCTI is reduced to a reference (type, ID, name, author and markings). Its fields and its Title, Analysis and History notes are not sent, so they cannot overwrite the newer version. Its relationships and the other objects of its file are still sent. A newer vulnerability takes the `created` date the platform holds when it is older than its own, so the notes it generates (whose IDs derive from `created`) are the same notes as those of the previous runs. This check covers vulnerabilities only: an older publication of another entity type that reaches the bucket after a newer one was already ingested by a previous run is sent as received.
- **Across runs**: a run starts only once the works sent by the previous run are complete, so a version is never applied before an older one still waiting in the queue. New files stay in the bucket in the meantime. A work that makes no progress for one hour is considered stalled: it is released once the connector queue is empty (its remaining messages are lost), while the connector keeps waiting, with a warning, as long as the queue still holds messages (for example after a worker outage). Resetting the connector state in OpenCTI clears the wait at any time.

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
