# OpenCTI External Reference Import

This connector allows organizations to import external references as PDF files or MarkDown files.

## General overview

OpenCTI data is coming from *import* connectors.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0
- Install wkhtmltox

### Configuration

| Parameter                                    | Docker envvar                                     | Mandatory | Description                                                                              |
|----------------------------------------------|---------------------------------------------------|-----------|------------------------------------------------------------------------------------------|
| `opencti_url`                                | `OPENCTI_URL`                                     | Yes       | The URL of the OpenCTI platform.                                                         |
| `opencti_token`                              | `OPENCTI_TOKEN`                                   | Yes       | The default admin token configured in the OpenCTI platform parameters file.              |
| `connector_id`                               | `CONNECTOR_ID`                                    | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                       |
| `connector_name`                             | `CONNECTOR_NAME`                                  | Yes       | Option `ImportExternalReference`                                                         |
| `connector_auto`                             | `CONNECTOR_AUTO`                                  | Yes       | `false` Enable/disable auto-import of external references                                |
| `connector_scope`                            | `CONNECTOR_SCOPE`                                 | Yes       | Supported file types: `'External-Reference'`                                             |
| `connector_confidence_level`                 | `CONNECTOR_CONFIDENCE_LEVEL`                      | Yes       | The default confidence level for created sightings (a number between 1 and 100).         |
| `connector_log_level`                        | `CONNECTOR_LOG_LEVEL`                             | Yes       | Connector logging verbosity, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `import_external_reference_import_as_pdf`    | `IMPORT_EXTERNAL_REFERENCE_IMPORT_AS_PDF`         | Yes       | Import as PDF file                                                                       |
| `import_external_reference_import_as_md`     | `IMPORT_EXTERNAL_REFERENCE_IMPORT_AS_MD`          | Yes       | Import as MD file                                                                        |
| `import_external_reference_import_pdf_as_md` | `IMPORT_EXTERNAL_REFERENCE_IMPORT_PDF_AS_MD`      | Yes       | If import_as_md is true, try to convert PDF as Markdown                                  |
| `timestamp_files`                            | `IMPORT_EXTERNAL_REFERENCE_TIMESTAMP_FILES`       | No        | If true, timestamp imported files to prevent overwriting versions                        |
| `cache_size`                                 | `IMPORT_EXTERNAL_REFERENCE_CACHE_SIZE`            | No        | Size of LRU URL cache to prevent fetching the same object repeatedly                     |
| `cache_ttl`                                  | `IMPORT_EXTERNAL_REFERENCE_CACHE_TTL`             | No        | Time-to-live (in seconds) for cache entries                                              |
| `browser_worker_count`                       | `IMPORT_EXTERNAL_REFERENCE_BROWSER_WORKER_COUNT`  | No        | Number of browser worker threads to use                                                  |
| `max_download_size`                          | `IMPORT_EXTERNAL_REFERENCE_MAX_DOWNLOAD_SIZE`     | No        | (50*1024*1024) Maximum download size                                                     |

After adding the connector, you should be able to extract information from a report.

*Reference: [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html)*

### YAML Configuration

**config.yaml**:

```yaml
import_as_pdf: false  # Import as PDF file
import_as_md: false   # Import as MD file
import_pdf_as_md: false # If import_as_md is true, try to convert PDF as Markdown
timestamp_files: false # If true, timestamp imported files to prevent overwriting versions
cache_size: 32 # Size of LRU URL cache to prevent fetching the same object repeatedly
cache_ttl: 3600 # Time-to-live (in seconds) for cache entries
browser_worker_count: 4 # Number of browser worker threads to use
max_download_size: 52428800 # (50*1024*1024) Maximum download size
```

[1] [OpenCTI Python Client Entities](https://github.com/OpenCTI-Platform/client-python/tree/master/pycti/entities)
