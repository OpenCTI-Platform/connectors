# OpenCTI External Reference Import

This connector allows organizations to import external references as PDF files or MarkDown files.

## General overview

OpenCTI data is coming from *import* connectors.

## Installation

### Requirements

- OpenCTI Platform >= 5.0.0

### Configuration

| Parameter                                    | Docker envvar                                | Mandatory | Description                                                                              |
|----------------------------------------------|----------------------------------------------|-----------|------------------------------------------------------------------------------------------|
| `opencti_url`                                | `OPENCTI_URL`                                | Yes       | The URL of the OpenCTI platform.                                                         |
| `opencti_token`                              | `OPENCTI_TOKEN`                              | Yes       | The default admin token configured in the OpenCTI platform parameters file.              |
| `connector_id`                               | `CONNECTOR_ID`                               | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                       |
| `connector_type`                             | `CONNECTOR_TYPE`                             | Yes       | Must be `INTERNAL_ENRICHMENT` (this is the connector type).                              |
| `connector_name`                             | `CONNECTOR_NAME`                             | Yes       | Option `ImportExternalReference`                                                         |
| `connector_auto`                             | `CONNCETOR_AUTO`                             | Yes       | `false` Enable/disable auto-import of external references                                |
| `connector_scope`                            | `CONNECTOR_SCOPE`                            | Yes       | Supported file types: `'External-Reference'`                                             |
| `connector_confidence_level`                 | `CONNECTOR_CONFIDENCE_LEVEL`                 | Yes       | The default confidence level for created sightings (a number between 1 and 100).         |
| `connector_log_level`                        | `CONNECTOR_LOG_LEVEL`                        | Yes       | Connector logging verbosity, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `import_external_reference_import_as_pdf`    | `IMPORT_EXTERNAL_REFERENCE_IMPORT_AS_PDF`    | Yes       | Import as PDF file                                                                       |
| `import_external_reference_import_as_md`     | `IMPORT_EXTERNAL_REFERENCE_IMPORT_AS_MD`     | Yes       | Import as MD file                                                                        |
| `IMPORT_EXTERNAL_REFERENCE_IMPORT_PDF_AS_MD` | `IMPORT_EXTERNAL_REFERENCE_IMPORT_PDF_AS_MD` | Yes       | If import_as_md is true, try to convert PDF as Markdown                                  |
After adding the connector, you should be able to extract information from a report.

*Reference: https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html*

### Configuration

**config.yaml**

```
import_as_pdf    : bool
import_as_md     : bool
import_pdf_as_md : bool
```

[1] https://github.com/OpenCTI-Platform/client-python/tree/master/pycti/entities