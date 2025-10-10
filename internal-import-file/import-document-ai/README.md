# AI-Based OpenCTI Document Import Connector  
*(Powered by Ariane or Azure OpenAI)*

| Status            | Date       | Comment |
| ----------------- |------------| ------- |
| Filigran Verified | 2025-03-18 |    -    |

This connector enables Enterprise Edition deployments to ingest unstructured threat-intelligence documents (e.g., PDFs, text files, reports) and automatically extract entities, observables, relationships, and indicators into OpenCTI.

It extends the default **Import Document** connector with advanced natural-language extraction capabilities, optional **Azure OpenAI** integration, and expanded STIX coverage — while remaining fully backward-compatible with prior versions.

---

## General Overview

The connector automatically extracts structured intelligence (STIX SDOs/SCOs/Relationships/Indicators) from unstructured documents such as PDFs, text, HTML, or DOCX files. It preprocesses text, extracts candidate observables (HINTS), and calls an LLM to resolve entities, relations, and context.

It produces complete STIX 2.1 bundles for ingestion into OpenCTI.

### Core Features

- **Span-based LLM extraction** — unified format for entities, observables, and relationships.  
- **Regex pre-scanning (HINTS)** — authoritative observables from the text.  
- **Full STIX 2.1 object coverage** — supports nearly all standard SDOs and SCOs.  
- **Relation validation** — all predicted relationships checked against OpenCTI’s allowed matrix.  
- **Deduplication and reconciliation** — merges positions and IDs across document chunks.  
- **Automatic container linking** — links new objects to existing Reports, Groupings, or Cases.  
- **Optional indicator creation** — automatically builds indicators from observables.  
- **Multiple AI providers** — works with either Filigran’s Ariane or Azure OpenAI models.  
- **Rate limiting & retry logic** — prevents API throttling and ensures stable ingestion.

---

## AI Processing Modes

| Mode | Description |
|------|--------------|
| **Ariane (default)** | Uses Filigran’s hosted AI engine via the `connector_web_service_url` endpoint. Requires a PEM license key. |
| **Azure OpenAI** | Uses your Azure OpenAI resource (`gpt-4o`, `gpt-4o-mini`, etc.) for local parsing. No Filigran license required. |

Both paths produce identical STIX outputs:  
- Entities (`SDOs`)  
- Observables (`SCOs`)  
- Relationships  
- Indicators (optional)

---

## Supported STIX Objects

### STIX Domain Objects (SDOs)

| Entity           | STIX Type / Field             | Supported | Example                                                  | Notes                                                                                |
| ---------------- | ----------------------------- | --------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| Attack Pattern   | `attack-pattern.x_mitre_id`   | :heavy_check_mark:         | T1566.002                                                | Matched via MITRE ATT&CK ID or name; cached lookup in OpenCTI                        |
| Campaign         | `campaign.name`               | :heavy_plus_sign:        | Operation Triangulation                                  | Normalized by capitalization; validated length ≥ 2                                   |
| Course of Action | `course-of-action.name`       | :heavy_plus_sign:        | Disable SMBv1                                            | Sanitized, trimmed; deduped by normalized text                                       |
| Grouping         | `grouping.name`               | :heavy_plus_sign:        | APT29 cluster                                            | Normalized name; used for logical report groupings                                   |
| Identity         | `identity.name`               | :heavy_plus_sign:        | Microsoft Corporation                                    | Normalized per STIX identity schema; organization vs individual resolved via context |
| Incident         | `incident.name`               | :heavy_plus_sign:        | Colonial Pipeline Attack                                 | Normalized, UTF-8 sanitized                                                          |
| Indicator        | `indicator.pattern`           | :heavy_check_mark:         | `[file:hashes.MD5 = '3525a8a16ce8988885d435133b3e85d8']` | Generated from observables with `.based-on` relationship                             |
| Infrastructure   | `infrastructure.name`         | :heavy_plus_sign:        | C2 node 45.32.1.12                                       | Normalized label; deduped by entity ID                                               |
| Intrusion Set    | `intrusion-set.name`          | :heavy_check_mark:         | Lazarus Group                                            | Case-insensitive deduplication; normalized aliases                                   |
| Location         | `location.name`               | :heavy_check_mark:         | France                                                   | Validated against ISO 3166 / STIX dictionary                                         |
| Malware          | `malware.name`                | :heavy_check_mark:         | Emotet                                                   | Lowercased, normalized name; deduped                                                 |
| Note             | `note.content`                | :heavy_plus_sign:        | Analyst comments                                         | Sanitized text block                                                                 |
| Observed Data    | `observed-data.objects`       | :heavy_plus_sign:        | Network packet captures                                  | Auto-linked via observable relationships                                             |
| Opinion          | `opinion.opinion`             | :heavy_plus_sign:        | MITRE assessment                                         | Normalized strings; sentiment detection optional                                     |
| Report           | `report.name`, `.object_refs` | :heavy_check_mark:         | Threat bulletin                                          | Created automatically if no container entity provided                                |
| Threat Actor     | `threat-actor.name`           | :heavy_check_mark:         | APT28                                                    | Normalized, deduped by lowercase canonical name                                      |
| Tool             | `tool.name`                   | :heavy_check_mark:         | PowerShell                                               | Normalized; used to link observed processes                                          |
| Vulnerability    | `vulnerability.name`          | :heavy_check_mark:         | CVE-2023-12345                                           | Matched via CVE pattern `CVE-\d{4}-\d{4,7}`                                          |

:heavy_check_mark: = fully implemented
:heavy_plus_sign: = partially implemented
:x:  = not implemented


---

### STIX Cyber Observables (SCOs)

| Entity               | STIX Type / Field                                | Supported | Example                                     | Notes                                                                           |
| -------------------- | ------------------------------------------------ | --------- | ------------------------------------------- | ------------------------------------------------------------------------------- |
| Autonomous System    | `autonomous-system.number`                       | :heavy_check_mark:         | AS12345                                     | Validated via ASN regex `AS\d+`; numeric cast if possible                       |
| Domain Name          | `domain-name.value`                              | :heavy_check_mark:         | evil.com                                    | RFC 1035 validated; IDNA normalized; lowercased                                 |
| Email Address        | `email-addr.value`                               | :heavy_check_mark:         | [user@example.com](mailto:user@example.com) | RFC 5321/5322 validated; lowercased                                             |
| File                 | `file.name`, `file.hashes.MD5/SHA-1/SHA-256`     | :heavy_check_mark:         | malware.exe                                 | Hashes validated via hex regex; names sanitized                                 |
| IPv4 Address         | `ipv4-addr.value`                                | :heavy_check_mark:         | 10.0.0.1                                    | RFC 791 validated; CIDR and individual IP supported                             |
| IPv6 Address         | `ipv6-addr.value`                                | :heavy_check_mark:         | fe80::1                                     | RFC 4291 validated; expanded to canonical form                                  |
| MAC Address          | `mac-addr.value`                                 | :heavy_check_mark:         | 00:11:22:33:44:55                           | Normalized to lowercase, colon-delimited                                        |
| Mutex                | `mutex.name`                                     | :heavy_plus_sign:        | Global\MutexLock                            | Regex matched; normalized whitespace                                            |
| Network Traffic      | `network-traffic.src_ref`, `.dst_ref`            | :heavy_plus_sign:        | src=10.0.0.1, dst=8.8.8.8                   | Built dynamically for bidirectional pairs                                       |
| Process              | `process.command_line`                           | :heavy_plus_sign:        | cmd.exe /c whoami                           | Sanitized string extraction                                                     |
| Software             | `software.name`, `.version`                      | :heavy_plus_sign:        | Chrome 129                                  | Normalized version tokens; deduped                                              |
| URL                  | `url.value`                                      | :heavy_check_mark:         | [https://example.org](https://example.org)  | RFC 3986 validated and refanged; IDN-safe                                       |
| User Account         | `user-account.user_id`                           | :heavy_plus_sign:        | admin                                       | Normalized lowercase username                                                   |
| Windows Registry Key | `windows-registry-key.key`                       | :heavy_check_mark:         | HKEY_LOCAL_MACHINE\Software...              | Case-insensitive normalization; backslashes preserved                           |
| X.509 Certificate    | `x509-certificate.subject`, `.issuer`, `.hashes` | :heavy_check_mark:         | CN=example.com                              | Fingerprints normalized (colons removed, lowercase); validated via ASN.1 fields |

---

### Indicator and Relationship Generation

| Object                    | Type / Description       | Example                               | Notes                                            |
| ------------------------- | ------------------------ | ------------------------------------- | ------------------------------------------------ |
| Indicator                 | Derived from observables | `[ipv4-addr:value = '45.61.148.153']` | Created automatically if `create_indicator=True` |
| Based-On                  | `indicator -> observable` | Indicator (hash) -> File               | Always generated during bundle composition       |
| Related-To                | `observable <-> entity`    | URL -> Malware                         | Created when linking to non-container entities   |
| Uses / Targets / Exploits | Entity relationships     | Malware -> Vulnerability               | Validated against OpenCTI relation policy        |
| Authored-By               | Entity -> Author Identity | Report -> Identity                     | Propagated when available in container context   |


All observables optionally generate indicators if `connector_create_indicator=true`.

---

## Relationships

Predicted or inferred relationships are validated against OpenCTI’s `allowed-relations` matrix before bundle submission.

### Relationships

| Relationship | From | To | Description |
|---------------|------|----|--------------|
| uses | Threat Actor / Intrusion Set | Attack Pattern / Malware / Tool | Indicates operational use |
| targets | Intrusion Set / Malware / Attack Pattern | Vulnerability / Organization / Sector / Location | Describes intended targets |
| attributed-to | Malware / Intrusion Set | Threat Actor | Attribution relationships |
| originates-from | Threat Actor / Intrusion Set | Location | Source origin |
| located-at | Infrastructure / Organization | Location | Physical or logical placement |
| based-on | Indicator | Observable | Derived evidence linkage |
| mitigates | Course of Action | Vulnerability / Attack Pattern | Defensive measures |
| exploits | Malware / Attack Pattern | Vulnerability | Exploitation chain |
| related-to | Any | Any | Contextual relationships |
| derived-from | Observable | Observable | Derived or transformed data |

Relations failing schema validation or policy checks are logged as **skipped**, including `(from_type, rel_type, to_type)` details.

---

## Preprocessing & Extraction Flow

1. **File retrieval** -> from OpenCTI import queue.  
2. **Text extraction** -> PDFs (OCR optional), HTML, DOCX, TXT.  
3. **Normalization** -> unwrap, refang, whitespace compact.  
4. **Regex scanning** -> extract deterministic observables as HINTS.  
5. **Chunking** -> token-budget-based slicing with overlap.  
6. **Model call** -> OpenAI (Azure or Ariane) with HINTS + text.  
7. **Relation filtering** -> remove disallowed combinations.  
8. **Deduplication** -> merge duplicates and re-link positions.  
9. **Bundle creation** -> STIX 2.1-compliant and validated.  

---

## Indicators

If enabled (`connector_create_indicator: true`), the connector:

- Generates Indicators from all supported observables.
- Creates `based-on` relationships to link Indicators to their source observables.
- Preserves marking definitions and authorship inherited from the contextual entity (if any).

Indicators adopt OpenCTI’s default temporal validity and scoring schema.

---

## Preprocessing and OCR

- **Normalization pipeline:** de-wraps lines, refangs IOCs, compacts whitespace.  
- **OCR support:** EasyOCR + poppler-utils (CPU only by default).  
- **GPU usage:** supported with custom CUDA-enabled base image (see below).

To disable OCR:
```bash
IMPORT_DOCUMENT_PDF_OCR=false
```

---

### Configuration

| Parameter | Docker envvar | Default | Mandatory | Description |
|------------|---------------|----------|------------|--------------|
| `opencti_url` | `OPENCTI_URL` |  | Yes | The URL of the OpenCTI platform. |
| `opencti_token` | `OPENCTI_TOKEN` |  | Yes | The default admin token configured in the OpenCTI platform parameters file. |
| `connector_id` | `CONNECTOR_ID` |  | Yes | A valid arbitrary `UUIDv4` that must be unique for this connector. |
| `connector_name` | `CONNECTOR_NAME` |  | Yes | Connector name, e.g. `ImportDocumentAI`. |
| `connector_auto` | `CONNECTOR_AUTO` | `false` | No | Enable/disable automatic import of report files. |
| `connector_scope` | `CONNECTOR_SCOPE` |  | Yes | Supported file types: `'application/pdf','text/plain','text/html','text/markdown','text/csv','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/msword','application/octet-stream'`. |
| `connector_log_level` | `CONNECTOR_LOG_LEVEL` | `error` | No | Logging level for this connector (`debug`, `info`, `warn`, `error`). |
| `connector_create_indicator` | `CONNECTOR_CREATE_INDICATOR` | `false` | No | Create an indicator for each extracted observable. |
| `connector_web_service_url` | `CONNECTOR_WEB_SERVICE_URL` | `https://importdoc.ariane.filigran.io` | No | Web service endpoint for the Filigran Ariane backend. Used when not using OpenAI or Azure OpenAI. |
| `connector_licence_key_pem` | `CONNECTOR_LICENCE_KEY_PEM` |  | See note | The PEM license certificate provided by Filigran (Enterprise Edition). **Required only when using the Ariane backend.** |
| `import_document_pdf_ocr` | `IMPORT_DOCUMENT_PDF_OCR` | `true` | No | Enable or disable OCR for PDF files (requires EasyOCR and poppler-utils). |
| `import_document_pdf_ocr_langs` | `IMPORT_DOCUMENT_PDF_OCR_LANGS` | `en` | No | OCR recognition languages. Comma-separated list or YAML array (e.g. `en,fr,de`). |
| `import_document_pdf_ocr_page_dpi` | `IMPORT_DOCUMENT_PDF_OCR_PAGE_DPI` | `300` | No | Rendering DPI used for PDF OCR preprocessing (higher values improve accuracy but increase processing time). |
| `ai_provider` | `IMPORT_DOCUMENT_AI_PROVIDER` | `ariane` | Yes | Which AI backend to use for extraction. Options: `ariane`, `openai`, `azureopenai`. Determines which credentials are required. |
| `ai_model` | `IMPORT_DOCUMENT_AI_MODEL` | `gpt-4o` | No | Model name used for extraction. Must exist on your OpenAI/Azure deployment. |
| `azure_openai_endpoint` | `AZURE_OPENAI_ENDPOINT` |  | Required if `ai_provider=azureopenai` | Azure OpenAI endpoint URL (enables Azure OpenAI entity extraction if set). |
| `azure_openai_key` | `AZURE_OPENAI_KEY` |  | Required if `ai_provider=openai` or `ai_provider=azureopenai` | Azure or OpenAI API key. |
| `azure_openai_deployment` | `AZURE_OPENAI_DEPLOYMENT` |  | Required if `ai_provider=azureopenai` | Azure OpenAI deployment name. |
| `azure_openai_api_version` | `AZURE_OPENAI_API_VERSION` | `2024-02-15-preview` | No | Azure OpenAI API version string. |
| `max_model_tokens` | `IMPORT_DOCUMENT_MAX_MODEL_TOKENS` | `4096` | No | Maximum total tokens (input + output) supported by the model. Used for dynamic chunk sizing. |
| `model_input_ratio` | `IMPORT_DOCUMENT_MODEL_INPUT_RATIO` | `0.3` | No | Fraction of total tokens reserved for input context (0–1). Controls balance between input and completion size. |
| `openai_rpm` | `IMPORT_DOCUMENT_OPENAI_RPM` |  | No | Optional request-per-minute rate limit for OpenAI/Azure calls. If unset, rate limiting is disabled. |
| `prompt_path` | `IMPORT_DOCUMENT_PROMPT_PATH` |  | No | Absolute or repo-relative path to override the default system prompt used for LLM extraction. |
| `trace_payloads` | `REPORTIMPORTER_TRACE_PAYLOADS` | `false` | No | Enable detailed tracing of model inputs/outputs and STIX bundles (for debugging). Should not be used in production. |

---

### Important Notes on License Keys

If you use the **default (Ariane)** backend, you **must** provide a valid Filigran license certificate (`connector_licence_key_pem`).

If you use **Azure OpenAI** (`ai_provider=azureopenai`), you must provide:
- `AZURE_OPENAI_ENDPOINT`
- `AZURE_OPENAI_KEY`
- `AZURE_OPENAI_DEPLOYMENT`
- (optionally) `AZURE_OPENAI_API_VERSION`

If you use **OpenAI (non-Azure)**, you must provide:
- `AZURE_OPENAI_KEY` (used as OpenAI API key)

---

### Azure OpenAI Integration

To use Azure OpenAI for entity extraction, set:

```env
AZURE_OPENAI_ENDPOINT=https://YOUR-RESOURCE-NAME.openai.azure.com/
AZURE_OPENAI_KEY=YOUR_AZURE_OPENAI_KEY
AZURE_OPENAI_DEPLOYMENT=YOUR_DEPLOYMENT_NAME
AZURE_OPENAI_API_VERSION=2024-02-15-preview
```

If these are not set, the connector defaults to the Filigran Ariane service defined by `connector_web_service_url`.

---

## Installation

### Requirements
- OpenCTI ≥ 6.5.0  
- Docker / Docker Compose  
- Python 3.12 (within container)

### Deployment

```bash
docker compose build
docker compose up -d
```

or standalone:

```bash
docker run --rm   -e OPENCTI_URL=https://opencti.example.org   -e OPENCTI_TOKEN=YOUR_TOKEN   -e CONNECTOR_ID=$(uuidgen)   -v $(pwd)/config.yml:/app/config.yml   import-document-ai:latest
```

---

## GPU-Ready Docker Setup (Optional)

To enable GPU acceleration for OCR:
- Build a custom version of the connector from a CUDA-enabled PyTorch base image (`pytorch/pytorch:<ver>-cuda<xx>`).
- Keep EasyOCR and Torch versions compatible with the CUDA runtime.
- Launch container with `--gpus all`.

The repository Dockerfile builds a CPU-only image by default.

---

## Debugging

Increase verbosity:
```bash
CONNECTOR_LOG_LEVEL=debug
```

Trace full AI prompt and bundle payloads (use only for troubleshooting):
```bash
REPORTIMPORTER_TRACE_PAYLOADS=1
```

Logs include per-phase `[TRACE <id>]` correlation IDs and retry diagnostics.

---

## Supported Formats Summary

| Format | Supported | Notes |
|---------|------------|-------|
| PDF | :heavy_check_mark: | With optional OCR |
| Text | :heavy_check_mark: | UTF-8 or ASCII |
| HTML | :heavy_check_mark: | Converted to Markdown |
| Markdown | :heavy_check_mark: | Native parsing |
| CSV / DOCX / DOC | :heavy_check_mark: | Basic extraction |

---

## Reference

- [STIX 2.1 Specification](https://docs.oasis-open.org/cti/stix/v2.1/cs01/stix-v2.1-cs01.html)  
- [OpenCTI Documentation](https://www.filigran.io/opencti/)
