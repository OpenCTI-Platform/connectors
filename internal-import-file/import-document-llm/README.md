# OpenCTI Import Document LLM Connector

| Status    | Date       | Comment                              |
|-----------|------------|--------------------------------------|
| Community | 2026-04-12 | Internal import with LLM extraction. |

## Table of Contents

- [OpenCTI Import Document LLM Connector](#opencti-import-document-llm-connector)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Capabilities](#capabilities)
  - [Supported Providers](#supported-providers)
  - [Processing Pipeline](#processing-pipeline)
  - [Supported STIX Output](#supported-stix-output)
    - [Entity and Observable Families](#entity-and-observable-families)
    - [Relationships](#relationships)
    - [Indicators](#indicators)
  - [Configuration](#configuration)
    - [OpenCTI Base Variables](#opencti-base-variables)
    - [Connector Base Variables](#connector-base-variables)
    - [LLM Variables](#llm-variables)
    - [OpenAI Provider Variables](#openai-provider-variables)
    - [Azure OpenAI Provider Variables](#azure-openai-provider-variables)
    - [Ollama Provider Variables](#ollama-provider-variables)
    - [OCR Variables](#ocr-variables)
    - [Prompt and Tracing Variables](#prompt-and-tracing-variables)
  - [Context Window and Token Budgeting](#context-window-and-token-budgeting)
  - [Install and Run](#install-and-run)
    - [Docker Compose](#docker-compose)
    - [Local Development](#local-development)
  - [Operational Notes](#operational-notes)
  - [Troubleshooting](#troubleshooting)
  - [Testing](#testing)

## Overview

This connector is an **Internal Import File** connector for OpenCTI.

It ingests unstructured documents (for example PDF, text, HTML, markdown, CSV, and Office document formats), runs preprocessing and IOC hint extraction, calls an LLM provider, and converts extracted entities, observables, and relationships into STIX 2.1 objects for import into OpenCTI.

The connector is built for deployments that want a provider-selectable LLM parsing path with deterministic preprocessing, relationship filtering, and OpenCTI-native bundle submission.

## Capabilities

- LLM-based extraction of entities, observables, and relations from document text.
- Structured IOC hint pre-scan using regex scanning before model inference.
- Run-scoped deduplication for exact files and normalized extracted text.
- Cheap document triage that drops junk pages and supports regex-only extraction.
- Chunked prompt construction with overlap and token-aware message sizing.
- Context-window handling with provider metadata support and manual override.
- Optional indicator generation from extracted observables.
- OpenCTI relationship policy validation before relationship materialization.
- Lazy OCR for likely image-based PDFs with configurable languages and DPI.
- Optional request throttling (RPM) for provider calls.
- Optional payload tracing for prompt/response debugging.

## Supported Providers

The connector supports three LLM provider modes through `IMPORT_DOCUMENT_AI_PROVIDER`:

- `openai`
- `azureopenai`
- `ollama`

Provider behavior is unified at the connector layer so all providers flow through the same normalization, chunking, relation filtering, and STIX bundle generation logic.

## Processing Pipeline

1. OpenCTI sends an internal import message.
2. The connector downloads the file content from OpenCTI.
3. File text extraction runs cheaply first.
4. Run-scoped dedupe skips exact duplicate files and duplicate extracted text.
5. Text normalization and structured IOC regex scanning produce hints.
6. Cheap triage decides DROP, REGEX_ONLY, LLM_EXTRACT, or OCR retry for PDFs.
7. Text is chunked using token budgets and overlap only when LLM extraction is justified.
8. Provider call(s) run per chunk with a strict extraction prompt.
9. Chunk responses are normalized and merged with authoritative regex hints.
10. Span-based entities and relationships are converted to STIX objects.
11. Relationship rules are checked against allowed relation combinations.
12. Bundle is linked to context entity or a generated report container.
13. STIX bundle is submitted to OpenCTI.

## Supported STIX Output

### Entity and Observable Families

The connector emits STIX-compatible entities and observables based on model output and internal normalization logic. Typical categories include:

- Intrusion sets
- Threat actors
- Malware
- Tools
- Vulnerabilities
- Attack patterns
- Infrastructure
- Identities and locations
- Domain names, URLs, IPs, hashes, emails, and other observables

Final object creation still depends on parsed content quality and relation validation rules.

### Relationships

The connector accepts relation candidates from the model and filters them through OpenCTI allowed relation logic before creating STIX relationship objects.

### Indicators

If indicator creation is enabled, observables can be transformed into indicators and linked using `based-on` relationships.

## Configuration

Configuration values can be provided with environment variables (`docker-compose.yml`) or with `src/config.yml` (based on `src/config.yml.sample`).

### OpenCTI Base Variables

| Parameter | Env var | Required | Description |
| --- | --- | --- | --- |
| OpenCTI URL | `OPENCTI_URL` | Yes | Base URL of OpenCTI platform. |
| OpenCTI token | `OPENCTI_TOKEN` | Yes | API token for connector authentication. |

### Connector Base Variables

| Parameter | Env var | Default | Required | Description |
| --- | --- | --- | --- | --- |
| Connector ID | `CONNECTOR_ID` | - | Yes | Unique UUIDv4 for this connector instance. |
| Connector name | `CONNECTOR_NAME` | `ImportDocumentLLM` | No | Display name in OpenCTI. |
| Connector scope | `CONNECTOR_SCOPE` | File MIME list | Yes | MIME types accepted by connector. |
| Connector auto | `CONNECTOR_AUTO` | `false` | No | Auto-process files in scope. |
| Validate before import | `CONNECTOR_VALIDATE_BEFORE_IMPORT` | Depends on deployment | No | Validate bundles before ingestion. |
| Log level | `CONNECTOR_LOG_LEVEL` | `error` | No | Logging level (`debug`, `info`, `warn`, `error`). |

### LLM Variables

| Parameter | Env var | Default | Required | Description |
| --- | --- | --- | --- | --- |
| Provider | `IMPORT_DOCUMENT_AI_PROVIDER` | `ollama` in sample deployments | Yes | LLM backend selector (`openai`, `azureopenai`, `ollama`). |
| Model | `IMPORT_DOCUMENT_AI_MODEL` | `gemma4` in sample Ollama deployments | Yes | Base model/deployment reference used by provider mode. |
| Create indicator | `IMPORT_DOCUMENT_CREATE_INDICATOR` | `false` | No | Create indicators from supported extracted observables. |
| Create indicator (fallback) | `CONNECTOR_CREATE_INDICATOR` | `false` | No | Secondary fallback used only when `IMPORT_DOCUMENT_CREATE_INDICATOR` is unset/false. |
| Manual context window | `IMPORT_DOCUMENT_MANUAL_CONTEXT_WINDOW` | unset | No | Explicit total context window override (input + output). |
| Max model tokens fallback | `IMPORT_DOCUMENT_MAX_MODEL_TOKENS` | `4096` | No | Fallback context window when no provider metadata is available. |
| Input ratio | `IMPORT_DOCUMENT_MODEL_INPUT_RATIO` | `0.3` | No | Fraction of available token budget allocated to chunk input text. |
| RPM throttle | `IMPORT_DOCUMENT_LLM_RPM` | unset | No | Request per minute limit for provider calls. `IMPORT_DOCUMENT_OPENAI_RPM` remains accepted as a legacy alias. |
| Run binary cache size | `IMPORT_DOCUMENT_RUN_BINARY_CACHE_SIZE` | `100000` | No | Maximum exact-file hashes retained for run-scoped dedupe. |
| Run text cache size | `IMPORT_DOCUMENT_RUN_TEXT_CACHE_SIZE` | `100000` | No | Maximum normalized text hashes retained for run-scoped dedupe. |

### OpenAI Provider Variables

| Parameter | Env var | Required when provider is `openai` | Description |
| --- | --- | --- | --- |
| API key | `OPENAI_API_KEY` | Yes | OpenAI API key. |

Notes:

- `AZURE_OPENAI_KEY` is also accepted as a secondary key source during key resolution.

### Azure OpenAI Provider Variables

| Parameter | Env var | Required when provider is `azureopenai` | Description |
| --- | --- | --- | --- |
| Endpoint | `AZURE_OPENAI_ENDPOINT` | Yes | Azure OpenAI endpoint URL. |
| API key | `AZURE_OPENAI_KEY` | Yes | Azure OpenAI key. |
| Deployment | `AZURE_OPENAI_DEPLOYMENT` | Yes | Azure deployment name. |
| API version | `AZURE_OPENAI_API_VERSION` | No | Azure API version (default `2024-02-15-preview`). |

### Ollama Provider Variables

| Parameter | Env var | Default | Required when provider is `ollama` | Description |
| --- | --- | --- | --- | --- |
| Host | `OLLAMA_HOST` | `http://localhost:11434` | No | Ollama API host. |
| Pull on start | `OLLAMA_PULL_ON_START` | `false` | No | Pull model at startup before metadata query/inference. |
| Pull timeout | `OLLAMA_PULL_TIMEOUT_S` | `600` | No | Startup pull timeout in seconds. |

### OCR Variables

| Parameter | Env var | Default | Required | Description |
| --- | --- | --- | --- | --- |
| OCR enabled | `IMPORT_DOCUMENT_PDF_OCR` | `false` | No | Enable lazy OCR retry for likely image-based PDFs. |
| OCR languages | `IMPORT_DOCUMENT_PDF_OCR_LANGS` | `en` | No | Language list or CSV for OCR. |
| OCR DPI | `IMPORT_DOCUMENT_PDF_OCR_PAGE_DPI` | `300` | No | Render DPI for OCR preprocessing. |

### Prompt and Tracing Variables

| Parameter | Env var | Default | Required | Description |
| --- | --- | --- | --- | --- |
| Prompt path | `IMPORT_DOCUMENT_PROMPT_PATH` | internal default prompt | No | Override the extraction system prompt file path. |
| Trace payloads | `REPORTIMPORTER_TRACE_PAYLOADS` | `false` | No | Enable verbose tracing of prompt/response payloads. |

## Context Window and Token Budgeting

At runtime, context window resolution is prioritized as follows:

1. `IMPORT_DOCUMENT_MANUAL_CONTEXT_WINDOW` if set and valid.
2. Provider metadata discovery (currently implemented for Ollama model info).
3. `IMPORT_DOCUMENT_MAX_MODEL_TOKENS` fallback.
4. Internal model fallback table for known OpenAI model families.

The final usable budget accounts for:

- system prompt token count
- safety margin
- input ratio
- reserved completion budget and continuation strategy

This keeps chunk construction deterministic and protects against prompt overflow.

## Install and Run

### Docker Compose

From [docker-compose.yml](docker-compose.yml):

```bash
docker compose build
docker compose up -d
```

Set provider-specific env vars in compose before first run.

### Local Development

From [src](src):

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt -c constraints.txt
python main.py
```

## Operational Notes

- Keep `REPORTIMPORTER_TRACE_PAYLOADS` disabled in normal production operation.
- For Ollama in Docker Desktop on Windows, use `host.docker.internal` if the model runtime runs on the host.
- Ensure the selected model can handle extraction prompt size and expected report lengths.
- If extraction quality drifts, review prompt content at [src/reportimporter/prompts/system_prompt_relations.md](src/reportimporter/prompts/system_prompt_relations.md).

## Troubleshooting

- Provider auth errors:
  - verify provider-specific env vars and deployment/model names.
- Empty extraction results:
  - reduce input ratio, raise context window, inspect prompt and trace logs.
- OCR quality issues:
  - increase `IMPORT_DOCUMENT_PDF_OCR_PAGE_DPI`, adjust OCR languages.
- Ollama metadata/context mismatch:
  - set `IMPORT_DOCUMENT_MANUAL_CONTEXT_WINDOW` explicitly.

## Testing

Run focused test suites:

```bash
python -m pytest tests/test_ollama_provider.py tests/test_llmhelper.py tests/test_llmhelper_relations.py tests/test_llmhelper_budget.py tests/test_token_counting.py tests/test_reportimporter.py -q
```

Run the full suite:

```bash
python -m pytest tests -q
```
