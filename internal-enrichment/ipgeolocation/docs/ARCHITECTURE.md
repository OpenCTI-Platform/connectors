# Architecture Document

## Overview

The IPGeolocation.io OpenCTI Connector is an **internal enrichment** connector
that transforms IP intelligence from IPGeolocation.io v3 APIs into semantically
rich STIX 2.1 knowledge within the OpenCTI platform.

## Component Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    OpenCTI Platform                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│  │Observable │→ │ RabbitMQ │→ │Connector │→ │  Worker  │        │
│  │ (IPv4/6) │  │  Queue   │  │ Process  │  │ Ingests  │        │
│  └──────────┘  └──────────┘  └────┬─────┘  └──────────┘        │
│                                    │                             │
└────────────────────────────────────┼─────────────────────────────┘
                                     │
            ┌────────────────────────┼────────────────────────┐
            │        Connector Process (Python)               │
            │                                                  │
            │  ┌─────────┐                                    │
            │  │ Config   │  Typed configuration from          │
            │  │          │  env vars / YAML                   │
            │  └────┬─────┘                                    │
            │       │                                          │
            │  ┌────▼─────┐   ┌──────────────┐               │
            │  │ Connector │──►│  API Client   │──► IPGeolocation.io
            │  │ (orchestr)│   │  (retry/cache)│   /v3/ipgeo   │
            │  └────┬──────┘   └──────────────┘   /v3/security │
            │       │                              /v3/asn      │
            │       │                              /v3/abuse    │
            │  ┌────▼──────┐                                   │
            │  │Risk Scorer │  Unified score 0-100             │
            │  └────┬──────┘                                   │
            │       │                                          │
            │  ┌────▼──────┐                                   │
            │  │STIX Mapper │  Location, ASN, Identity,        │
            │  │            │  Indicator, Note, Opinion,       │
            │  │            │  Relationship objects             │
            │  └────┬──────┘                                   │
            │       │                                          │
            │  ┌────▼──────┐                                   │
            │  │ Markdown   │  Analyst-readable notes          │
            │  │ Generator  │                                  │
            │  └────┬──────┘                                   │
            │       │                                          │
            │       ▼                                          │
            │  STIX 2.1 Bundle → OpenCTI                       │
            └──────────────────────────────────────────────────┘
```

## Module Responsibilities

| Module              | Responsibility                                       |
|---------------------|------------------------------------------------------|
| `config.py`         | Typed configuration from env/YAML                    |
| `models.py`         | Typed dataclasses for API responses                  |
| `api_client.py`     | HTTP client with retry, rate-limit, credit logic     |
| `connector.py`      | Orchestrator: read observable → enrich → send bundle |
| `risk_scorer.py`    | Normalize threat signals into unified 0-100 score    |
| `stix_mapper.py`    | Transform intelligence into STIX 2.1 objects         |
| `markdown_generator.py` | Produce analyst-readable enrichment notes        |

## Credit Optimization

The connector supports two API consumption modes:

**Single-call mode** (`IPGEOLOCATION_SINGLE_CALL_MODE=true`):
- Uses `/v3/ipgeo?include=security,abuse` for one HTTP call
- Adds dedicated `/v3/asn` for richer network data
- Total: 2 HTTP calls per enrichment (4 credits typical)

**Dedicated mode** (`IPGEOLOCATION_SINGLE_CALL_MODE=false`):
- Calls `/v3/ipgeo`, `/v3/security`, `/v3/asn`, `/v3/abuse` separately
- Total: 4 HTTP calls per enrichment (5 credits typical)
- Useful when only some APIs are enabled

## Data Flow

1. OpenCTI triggers enrichment (auto or manual)
2. Connector reads observable via GraphQL
3. TLP check (respects `max_tlp`)
4. API client calls IPGeolocation.io
5. Response parsed into typed `IPIntelligence`
6. Risk scorer produces `RiskAssessment`
7. STIX mapper creates objects (Location, ASN, Identity, etc.)
8. Markdown generator creates analyst note
9. Bundle assembled and sent to OpenCTI via `send_stix2_bundle`
