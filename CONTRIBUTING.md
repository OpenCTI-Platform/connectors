---
version: 1.0
category: Documentation
audience: Partners, Customers, Community Contributors, Internal Team Members
maintainers: XTM Integrations Team
last updated: January 2026
status: Accepted
---

# OpenCTI Connector Development Guidelines

## Table of Contents

- [Introduction](#introduction)
  - [What is a Connector?](#what-is-a-connector)
  - [Connector Types Covered](#connector-types-covered)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [Quick Start](#quick-start)
  - [Initial Setup](#initial-setup)
  - [Creating a New Connector](#creating-a-new-connector)
  - [Understanding the Template Structure](#understanding-the-template-structure)
- [Documentation Structure](#documentation-structure)
- [Quick Overview](#quick-overview)
  - [Common Implementation Guidelines](#common-implementation-guidelines)
  - [Connector-Type Specific Guidelines](#connector-type-specific-guidelines)
- [Code Quality Standards](#code-quality-standards)
- [Getting Help](#getting-help)
  - [Resources](#resources)
  - [Community Support](#community-support)
  - [Contributing](#contributing)
- [Quick Reference](#quick-reference)

## Introduction

Welcome to the OpenCTI Connector Development Guidelines. This documentation provides comprehensive guidance for
developing high-quality connectors that integrate seamlessly with the OpenCTI platform.

OpenCTI connectors enable integration with external threat intelligence sources, enrichment services, and data streaming
platforms. These guidelines ensure consistency, maintainability, and reliability across all connectors in the OpenCTI
ecosystem.

### What is a Connector?

Connectors are standalone Python applications that interact with OpenCTI through the platform's API and messaging
infrastructure. They extend OpenCTI's capabilities by:

- **Importing threat intelligence** from external sources
- **Enriching existing data** with additional context
- **Streaming events** to external platforms in real-time
- **Processing files** for import/export operations

### Connector Types Covered

This documentation covers three primary connector types:

| Type                    | Purpose                                                  | Use Cases                                                       |
|-------------------------|----------------------------------------------------------|-----------------------------------------------------------------|
| **External Import**     | Fetch data from external sources and import into OpenCTI | Threat feeds, OSINT sources, vendor APIs                        |
| **Internal Enrichment** | Enrich entities within OpenCTI with additional data      | IP/domain reputation, vulnerability enrichment, entity analysis |
| **Stream**              | Listen to OpenCTI events and sync to external platforms  | SIEM integration, ticketing systems, real-time synchronization  |

## Prerequisites

Before starting connector development, ensure you have:

### Technical Requirements

- **Python 3.11 or 3.12** installed
- [**Docker**](https://docs.docker.com/engine/install/) and [**Docker Compose**](https://docs.docker.com/compose/install/) for containerization
- **Git** for version control
- Access to a **running OpenCTI instance** (v6.8.12 or higher)
- **API credentials** for the external service you're integrating

### Knowledge Requirements

- Proficiency in **Python programming**
- Understanding of **STIX 2.1 specification** ([OASIS STIX 2.1 Spec](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html))
- Familiarity with **Docker** and containerization concepts
- Basic understanding of **message queues** (RabbitMQ)
- Experience with **RESTful APIs**

### Development Environment

You can develop connectors using either:

1. **Docker Environment** (Recommended for production-like testing)
    - Requires Docker Compose knowledge
    - Best for integration testing
    - See [Docker Setup Guide](./docs/01-common-implementation.md#docker-environment)

2. **Local Environment** (Recommended for development)
    - Faster iteration cycle
    - Easier debugging
    - See [Local Setup Guide](./docs/01-common-implementation.md#local-environment)

## Getting Started

### Quick Start

1. **Identify your connector type** based on your use case
2. **Set up your development environment** (Docker or local)
3. **Use the connector creation script** to generate boilerplate code
4. **Review the appropriate specification document** for your connector type
5. **Implement your connector logic**
6. **Test thoroughly** following testing guidelines
7. **Submit a pull request** for review

### Initial Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR-USERNAME/connectors.git
cd connectors
git remote add upstream https://github.com/OpenCTI-Platform/connectors.git

# Create a branch for your connector
git checkout -b feature/my-connector-name
```

### Creating a New Connector

#### Choosing the Right Template

The fastest way to start is using the provided script:

```bash
cd templates
sh create_connector_dir.sh -t <TYPE> -n <NAME>
```

Where:

- `<TYPE>` is one of: external-import, internal-enrichment, stream
- `<NAME>` is your connector's name (e.g., my-threat-feed)

This creates a complete connector structure with:

- Pre-configured settings and configuration files
- Standardized directory structure
- Template implementation code
- Testing framework setup
- Docker deployment files
- Metadata files for documentation

Navigate to the `templates/` folder and copy the appropriate template for your connector type:

Or you can use command lines

```bash
# For External Import connector
cp -r templates/external-import external-import/my-connector

# For Internal Enrichment connector
cp -r templates/internal-enrichment internal-enrichment/my-connector

# For Stream connector
cp -r templates/stream stream/my-connector
```


### Understanding the Template Structure

All connectors follow this standardized structure:

```
my-connector/
├── __metadata__/                 # Connector metadata for catalog
│   ├── connector_manifest.json   # Connector information and configuration
│   └── logo.png                  # Connector logo (optional)
├── src/                          # Source code
│   ├── connector/                # Main connector logic
│   │   ├── __init__.py
│   │   ├── connector.py          # Core connector implementation
│   │   ├── converter_to_stix.py  # STIX conversion logic
│   │   ├── settings.py           # Configuration and validation
│   │   └── utils.py              # Utility functions
│   ├── my_client/                # External API client
│   │   ├── __init__.py
│   │   └── api_client.py         # API interaction logic
│   ├── main.py                   # Entry point
│   └── requirements.txt          # Python dependencies
├── tests/                        # Test suite
│   ├── test_connector/
│   │   └── test_settings.py
│   ├── conftest.py
│   ├── test_main.py
│   └── test-requirements.txt
├── .dockerignore             
├── config.yml.sample             # Sample configuration
├── docker-compose.yml            # Docker Compose configuration
├── Dockerfile                    # Container definition
├── entrypoint.sh                 # Container entry point
└── README.md                     # Connector documentation
```

## Documentation Structure

This guide is organized into multiple documents:

### Core Documentation

**[Common Implementation Guidelines](./docs/01-common-implementation.md)** (Start here!)
- Environment setup (Docker & Local)
- Directory structure and file organization
- Using the connectors-sdk
- Configuration management with Pydantic
- STIX 2.1 object creation
- Logging best practices
- State management
- Error handling patterns

### Connector-Type Specific Guidelines

**[External Import Connector Specifications](./docs/02-external-import-specifications.md)**
- Scheduling and interval handling
- Work initialization and tracking
- State management for incremental imports
- Rate limiting and API quotas
- Data deduplication strategies
- External API client implementation

**[Internal Enrichment Connector Specifications](./docs/03-internal-enrichment-specifications.md)**
- Event-driven architecture
- Entity scope validation
- TLP marking handling
- Playbook compatibility requirements
- Enrichment patterns and best practices
- Bundle handling for enrichment

**[Stream Connector Specifications](./docs/04-stream-specifications.md)**
- Live stream listening
- Event type handling (create/update/delete)
- Stream ID configuration
- Real-time synchronization patterns
- Error recovery and reconnection
- Backpressure handling

**[Code Quality & Standards](./docs/05-code-quality-standards.md)**
- Code style requirements
- Pylint configuration and custom plugins
- STIX 2.1 compliance validation
- Testing requirements and frameworks
- Docker and deployment standards
- Documentation requirements
- Security best practices
- Performance guidelines

## Quick Overview

### Common Implementation Guidelines

All connector types share common implementation patterns:

#### Configuration with Pydantic

All connectors use **Pydantic models** for configuration validation:

```python
from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class MyConnectorConfig(BaseConfigModel):
    api_base_url: HttpUrl = Field(description="API base URL.")
    api_key: str = Field(description="API key for authentication.")
```

#### Using the Connectors SDK

The **connectors-sdk** provides STIX-compliant models:

```python
from connectors_sdk.models import Indicator, OrganizationAuthor, TLPMarking

author = OrganizationAuthor(name="My Source")
tlp_marking = TLPMarking(level="green")

indicator = Indicator(
    name="Malicious IP",
    pattern="[ipv4-addr:value = '192.0.2.1']",
    pattern_type="stix",
    valid_from="2026-01-01T00:00:00Z",
    markings=[tlp_marking],
    author=author,
    score=75,
)
stix_indicator = indicator.to_stix2_object()
```

#### Logging

Always use the helper's logger:

```python
self.helper.connector_logger.info("Processing started", {"entity_id": entity_id})
self.helper.connector_logger.error("Failed to connect", {"error": str(e)})
```

#### Sending Data to OpenCTI

Standard pattern for sending STIX bundles:

```python
# Create bundle
stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)

# Send to OpenCTI
bundles_sent = self.helper.send_stix2_bundle(
    stix_objects_bundle,
    work_id=work_id,
    cleanup_inconsistent_bundle=True,
)
```

### Connector-Type Specific Guidelines

Each connector type has specific requirements and patterns. See the dedicated documentation:

- **External Import**: Focus on scheduled execution, state persistence, and incremental imports
- **Internal Enrichment**: Focus on event handling, scope validation, and playbook compatibility
- **Stream**: Focus on real-time event processing and external platform synchronization

### Code Quality Standards

All connectors must meet these quality standards:

### Linting Requirements

- **Pass pylint** with repository `.pylintrc` configuration
- **Use custom STIX plugin** to ensure proper STIX ID generation
- **Format with black** and **isort** before committing

```bash
# Install dependencies
cd shared/pylint_plugins/check_stix_plugin
pip install -r requirements.txt

# Run pylint with custom plugin
cd shared/pylint_plugins/check_stix_plugin
PYTHONPATH=. python -m pylint <path_to_connector> --load-plugins linter_stix_id_generator

# Format code
black <path_to_connector>
isort --profile black <path_to_connector>
```

### STIX 2.1 Compliance

- Use **connectors-sdk models** for STIX object creation
- Never create STIX objects without deterministic IDs
- Validate all STIX objects comply with STIX 2.1 specification
- Include proper relationships between objects

### Testing Requirements

- **Unit tests** for all core functionality
- **Integration tests** for external API interactions
- Test configuration validation
- Test error handling paths

### Docker Standards

- Use **python:3.12-alpine** base image
- Minimize layer count and image size
- Include health checks where applicable
- Follow security best practices (non-root user, minimal packages)
- Document all environment variables

### Documentation Standards

- Complete **README.md** with:
    - Connector description and use cases
    - Configuration parameters with examples
    - Setup and deployment instructions
    - Prerequisites and dependencies
    - Troubleshooting guide
- **Metadata file** (`connector_manifest.json`) with accurate information
- **Inline code documentation** for complex logic
- **Type hints** for all function signatures

## Getting Help

### Resources

- **OpenCTI Documentation**: [https://docs.opencti.io](https://docs.opencti.io)
- **Connector Development Docs**: [https://docs.opencti.io/latest/development/connectors](https://docs.opencti.io/latest/development/connectors)
- **STIX 2.1 Specification**: [https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- **OpenCTI Ecosystem**: [https://hub.filigran.io/cybersecurity-solutions/open-cti-integrations](https://hub.filigran.io/cybersecurity-solutions/open-cti-integrations)

### Community Support

For questions and community help:

- **Slack Community**: [https://community.filigran.io](https://community.filigran.io)
- **GitHub Issues**: [https://github.com/OpenCTI-Platform/connectors/issues](https://github.com/OpenCTI-Platform/connectors/issues)

### Contributing

When your connector is ready:

1. **Ensure all quality checks pass** (linting, tests, documentation)
2. **Test in a production-like environment**
3. **Create a Pull Request** on the [connectors repository](https://github.com/OpenCTI-Platform/connectors)
4. **Respond to review feedback** from maintainers
5. **Update documentation** as needed

> [!IMPORTANT]  
> When creating a Pull Request on this repository, ALWAYS create along with an associated GitHub issue describing the purpose of your contribution (what problem it fixes, what improvement it brings, or what new integration it provides).

Connectors that meet quality standards will be:

- Integrated into CI/CD pipelines
- Added to the OpenCTI Ecosystem catalog
- Available to the community via Docker Hub

---

## Quick Reference

| Need to...                     | See Document                                                           | Section              |
|--------------------------------|------------------------------------------------------------------------|----------------------|
| Set up development environment | [Common Implementation](./docs/01-common-implementation.md)            | Environment Setup    |
| Create STIX objects            | [Common Implementation](./docs/01-common-implementation.md)            | STIX Object Creation |
| Schedule periodic imports      | [External Import](./docs/02-external-import-specifications.md)         | Scheduling           |
| Handle enrichment events       | [Internal Enrichment](./docs/03-internal-enrichment-specifications.md) | Event Processing     |
| Listen to platform streams     | [Stream](./docs/04-stream-specifications.md)                           | Stream Listening     |
| Fix linting errors             | [Code Quality](./docs/05-code-quality-standards.md)                    | Linting              |
| Write tests                    | [Code Quality](./docs/05-code-quality-standards.md)                    | Testing              |
| Deploy with Docker             | [Code Quality](./docs/05-code-quality-standards.md)                    | Docker Standards     |

---

**Ready to start?** Proceed to [Common Implementation Guidelines](./docs/01-common-implementation.md) to begin developing
your connector.
