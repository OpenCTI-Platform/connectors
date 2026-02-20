# Code Quality & Standards

**Document:** 05-code-quality-standards.md
**Applies to:** All connector types

## Table of Contents

- [Code Style Requirements](#code-style-requirements)
- [Linting with Pylint](#linting-with-pylint)
- [STIX 2.1 Compliance](#stix-21-compliance)
- [Testing Requirements](#testing-requirements)
- [Docker Standards](#docker-standards)
- [Documentation Standards](#documentation-standards)
- [Security Best Practices](#security-best-practices)
- [Performance Guidelines](#performance-guidelines)
- [Metadata Requirements](#metadata-requirements)

---

## Code Style Requirements

### Python Version

- **Python 3.11 or 3.12** required
- Use type hints for all function signatures
- Follow PEP 8 style guidelines

### Code Formatting

All code must be formatted with **Black** and **isort** running at root level of the connectors repository:

```bash
# Format code
black .

# Sort imports
isort --profile black .
```

### Configuration Files

**File:** `pyproject.toml` (if using)

```toml
[tool.black]
line-length = 88
target-version = ['py311']

[tool.isort]
profile = "black"
line_length = 88
```

### Import Organization

```python
# Standard library imports
import json
import time
from datetime import datetime, timezone
from typing import List, Optional

# Third-party imports
import requests
from pydantic import Field, HttpUrl

# OpenCTI/SDK imports
from connectors_sdk import BaseConfigModel, BaseConnectorSettings
from connectors_sdk.models import Indicator, IPV4Address, TLPMarking
from pycti import OpenCTIConnectorHelper

# Local imports
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from my_client import MyClient
```

### Type Hints

Use type hints for all function signatures:

```python
from typing import List, Dict, Optional

def process_entities(
    entities: List[Dict],
    max_items: Optional[int] = None
) -> List[str]:
    """
    Process entities and return their IDs.

    Args:
        entities: List of entity dictionaries
        max_items: Maximum number of items to process

    Returns:
        List of entity IDs
    """
    processed_ids: List[str] = []

    for entity in entities[:max_items]:
        entity_id: str = entity["id"]
        processed_ids.append(entity_id)

    return processed_ids
```

### Docstrings

Use Google-style docstrings:

```python
def enrich_entity(entity_id: str, value: str) -> List[dict]:
    """
    Enrich an entity with additional context.

    This function fetches enrichment data from an external API
    and converts it to STIX objects.

    Args:
        entity_id: STIX ID of the entity to enrich
        value: Value to use for enrichment lookup

    Returns:
        List of STIX objects containing enrichment data

    Raises:
        ValueError: If entity_id is invalid
        ConnectionError: If API request fails
    """
    pass
```

---

## Linting with Pylint

### Pylint Configuration

All connectors must pass pylint with the repository's `.pylintrc` configuration.

### Custom STIX Plugin

The repository includes a custom pylint plugin that ensures STIX objects are created with deterministic IDs.

#### Installation

```bash
cd shared/pylint_plugins/check_stix_plugin
pip install -r requirements.txt
```

#### Running Pylint

```bash
# Full lint check
cd shared/pylint_plugins/check_stix_plugin
PYTHONPATH=. python -m pylint <path_to_connector> --load-plugins linter_stix_id_generator
```

#### Custom Plugin Only

```bash
cd shared/pylint_plugins/check_stix_plugin
PYTHONPATH=. python -m pylint <path_to_connector> \
    --disable=all \
    --enable=no_generated_id_stix,no-value-for-parameter,unused-import \
    --load-plugins linter_stix_id_generator
```

### Common Pylint Issues

#### no_generated_id_stix

**Problem:** Creating STIX objects without deterministic IDs

```python
# Bad - stix2 auto-generates non-deterministic ID
indicator = stix2.Indicator(
    name="Malicious IP",
    pattern="[ipv4-addr:value = '192.0.2.1']",
)
```

**Solution:** Use connectors-sdk or generate ID with pycti

```python
# Good - using connectors-sdk (recommended)
from connectors_sdk.models import Indicator

indicator = Indicator(
    name="Malicious IP",
    pattern="[ipv4-addr:value = '192.0.2.1']",
    pattern_type="stix",
    valid_from="2026-01-14T00:00:00Z",
)
stix_indicator = indicator.to_stix2_object()

# Good - using pycti to generate deterministic ID
from pycti import Indicator
import stix2

indicator_id = Indicator.generate_id("[ipv4-addr:value = '192.0.2.1']")
indicator = stix2.Indicator(
    id=indicator_id,
    name="Malicious IP",
    pattern="[ipv4-addr:value = '192.0.2.1']",
)
```

### Pre-commit Hooks

Consider using pre-commit hooks:

**File:** `.pre-commit-config.yaml`

```yaml
repos:
  - repo: https://github.com/psf/black
    rev: 23.12.1
    hooks:
      - id: black
        language_version: python3.11

  - repo: https://github.com/PyCQA/isort
    rev: 5.13.2
    hooks:
      - id: isort
        args: ["--profile", "black"]

  - repo: https://github.com/PyCQA/pylint
    rev: v3.0.3
    hooks:
      - id: pylint
        args: ["--load-plugins=linter_stix_id_generator"]
```

---

## STIX 2.1 Compliance

### Using Connectors SDK

**Always use connectors-sdk for STIX object creation** (preferred method):

```python
from connectors_sdk.models import (
    Indicator,
    IPV4Address,
    OrganizationAuthor,
    TLPMarking,
)
from connectors_sdk.models.octi import related_to

# Create objects
author = OrganizationAuthor(name="My Source")
tlp = TLPMarking(level="amber")

indicator = Indicator(
    name="Malicious IP",
    pattern="[ipv4-addr:value = '192.0.2.1']",
    pattern_type="stix",
    valid_from="2026-01-14T00:00:00Z",
    author=author,
    markings=[tlp],
)

ip = IPV4Address(
    value="192.0.2.1",
    author=author,
    markings=[tlp],
)

# Create relationship
relationship = indicator | related_to | ip

# Convert to STIX
stix_objects = [
    author.to_stix2_object(),
    tlp.to_stix2_object(),
    indicator.to_stix2_object(),
    ip.to_stix2_object(),
    relationship.to_stix2_object(),
]
```

### STIX 2.1 Validation

Ensure all STIX objects:

1. **Have deterministic IDs** - Never use auto-generated IDs
2. **Include required properties** - According to STIX 2.1 spec
3. **Use correct object types** - Valid STIX 2.1 types
4. **Have proper relationships** - Valid relationship types
5. **Include markings** - TLP or other appropriate markings

### Common STIX Patterns

#### Observable Pattern

```python
# IPv4 Address
pattern = "[ipv4-addr:value = '192.0.2.1']"

# Domain Name
pattern = "[domain-name:value = 'evil.com']"

# File Hash (MD5)
pattern = "[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']"

# URL
pattern = "[url:value = 'http://evil.com/malware.exe']"

# Email Address
pattern = "[email-addr:value = 'attacker@evil.com']"

# Combined Pattern
pattern = "[ipv4-addr:value = '192.0.2.1'] AND [network-traffic:dst_port = 443]"
```

### Relationship Types

Use valid STIX relationship types:

- `related-to` - Generic relationship
- `indicates` - Indicator indicates malware/threat-actor
- `attributed-to` - Attack attributed to threat actor
- `targets` - Campaign targets organization
- `uses` - Threat actor uses malware/tool
- `mitigates` - Course of action mitigates vulnerability
- `originates-from` - Observable originates from location

---

## Testing Requirements

### Test Framework

Use **pytest** for testing:

**File:** `tests/test-requirements.txt`

```text
pytest>=7.4.0
pytest-cov>=4.1.0
responses>=0.23.0
faker>=20.0.0
```

### Test Structure

```
tests/
├── conftest.py                 # Shared fixtures
├── test_main.py                # Main entry point tests
├── test_connector/
│   ├── test_connector.py       # Connector logic tests
│   ├── test_converter.py       # STIX conversion tests
│   └── test_settings.py        # Configuration tests
└── test_client/
    └── test_api_client.py      # External API client tests
```

### Configuration Tests

**File:** `tests/test_connector/test_settings.py`

```python
import pytest
from pydantic import ValidationError

from connector.settings import ConnectorSettings


def test_valid_configuration():
    """Test valid configuration loads successfully."""
    config = ConnectorSettings()
    assert config.connector.name is not None
    assert config.my_connector.api_base_url is not None


def test_invalid_api_url():
    """Test that invalid URL raises validation error."""
    import os

    os.environ["MY_CONNECTOR_API_BASE_URL"] = "not-a-url"

    with pytest.raises(ValidationError):
        ConnectorSettings()


def test_default_values():
    """Test that default values are set correctly."""
    config = ConnectorSettings()
    assert config.my_connector.max_tlp_level == "amber"
```

### Unit Tests

**File:** `tests/test_connector/test_converter.py`

```python
import pytest
from connector.converter_to_stix import ConverterToStix


@pytest.fixture
def converter(mock_helper):
    """Create converter instance."""
    return ConverterToStix(
        helper=mock_helper,
        tlp_level="green"
    )


def test_create_indicator(converter):
    """Test indicator creation."""
    indicator = converter.create_indicator(
        name="Test Indicator",
        pattern="[ipv4-addr:value = '192.0.2.1']",
        pattern_type="stix",
    )

    assert indicator["type"] == "indicator"
    assert indicator["name"] == "Test Indicator"
    assert "id" in indicator
    assert indicator["id"].startswith("indicator--")


def test_create_observable(converter):
    """Test observable creation."""
    observable = converter.create_ipv4_observable("192.0.2.1")

    assert observable["type"] == "ipv4-addr"
    assert observable["value"] == "192.0.2.1"
    assert "id" in observable
```

### Integration Tests

**File:** `tests/test_connector/test_connector.py`

```python
import pytest
import responses

from connector import MyConnector
from connector.settings import ConnectorSettings


@pytest.fixture
def connector(mock_helper, test_config):
    """Create connector instance."""
    config = ConnectorSettings()
    return MyConnector(config=config, helper=mock_helper)


@responses.activate
def test_collect_intelligence(connector):
    """Test intelligence collection."""
    # Mock API response
    responses.add(
        responses.GET,
        "https://api.example.com/threats",
        json={"items": [{"id": "1", "value": "192.0.2.1"}]},
        status=200
    )

    # Collect intelligence
    stix_objects = connector._collect_intelligence()

    # Verify results
    assert len(stix_objects) > 0
    assert any(obj["type"] == "ipv4-addr" for obj in stix_objects)
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html --cov-report=term

# Run specific test file
pytest tests/test_connector/test_settings.py

# Run with verbose output
pytest -v

# Run with debug output
pytest -s
```

### Coverage Requirements

- Focus on critical paths and error handling
- Test configuration validation thoroughly

---

## Docker Standards

### Dockerfile Standards

**File:** `Dockerfile`

```dockerfile
FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-cisa-known-exploited-vulnerabilities
WORKDIR /opt/opencti-connector-cisa-known-exploited-vulnerabilities

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-cisa-known-exploited-vulnerabilities && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

CMD ["python", "main.py"]
```

Example with entrypoint.sh

```dockerfile
FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-template

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-template && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
```


### Dockerfile Best Practices

1. **Use alpine base image** - Smaller size, better security
2. **Minimize layers** - Combine RUN commands
3. **Clean up** - Remove build dependencies after installation
4. **Use specific versions** - `python:3.12-alpine` not `python:alpine`
5. **Don't run as root** - Add non-root user if possible
6. **Use .dockerignore** - Exclude unnecessary files

### .dockerignore

**File:** `.dockerignore`

```
**/logs
**/*.gql
**/venv
**/.venv
**/__pycache__/
**/*.egg-info/
**/config.yml
**/__pycache__
**/__metadata__
**/__docs__
```

### Docker Compose Configuration

**File:** `docker-compose.yml`

```yaml
version: '3'
services:
  connector-my-connector:
    build: .
    image: opencti/connector-my-connector:latest
    environment:
      - OPENCTI_URL=http://localhost
      - OPENCTI_TOKEN=${OPENCTI_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_ID}
      - CONNECTOR_NAME=My Connector
      - CONNECTOR_SCOPE=indicator,observable
      - CONNECTOR_LOG_LEVEL=info
      - CONNECTOR_DURATION_PERIOD=PT1H
      - MY_CONNECTOR_API_BASE_URL=https://api.example.com
      - MY_CONNECTOR_API_KEY=${MY_CONNECTOR_API_KEY}
    restart: unless-stopped
    networks:
      - default

networks:
  default:
    external: true
    name: docker_default
```

### Environment Variables Documentation

Document all environment variables in README.md:

| Variable               | Description             | Default                 | Required |
| ---------------------- | ----------------------- | ----------------------- | -------- |
| `OPENCTI_URL`          | OpenCTI platform URL    | `http://localhost:8080` | Yes      |
| `OPENCTI_TOKEN`        | OpenCTI API token       | -                       | Yes      |
| `CONNECTOR_ID`         | Unique connector ID     | -                       | Yes      |
| `CONNECTOR_NAME`       | Connector name          | -                       | Yes      |
| `CONNECTOR_SCOPE`      | Entity types to process | -                       | Yes      |
| `MY_CONNECTOR_API_KEY` | External API key        | -                       | Yes      |

---

## Documentation Standards

### README.md Structure

Every connector must have a comprehensive README:

```markdown
# My Connector

Brief description of what the connector does.

## Description

Detailed description of the connector's functionality, data sources,
and integration capabilities.

## Requirements

- OpenCTI Platform >= 6.8.12
- External API account (if applicable)
- API credentials

## Configuration

### Docker

\```yaml
environment:
  - OPENCTI_URL=http://opencti:8080
  - OPENCTI_TOKEN=ChangeMe
  - CONNECTOR_ID=ChangeMe
  - MY_CONNECTOR_API_KEY=ChangeMe
\```

### Local

\```yaml
opencti:
  url: 'http://localhost:8080'
  token: 'ChangeMe'

connector:
  id: 'ChangeMe'
  name: 'My Connector'

my_connector:
  api_key: 'ChangeMe'
\```

## Installation

### Docker

\```bash
docker compose up -d
\```

### Local

\```bash
python3 -m venv venv
source venv/bin/activate
cd src
pip install -r requirements.txt
python main.py
\```

## Configuration Parameters

| Parameter | Description | Default | Required |
| --------- | ----------- | ------- | -------- |
| ...       | ...         | ...     | ...      |

## Behavior

Describe how the connector behaves, what it does, when it runs, etc.

## Troubleshooting

### Common Issues

1. **Issue**: Description
   **Solution**: How to fix

## Additional Resources

- [External API Documentation](https://...)
- [OpenCTI Documentation](https://docs.opencti.io)
```

### Inline Documentation

```python
class MyConnector:
    """
    Main connector class for My Connector.

    This connector integrates with External Service to import
    threat intelligence data into OpenCTI.

    Attributes:
        config: Connector configuration settings
        helper: OpenCTI connector helper
        client: External API client
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        Initialize the connector.

        Args:
            config: Validated configuration settings
            helper: OpenCTI connector helper instance
        """
        self.config = config
        self.helper = helper
        # ... initialization code
```

---

## Security Best Practices

### Secrets Management

**Never commit secrets to the repository:**

```python
# Bad - hardcoded credentials
API_KEY = "abc123xyz"

# Good - from environment/config
api_key = os.getenv("MY_CONNECTOR_API_KEY")
api_key = self.config.my_connector.api_key
```

### Input Validation

```python
def process_entity(self, entity_value: str) -> None:
    """Process entity with input validation."""
    # Validate input
    if not entity_value or len(entity_value) > 1000:
        raise ValueError("Invalid entity value")

    # Sanitize input
    entity_value = entity_value.strip()

    # Process...
```

### API Security

```python
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

def create_session() -> requests.Session:
    """Create secure HTTP session with retry logic."""
    session = requests.Session()

    # Configure retries
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Set timeout
    session.timeout = 30

    return session
```

### TLP Handling

```python
def check_tlp_access(self, entity_tlp: str, max_tlp: str) -> bool:
    """
    Verify connector has access to entity based on TLP.

    Args:
        entity_tlp: Entity's TLP marking
        max_tlp: Maximum TLP level for connector

    Returns:
        True if access allowed, False otherwise
    """
    return self.helper.check_max_tlp(entity_tlp, max_tlp)
```

---

## Performance Guidelines

### Efficient Data Processing

```python
def process_large_dataset(self, data: List[dict]) -> List[dict]:
    """Process large dataset efficiently."""
    stix_objects = []

    # Process in batches
    batch_size = 100
    for i in range(0, len(data), batch_size):
        batch = data[i:i + batch_size]

        # Process batch
        for item in batch:
            stix_obj = self.convert_to_stix(item)
            stix_objects.append(stix_obj)

        # Allow other operations
        if i % 1000 == 0:
            self.helper.connector_logger.info(
                f"Processed {i} items"
            )

    return stix_objects
```

### Memory Management

```python
def stream_large_file(self, file_path: str) -> None:
    """Process large file without loading entirely into memory."""
    with open(file_path, 'r') as f:
        for line in f:
            # Process line by line
            item = json.loads(line)
            self.process_item(item)
```

### Caching

```python
from functools import lru_cache

class MyConnector:
    @lru_cache(maxsize=1000)
    def lookup_entity(self, entity_id: str) -> dict:
        """
        Lookup entity with caching.

        Results are cached to avoid repeated API calls.
        """
        return self.client.get_entity(entity_id)
```

---

## Metadata Requirements

### Connector Manifest

**File:** `__metadata__/connector_manifest.json`

```json
{
  "title": "My Connector",
  "slug": "my-connector",
  "description": "Full description of what the connector does",
  "short_description": "Brief one-line summary",
  "logo": "external-import/my-connector/__metadata__/logo.png",
  "use_cases": ["Open Source Threat Intel", "Commercial Threat Feed"],
  "verified": false,
  "last_verified_date": null,
  "playbook_supported": false,
  "max_confidence_level": 75,
  "support_version": ">=6.8.12",
  "subscription_link": "https://example.com/subscribe",
  "source_code": "https://github.com/OpenCTI-Platform/connectors/tree/master/external-import/my-connector",
  "manager_supported": false,
  "container_version": "rolling",
  "container_image": "opencti/connector-my-connector",
  "container_type": "EXTERNAL_IMPORT"
}
```

### Metadata Fields

| Field                  | Description                              | Required |
| ---------------------- | ---------------------------------------- | -------- |
| `title`                | Official connector name                  | Yes      |
| `slug`                 | Directory name                           | No       |
| `description`          | Detailed description                     | Yes      |
| `short_description`    | Brief summary                            | Yes      |
| `logo`                 | Path to logo (or null)                   | No       |
| `use_cases`            | List of use cases                        | No       |
| `verified`             | Verification status (set by maintainers) | No       |
| `playbook_supported`   | Playbook compatibility (enrichment only) | No       |
| `max_confidence_level` | Maximum confidence score (0-100)         | No       |
| `support_version`      | Minimum OpenCTI version                  | No       |
| `subscription_link`    | Link to service subscription             | No       |
| `source_code`          | GitHub source URL                        | No       |
| `container_image`      | Docker image name                        | Yes      |
| `container_type`       | Connector type                           | Yes      |

### Logo Requirements

- **Format**: PNG
- **Size**: 256x256 pixels recommended
- **Location**: `__metadata__/logo.png`
- **Optional**: Set to `null` if no logo

---

## Checklist Before Submission

Before submitting your connector:

- [ ] Code formatted with Black and isort
- [ ] Passes pylint with custom STIX plugin
- [ ] All STIX objects use deterministic IDs
- [ ] Unit tests written and passing
- [ ] Test coverage >= 70%
- [ ] README.md complete with all sections
- [ ] Dockerfile follows best practices
- [ ] docker-compose.yml configured correctly
- [ ] connector_manifest.json complete and accurate
- [ ] No hardcoded secrets or credentials
- [ ] Logging uses structured format
- [ ] Error handling implemented
- [ ] Type hints on all functions
- [ ] Docstrings on public methods
- [ ] Configuration validation with Pydantic
- [ ] Works with Docker deployment
- [ ] Works with local deployment
- [ ] Tested with real OpenCTI instance

---

## Resources

- **Black**: [https://black.readthedocs.io](https://black.readthedocs.io)
- **isort**: [https://pycqa.github.io/isort](https://pycqa.github.io/isort)
- **Pylint**: [https://pylint.pycqa.org](https://pylint.pycqa.org)
- **pytest**: [https://docs.pytest.org](https://docs.pytest.org)
- **STIX 2.1 Spec**: [https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
- **Docker Best Practices**: [https://docs.docker.com/develop/dev-best-practices](https://docs.docker.com/develop/dev-best-practices)
