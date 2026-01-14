# Common Implementation Guidelines

**Document:** 01-common-implementation.md
**Applies to:** All connector types (External Import, Internal Enrichment, Stream)

## Table of Contents

- [Environment Setup](#environment-setup)
- [Directory Structure](#directory-structure)
- [Configuration Management](#configuration-management)
- [Using the Connectors SDK](#using-the-connectors-sdk)
- [STIX 2.1 Object Creation](#stix-21-object-creation)
- [Logging Best Practices](#logging-best-practices)
- [State Management](#state-management)
- [Error Handling](#error-handling)
- [Working with the Helper](#working-with-the-helper)

---

## Environment Setup

### Docker Environment

Docker is the recommended approach for production deployments and integration testing.

#### Prerequisites

1. **Install Docker and Docker Compose**
2. **Clone the OpenCTI Docker deployment**:

```bash
git clone https://github.com/OpenCTI-Platform/docker
cd docker
```

3. **Create environment file** with credentials:

```bash
cat << EOF > .env
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=ChangeMePlease
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
ELASTIC_MEMORY_SIZE=4G
CONNECTOR_HISTORY_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_CSV_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_REPORT_ID=$(cat /proc/sys/kernel/random/uuid)
EOF
```

4. **Start OpenCTI**:

```bash
docker compose up -d
```

#### Docker Networking

When OpenCTI is deployed in a folder named `docker`, a network called `docker_default` is created. Your connector must attach to this network to communicate with OpenCTI services.

In your connector's `docker-compose.yml`:

```yaml
version: '3'
services:
  connector-my-connector:
    image: opencti/connector-my-connector:latest
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
      - CONNECTOR_ID=${CONNECTOR_ID}
      - CONNECTOR_NAME=My Connector
      # Additional connector-specific variables
    networks:
      - default
    restart: unless-stopped

networks:
  default:
    external: true
    name: docker_default
```

#### Running Your Connector with Docker

```bash
cd external-import/my-connector
docker compose up --build
```

### Local Environment

Local development provides faster iteration and easier debugging.

#### Setup Steps

1. **Create a virtual environment**:

```bash
cd external-import/my-connector
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install dependencies**:

```bash
cd src
pip install -r requirements.txt
```

3. **Create configuration file**:

```bash
cp config.yml.sample config.yml
```

4. **Edit `config.yml`** with your OpenCTI connection details:

```yaml
opencti:
  url: 'http://localhost:8080'
  token: 'your-opencti-token'

connector:
  id: 'unique-connector-id'  # Generate with: uuidgen
  name: 'My Connector'
  scope: 'indicator'
  log_level: 'info'
  duration_period: 'PT10M'  # For external import connectors

my_connector:
  api_base_url: 'https://api.example.com'
  api_key: 'your-api-key'
```

5. **Run the connector**:

```bash
python main.py
```

---

## Directory Structure

All connectors follow this standardized structure:

```
my-connector/
├── __metadata__/
│   ├── connector_manifest.json
│   └── logo.png (optional)
├── src/
│   ├── connector/
│   │   ├── __init__.py
│   │   ├── connector.py
│   │   ├── converter_to_stix.py
│   │   ├── settings.py
│   │   └── utils.py
│   ├── my_client/
│   │   ├── __init__.py
│   │   └── api_client.py
│   ├── main.py
│   └── requirements.txt
├── tests/
│   ├── test_connector/
│   │   └── test_settings.py
│   ├── conftest.py
│   ├── test_main.py
│   └── test-requirements.txt
├── config.yml.sample
├── docker-compose.yml
├── Dockerfile
├── entrypoint.sh
└── README.md
```

### File Descriptions

| File/Directory | Purpose |
|----------------|---------|
| `__metadata__/` | Contains metadata for connector catalog and documentation |
| `connector_manifest.json` | Connector information, version, capabilities |
| `src/connector/connector.py` | Main connector logic and processing |
| `src/connector/converter_to_stix.py` | STIX object creation and conversion |
| `src/connector/settings.py` | Configuration models with Pydantic validation |
| `src/connector/utils.py` | Utility functions and helpers |
| `src/my_client/api_client.py` | External API client implementation |
| `src/main.py` | Entry point, initializes connector |
| `tests/` | Unit and integration tests |
| `config.yml.sample` | Sample configuration for users |
| `Dockerfile` | Container image definition |
| `docker-compose.yml` | Docker Compose service definition |

---

## Configuration Management

All connectors use **Pydantic** for configuration validation through the connectors-sdk.

### Configuration Structure

Configuration is organized into three sections:

1. **OpenCTI Connection** (`opencti`)
2. **Connector Settings** (`connector`)
3. **Connector-Specific Settings** (custom section)

### Defining Configuration with Pydantic

**File:** `src/connector/settings.py`

```python
from datetime import timedelta
from typing import Literal

from connectors_sdk import (
    BaseConfigModel,
    BaseConnectorSettings,
    BaseExternalImportConnectorConfig,
)
from pydantic import Field, HttpUrl


class ExternalImportConnectorConfig(BaseExternalImportConnectorConfig):
    """
    Override the BaseExternalImportConnectorConfig to add parameters
    and/or defaults specific to external import connectors.
    """
    name: str = Field(
        description="The name of the connector.",
        default="MyConnector",
    )
    duration_period: timedelta = Field(
        description="The period of time to await between two runs.",
        default=timedelta(hours=1),
    )


class MyConnectorConfig(BaseConfigModel):
    """
    Define parameters specific to your connector.
    """
    api_base_url: HttpUrl = Field(
        description="API base URL for the external service."
    )
    api_key: str = Field(
        description="API key for authentication."
    )
    max_tlp_level: Literal["clear", "white", "green", "amber", "red"] = Field(
        description="Maximum TLP level to process.",
        default="amber",
    )
    import_from_date: str = Field(
        description="Import data from this date (YYYY-MM-DD).",
        default="2024-01-01",
    )


class ConnectorSettings(BaseConnectorSettings):
    """
    Main settings class that combines all configuration sections.
    """
    connector: ExternalImportConnectorConfig = Field(
        default_factory=ExternalImportConnectorConfig
    )
    my_connector: MyConnectorConfig = Field(
        default_factory=MyConnectorConfig
    )
```

### Configuration File Format

**File:** `config.yml`

```yaml
opencti:
  url: 'http://localhost:8080'
  token: 'ChangeMe'

connector:
  id: 'ChangeMe'
  name: 'My Connector'
  scope: 'indicator,vulnerability'
  log_level: 'info'
  duration_period: 'PT1H'

my_connector:
  api_base_url: 'https://api.example.com'
  api_key: 'ChangeMe'
  max_tlp_level: 'amber'
  import_from_date: '2024-01-01'
```

### Environment Variables

Configuration can also be provided via environment variables (useful for Docker):

```bash
OPENCTI_URL=http://opencti:8080
OPENCTI_TOKEN=your-token
CONNECTOR_ID=unique-id
CONNECTOR_NAME=My Connector
CONNECTOR_SCOPE=indicator,vulnerability
CONNECTOR_LOG_LEVEL=info
CONNECTOR_DURATION_PERIOD=PT1H
MY_CONNECTOR_API_BASE_URL=https://api.example.com
MY_CONNECTOR_API_KEY=your-api-key
MY_CONNECTOR_MAX_TLP_LEVEL=amber
MY_CONNECTOR_IMPORT_FROM_DATE=2024-01-01
```

**Naming Convention:**
- Section name + field name in UPPERCASE
- Separate with underscores
- Example: `my_connector.api_base_url` → `MY_CONNECTOR_API_BASE_URL`

### Loading Configuration

**File:** `src/main.py`

```python
from connector import MyConnector
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper


if __name__ == "__main__":
    try:
        # Load and validate configuration
        settings = ConnectorSettings()

        # Initialize the connector helper
        helper = OpenCTIConnectorHelper(settings.model_dump())

        # Initialize and run the connector
        connector = MyConnector(config=settings, helper=helper)
        connector.run()

    except Exception as e:
        print(f"Failed to start connector: {e}")
        raise
```

---

## Using the Connectors SDK

The **connectors-sdk** simplifies STIX object creation and ensures compliance.

### Installation

Add to `requirements.txt`:

```text
connectors-sdk @ git+https://github.com/OpenCTI-Platform/connectors.git@master#subdirectory=connectors-sdk
```

### Benefits

- **Type-safe models** for STIX objects
- **Automatic ID generation** (deterministic)
- **Built-in validation** for STIX 2.1 compliance
- **OpenCTI custom properties** support
- **Relationship helpers** for linking objects

### Available Models

Common models include:

**Identity/Author:**
- `OrganizationAuthor`
- `IndividualAuthor`
- `SystemAuthor`

**Observable:**
- `IPV4Address`
- `IPV6Address`
- `DomainName`
- `URL`
- `EmailAddress`
- `FileHash`

**Indicator:**
- `Indicator`

**Threat Actor & Intrusion Set:**
- `ThreatActor`
- `IntrusionSet`

**Malware & Tool:**
- `Malware`
- `Tool`

**Vulnerability:**
- `Vulnerability`

**Marking:**
- `TLPMarking`
- `StatementMarking`

### Basic Usage Example

```python
from connectors_sdk.models import (
    IPV4Address,
    Indicator,
    OrganizationAuthor,
    TLPMarking,
    Vulnerability,
)
from connectors_sdk.models.octi import related_to

# Create author
author = OrganizationAuthor(name="My Threat Feed")

# Create TLP marking
tlp_green = TLPMarking(level="green")

# Create observable
ip = IPV4Address(
    value="192.0.2.1",
    author=author,
    markings=[tlp_green],
)

# Create indicator
indicator = Indicator(
    name="Malicious IP",
    pattern="[ipv4-addr:value = '192.0.2.1']",
    pattern_type="stix",
    valid_from="2026-01-14T00:00:00Z",
    labels=["malicious-activity"],
    author=author,
    markings=[tlp_green],
    score=85,
)

# Create vulnerability
vuln = Vulnerability(
    name="CVE-2024-1234",
    description="Critical vulnerability in Example Software",
    author=author,
    markings=[tlp_green],
)

# Create relationship
relationship = ip | related_to | vuln

# Convert to STIX objects
stix_objects = [
    author.to_stix2_object(),
    tlp_green.to_stix2_object(),
    ip.to_stix2_object(),
    indicator.to_stix2_object(),
    vuln.to_stix2_object(),
    relationship.to_stix2_object(),
]
```

---

## STIX 2.1 Object Creation

### Using Connectors SDK (Recommended)

Always use the connectors-sdk for creating STIX objects:

```python
from connectors_sdk.models import Indicator, OrganizationAuthor, TLPMarking

author = OrganizationAuthor(name="Example Source")
tlp = TLPMarking(level="amber")

indicator = Indicator(
    # ID is automatically generated
    name="Malicious domain",
    pattern="[domain-name:value = 'evil.com']",
    pattern_type="stix",
    valid_from="2026-01-14T00:00:00Z",
    labels=["phishing"],
    author=author,
    markings=[tlp],
    score=70,
)

stix_object = indicator.to_stix2_object()
```

### Legacy Method (Deprecated)

If you must use the legacy stix2 library:

```python
import stix2
from pycti import Indicator

# Generate deterministic ID
indicator_id = Indicator.generate_id("[domain-name:value = 'evil.com']")

indicator = stix2.Indicator(
    id=indicator_id,
    name="Malicious domain",
    pattern="[domain-name:value = 'evil.com']",
    pattern_type="stix",
    valid_from="2026-01-14T00:00:00Z",
)
```

**⚠️ Warning:** Always generate IDs using `pycti` helper methods. Never let stix2 auto-generate IDs as they won't be deterministic.

### Creating Relationships

Use the relationship helper from connectors-sdk:

```python
from connectors_sdk.models.octi import related_to, indicates

# Observable related to vulnerability
relationship1 = ip | related_to | vuln

# Indicator indicates malware
relationship2 = indicator | indicates | malware
```

---

## Logging Best Practices

### Using the Connector Logger

Always use `self.helper.connector_logger`:

```python
# Info level - general information
self.helper.connector_logger.info(
    "Starting data collection",
    {"source": "api.example.com"}
)

# Debug level - detailed information for debugging
self.helper.connector_logger.debug(
    "API response received",
    {"status_code": 200, "items": 42}
)

# Warning level - something unexpected but not fatal
self.helper.connector_logger.warning(
    "Rate limit approaching",
    {"remaining": 10, "reset_time": reset_time}
)

# Error level - errors that prevent processing
self.helper.connector_logger.error(
    "Failed to fetch data",
    {"error": str(e), "url": url}
)
```

### Log Levels

Set via `CONNECTOR_LOG_LEVEL` environment variable or `connector.log_level` in config:

- `debug` - Verbose output for development
- `info` - General operational messages (recommended)
- `warning` - Unexpected situations
- `error` - Errors that prevent operation

### Structured Logging

Always pass context as a dictionary:

```python
# Good - structured
self.helper.connector_logger.info(
    "Processing entity",
    {"entity_id": entity_id, "entity_type": entity_type}
)

# Bad - string concatenation
self.helper.connector_logger.info(
    f"Processing entity {entity_id} of type {entity_type}"
)
```

---

## State Management

Connectors can persist state between runs to track progress.

### Getting Current State

```python
current_state = self.helper.get_state()

if current_state is None:
    # First run
    current_state = {"last_run": None}
```

### Updating State

```python
from datetime import datetime, timezone

now = datetime.now(timezone.utc)
current_timestamp = int(now.timestamp())

# Update state
new_state = {
    "last_run": now.strftime("%Y-%m-%d %H:%M:%S"),
    "last_timestamp": current_timestamp,
    "items_processed": 42,
}

self.helper.set_state(new_state)
```

### State Use Cases

- **Last run timestamp** - For incremental imports
- **Cursor/pagination** - Resume from last position
- **Processing markers** - Track what's been processed
- **Rate limit tracking** - Monitor API usage

### Example: Incremental Import

```python
def process_message(self):
    current_state = self.helper.get_state()

    # Determine start date
    if current_state and "last_run" in current_state:
        start_date = current_state["last_run"]
        self.helper.connector_logger.info(
            "Resuming from last run",
            {"start_date": start_date}
        )
    else:
        start_date = self.config.my_connector.import_from_date
        self.helper.connector_logger.info(
            "First run, starting from",
            {"start_date": start_date}
        )

    # Fetch data since start_date
    data = self.client.get_data(since=start_date)

    # Process data...

    # Update state
    self.helper.set_state({
        "last_run": datetime.now(timezone.utc).isoformat()
    })
```

---

## Error Handling

### Exception Handling Pattern

```python
def process_message(self, data: dict) -> str:
    try:
        # Main processing logic
        result = self._process_data(data)
        return f"Successfully processed {result}"

    except KeyError as e:
        # Handle missing data
        self.helper.connector_logger.error(
            "Missing required field",
            {"error": str(e), "data": data}
        )
        return f"Failed: missing field {e}"

    except requests.exceptions.RequestException as e:
        # Handle API errors
        self.helper.connector_logger.error(
            "API request failed",
            {"error": str(e)}
        )
        return f"Failed: API error {e}"

    except Exception as e:
        # Catch-all for unexpected errors
        self.helper.connector_logger.error(
            "Unexpected error",
            {"error": str(e), "type": type(e).__name__}
        )
        raise  # Re-raise unexpected errors
```

### Graceful Degradation

```python
def enrich_entity(self, entity):
    enrichments = []

    # Try multiple enrichment sources
    try:
        enrichment1 = self.source1.enrich(entity)
        enrichments.append(enrichment1)
    except Exception as e:
        self.helper.connector_logger.warning(
            "Source 1 failed, continuing",
            {"error": str(e)}
        )

    try:
        enrichment2 = self.source2.enrich(entity)
        enrichments.append(enrichment2)
    except Exception as e:
        self.helper.connector_logger.warning(
            "Source 2 failed, continuing",
            {"error": str(e)}
        )

    return enrichments
```

### Retry Logic

```python
import time
from requests.exceptions import RequestException

def fetch_with_retry(self, url, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.json()
        except RequestException as e:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff
                self.helper.connector_logger.warning(
                    f"Request failed, retrying in {wait_time}s",
                    {"attempt": attempt + 1, "error": str(e)}
                )
                time.sleep(wait_time)
            else:
                self.helper.connector_logger.error(
                    "Max retries exceeded",
                    {"url": url, "error": str(e)}
                )
                raise
```

---

## Working with the Helper

The `OpenCTIConnectorHelper` provides essential methods for interacting with OpenCTI.

### Initialization

```python
from pycti import OpenCTIConnectorHelper

helper = OpenCTIConnectorHelper(config.model_dump())
```

### Common Helper Methods

#### Creating and Sending Bundles

```python
# Create bundle from STIX objects
bundle = self.helper.stix2_create_bundle(stix_objects)

# Send bundle to OpenCTI
bundles_sent = self.helper.send_stix2_bundle(
    bundle,
    work_id=work_id,
    cleanup_inconsistent_bundle=True,
)
```

#### Work Management

```python
# Initialize work
work_id = self.helper.api.work.initiate_work(
    self.helper.connect_id,
    "Importing threat feed"
)

# Mark work as completed
self.helper.api.work.to_processed(
    work_id,
    "Successfully imported 42 indicators"
)
```

#### TLP Checking

```python
# Check if entity TLP is within allowed level
is_valid = self.helper.check_max_tlp(
    entity_tlp,
    self.config.my_connector.max_tlp_level
)

if not is_valid:
    self.helper.connector_logger.warning(
        "Entity TLP exceeds maximum allowed level"
    )
    return
```

#### Querying OpenCTI API

```python
# Get entity by ID
entity = self.helper.api.stix_domain_object.read(id=entity_id)

# Search indicators
indicators = self.helper.api.indicator.list(
    filters=[{
        "key": "pattern_type",
        "values": ["stix"]
    }]
)
```

### Helper Properties

| Property | Description |
|----------|-------------|
| `helper.connect_id` | Connector's unique ID |
| `helper.connect_name` | Connector's name |
| `helper.connect_scope` | Connector's scope |
| `helper.connect_live_stream_id` | Stream ID (for stream connectors) |
| `helper.api` | OpenCTI API client |

---

## Next Steps

After understanding these common implementation patterns:

1. **External Import Connectors**: Read [External Import Specifications](./02-external-import-specifications.md)
2. **Internal Enrichment Connectors**: Read [Internal Enrichment Specifications](./03-internal-enrichment-specifications.md)
3. **Stream Connectors**: Read [Stream Connector Specifications](./04-stream-specifications.md)
4. **Code Quality**: Review [Code Quality & Standards](./05-code-quality-standards.md)
