# Stream Connector Specifications

**Document:** 04-stream-specifications.md
**Connector Type:** `STREAM`

## Table of Contents

- [Overview](#overview)
- [Connector Architecture](#connector-architecture)
- [Stream Configuration](#stream-configuration)
- [Event Types](#event-types)
- [Processing Stream Events](#processing-stream-events)
- [Real-Time Synchronization](#real-time-synchronization)
- [Error Handling and Recovery](#error-handling-and-recovery)
- [Filtering and Routing](#filtering-and-routing)
- [Best Practices](#best-practices)
- [Complete Example](#complete-example)

---

## Overview

Stream connectors listen to real-time events from the OpenCTI platform and synchronize changes to external systems (SIEM, ticketing, messaging platforms, etc.).

### Purpose

- Stream OpenCTI data changes to external platforms in real-time
- Maintain bi-directional synchronization
- React to entity creation, updates, and deletions
- Enable event-driven workflows with external systems

### Key Characteristics

- **Real-time**: Processes events as they occur
- **Event-driven**: Reacts to create/update/delete events
- **Stateless**: Each event is processed independently
- **Stream-based**: Uses OpenCTI live streams

### Use Cases

- **SIEM Integration**: Push indicators and observables to security tools
- **Ticketing Systems**: Create/update tickets based on OpenCTI events
- **Messaging Platforms**: Send alerts to Slack, Teams, etc.
- **Data Warehouses**: Sync data to analytics platforms
- **Custom Workflows**: Trigger external automations

---

## Connector Architecture

### Class Structure

```python
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from my_client import MyExternalClient


class MyStreamConnector:
    """
    Stream connector for real-time synchronization.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """Initialize the connector."""
        self.config = config
        self.helper = helper

        # Initialize external system client
        self.client = MyExternalClient(
            self.helper,
            base_url=self.config.my_connector.api_base_url,
            api_key=self.config.my_connector.api_key,
        )

    def check_stream_id(self) -> None:
        """
        Validate that stream ID is configured.
        """
        # Implementation here
        pass

    def process_message(self, msg) -> None:
        """
        Process stream event.
        """
        # Implementation here
        pass

    def run(self) -> None:
        """
        Start listening to the stream.
        """
        self.helper.listen_stream(message_callback=self.process_message)
```

### Required Methods

| Method | Purpose |
|--------|---------|
| `__init__` | Initialize connector and external client |
| `check_stream_id()` | Validate stream ID configuration |
| `process_message()` | Process individual stream events |
| `run()` | Start stream listener |

---

## Stream Configuration

### Creating a Stream

Streams must be created in the OpenCTI UI before using them in a connector:

1. Navigate to **Data → Data Sharing → Live Streams**
2. Click **"Create stream"**
3. Configure:
   - **Name**: Descriptive name (e.g., "SIEM Integration Stream")
   - **Description**: Purpose of the stream
   - **Filters**: Entity types, labels, markings, etc.
4. Copy the **Stream ID**

### Connector Configuration

**File:** `config.yml`

```yaml
opencti:
  url: 'http://localhost:8080'
  token: 'ChangeMe'

connector:
  id: 'unique-connector-id'
  name: 'My Stream Connector'
  scope: 'indicator,observable'  # Entity types to process
  log_level: 'info'
  live_stream_id: 'stream-uuid-from-opencti'  # REQUIRED

my_connector:
  api_base_url: 'https://external-system.com/api'
  api_key: 'your-api-key'
```

**Environment variables:**

```bash
CONNECTOR_LIVE_STREAM_ID=stream-uuid-from-opencti
```

### Validating Stream ID

```python
def check_stream_id(self) -> None:
    """
    Validate that stream ID is configured.

    Raises:
        ValueError: If stream ID is missing or invalid
    """
    if (
        self.helper.connect_live_stream_id is None
        or self.helper.connect_live_stream_id == "ChangeMe"
    ):
        raise ValueError(
            "Missing stream ID. Please configure CONNECTOR_LIVE_STREAM_ID "
            "or connector.live_stream_id in config.yml"
        )

    self.helper.connector_logger.info(
        "Stream ID validated",
        {"stream_id": self.helper.connect_live_stream_id}
    )
```

---

## Event Types

Stream connectors receive three types of events:

### Event Type: Create

Triggered when a new entity is created in OpenCTI.

```python
if msg.event == "create":
    self.helper.connector_logger.info(
        "Entity created",
        {"entity_id": msg.data["id"], "entity_type": msg.data["type"]}
    )

    # Push to external system
    self.client.create_entity(msg.data)
```

### Event Type: Update

Triggered when an existing entity is modified.

```python
if msg.event == "update":
    self.helper.connector_logger.info(
        "Entity updated",
        {"entity_id": msg.data["id"], "entity_type": msg.data["type"]}
    )

    # Update in external system
    self.client.update_entity(msg.data)
```

### Event Type: Delete

Triggered when an entity is deleted from OpenCTI.

```python
if msg.event == "delete":
    self.helper.connector_logger.info(
        "Entity deleted",
        {"entity_id": msg.data["id"]}
    )

    # Delete from external system
    self.client.delete_entity(msg.data["id"])
```

---

## Processing Stream Events

### Message Structure

Stream events have this structure:

```python
msg = {
    "event": "create",  # or "update", "delete"
    "data": {
        "id": "indicator--uuid",
        "type": "indicator",
        "name": "Malicious IP",
        "pattern": "[ipv4-addr:value = '192.0.2.1']",
        "created_at": "2026-01-14T10:00:00.000Z",
        "updated_at": "2026-01-14T10:00:00.000Z",
        "objectMarking": [...],
        "labels": [...],
        # ... additional entity properties
    }
}
```

### Basic Event Processing

```python
def process_message(self, msg) -> None:
    """
    Process stream event.

    Args:
        msg: Stream message containing event type and data
    """
    try:
        # Validate stream ID
        self.check_stream_id()

        # Extract event data
        event_type = msg.event
        entity_data = msg.data
        entity_id = entity_data.get("id")
        entity_type = entity_data.get("type")

        self.helper.connector_logger.info(
            f"Processing {event_type} event",
            {"entity_id": entity_id, "entity_type": entity_type}
        )

        # Route to appropriate handler
        if event_type == "create":
            self._handle_create(entity_data)
        elif event_type == "update":
            self._handle_update(entity_data)
        elif event_type == "delete":
            self._handle_delete(entity_data)
        else:
            self.helper.connector_logger.warning(
                "Unknown event type",
                {"event_type": event_type}
            )

    except Exception as e:
        self.helper.connector_logger.error(
            "Failed to process event",
            {"error": str(e), "event": event_type}
        )
        # Don't raise - continue processing other events
```

### Event Handlers

```python
def _handle_create(self, entity_data: dict) -> None:
    """Handle entity creation."""
    try:
        # Transform data for external system
        external_data = self._transform_entity(entity_data)

        # Push to external system
        result = self.client.create_entity(external_data)

        self.helper.connector_logger.info(
            "Entity created in external system",
            {"entity_id": entity_data["id"], "external_id": result["id"]}
        )

    except Exception as e:
        self.helper.connector_logger.error(
            "Failed to create entity in external system",
            {"entity_id": entity_data["id"], "error": str(e)}
        )

def _handle_update(self, entity_data: dict) -> None:
    """Handle entity update."""
    try:
        external_data = self._transform_entity(entity_data)
        self.client.update_entity(entity_data["id"], external_data)

        self.helper.connector_logger.info(
            "Entity updated in external system",
            {"entity_id": entity_data["id"]}
        )

    except Exception as e:
        self.helper.connector_logger.error(
            "Failed to update entity",
            {"entity_id": entity_data["id"], "error": str(e)}
        )

def _handle_delete(self, entity_data: dict) -> None:
    """Handle entity deletion."""
    try:
        self.client.delete_entity(entity_data["id"])

        self.helper.connector_logger.info(
            "Entity deleted from external system",
            {"entity_id": entity_data["id"]}
        )

    except Exception as e:
        self.helper.connector_logger.error(
            "Failed to delete entity",
            {"entity_id": entity_data["id"], "error": str(e)}
        )
```

---

## Real-Time Synchronization

### Data Transformation

Transform OpenCTI entities to match external system format example:

```python
def _transform_entity(self, entity_data: dict) -> dict:
    """
    Transform OpenCTI entity to external system format.

    Args:
        entity_data: OpenCTI entity data

    Returns:
        Transformed data for external system
    """
    entity_type = entity_data.get("type")

    if entity_type == "indicator":
        return self._transform_indicator(entity_data)
    elif entity_type == "ipv4-addr":
        return self._transform_observable(entity_data)
    elif entity_type == "vulnerability":
        return self._transform_vulnerability(entity_data)
    else:
        # Generic transformation
        return {
            "id": entity_data["id"],
            "type": entity_type,
            "name": entity_data.get("name", ""),
            "description": entity_data.get("description", ""),
            "created": entity_data.get("created_at"),
            "modified": entity_data.get("updated_at"),
        }

def _transform_indicator(self, indicator: dict) -> dict:
    """Transform indicator to external format."""
    return {
        "id": indicator["id"],
        "name": indicator.get("name"),
        "pattern": indicator.get("pattern"),
        "type": indicator.get("pattern_type"),
        "valid_from": indicator.get("valid_from"),
        "valid_until": indicator.get("valid_until"),
        "confidence": indicator.get("confidence"),
        "labels": [label["value"] for label in indicator.get("labels", [])],
        "tlp": self._extract_tlp(indicator),
    }

def _extract_tlp(self, entity: dict) -> str:
    """Extract TLP marking from entity."""
    for marking in entity.get("objectMarking", []):
        if marking.get("definition_type") == "TLP":
            return marking["definition"]
    return "TLP:CLEAR"
```

### Bi-Directional Synchronization

For systems that require bi-directional sync:

```python
class MyStreamConnector:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper
        self.client = MyExternalClient(...)

        # Track mapping between OpenCTI and external IDs
        self.id_mapping = {}

    def _handle_create(self, entity_data: dict) -> None:
        """Create entity and track ID mapping."""
        external_data = self._transform_entity(entity_data)

        # Create in external system
        result = self.client.create_entity(external_data)

        # Store ID mapping for future updates
        opencti_id = entity_data["id"]
        external_id = result["id"]
        self.id_mapping[opencti_id] = external_id

        self.helper.connector_logger.info(
            "Entity synchronized",
            {"opencti_id": opencti_id, "external_id": external_id}
        )

    def _handle_update(self, entity_data: dict) -> None:
        """Update using mapped external ID."""
        opencti_id = entity_data["id"]

        # Get external ID from mapping
        external_id = self.id_mapping.get(opencti_id)

        if not external_id:
            # Not yet synced, treat as create
            self._handle_create(entity_data)
            return

        # Update in external system
        external_data = self._transform_entity(entity_data)
        self.client.update_entity(external_id, external_data)
```

---

## Error Handling and Recovery

### Graceful Error Handling

```python
def process_message(self, msg) -> None:
    """Process event with error recovery."""
    try:
        self.check_stream_id()

        event_type = msg.event
        entity_data = msg.data

        # Process event
        if event_type == "create":
            self._handle_create(entity_data)
        elif event_type == "update":
            self._handle_update(entity_data)
        elif event_type == "delete":
            self._handle_delete(entity_data)

    except ConnectionError as e:
        # Network errors - log and continue
        self.helper.connector_logger.error(
            "Connection error, event will be retried",
            {"error": str(e)}
        )
        # Don't raise - message will be redelivered

    except ValueError as e:
        # Data validation errors - log and skip
        self.helper.connector_logger.error(
            "Invalid data, skipping event",
            {"error": str(e), "entity_id": entity_data.get("id")}
        )
        # Don't raise - skip this message

    except Exception as e:
        # Unexpected errors - log and investigate
        self.helper.connector_logger.error(
            "Unexpected error processing event",
            {"error": str(e), "type": type(e).__name__}
        )
        # Don't raise - continue processing
```

### Retry Logic

```python
import time
from requests.exceptions import RequestException

def _handle_create_with_retry(self, entity_data: dict, max_retries: int = 3) -> None:
    """Create entity with retry logic."""
    for attempt in range(max_retries):
        try:
            external_data = self._transform_entity(entity_data)
            result = self.client.create_entity(external_data)

            self.helper.connector_logger.info(
                "Entity created successfully",
                {"entity_id": entity_data["id"], "attempt": attempt + 1}
            )
            return

        except RequestException as e:
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff
                self.helper.connector_logger.warning(
                    f"Create failed, retrying in {wait_time}s",
                    {"attempt": attempt + 1, "error": str(e)}
                )
                time.sleep(wait_time)
            else:
                self.helper.connector_logger.error(
                    "Max retries exceeded",
                    {"entity_id": entity_data["id"], "error": str(e)}
                )
                raise
```

### Dead Letter Queue

For critical events that must not be lost:

```python
def _handle_failed_event(self, msg, error: Exception) -> None:
    """Store failed events for manual retry."""
    import json
    from datetime import datetime

    failed_event = {
        "timestamp": datetime.now().isoformat(),
        "event_type": msg.event,
        "entity_id": msg.data.get("id"),
        "entity_type": msg.data.get("type"),
        "error": str(error),
        "data": msg.data,
    }

    # Write to file or send to dead letter queue
    with open("failed_events.jsonl", "a") as f:
        f.write(json.dumps(failed_event) + "\n")

    self.helper.connector_logger.error(
        "Event saved to dead letter queue",
        {"entity_id": msg.data.get("id")}
    )
```

---

## Filtering and Routing

### Entity Type Filtering

```python
def process_message(self, msg) -> None:
    """Process with entity type filtering."""
    entity_type = msg.data.get("type")

    # Define supported entity types
    supported_types = ["indicator", "ipv4-addr", "ipv6-addr", "domain-name"]

    if entity_type not in supported_types:
        self.helper.connector_logger.debug(
            "Skipping unsupported entity type",
            {"entity_type": entity_type}
        )
        return

    # Process supported types
    if msg.event == "create":
        self._handle_create(msg.data)
    # ... other event handlers
```

### TLP-Based Routing

```python
def process_message(self, msg) -> None:
    """Route events based on TLP marking."""
    entity_data = msg.data

    # Extract TLP
    tlp = self._extract_tlp(entity_data)

    # Route based on TLP
    if tlp in ["TLP:RED", "TLP:AMBER+STRICT"]:
        self.helper.connector_logger.info(
            "High-sensitivity entity, sending to secure channel",
            {"tlp": tlp}
        )
        self._send_to_secure_channel(entity_data)

    elif tlp in ["TLP:AMBER", "TLP:GREEN"]:
        self.helper.connector_logger.info(
            "Standard entity, sending to normal channel",
            {"tlp": tlp}
        )
        self._send_to_normal_channel(entity_data)

    else:  # TLP:CLEAR / TLP:WHITE
        self.helper.connector_logger.info(
            "Public entity, sending to all channels",
            {"tlp": tlp}
        )
        self._send_to_all_channels(entity_data)
```

### Label-Based Filtering

```python
def process_message(self, msg) -> None:
    """Filter events by labels."""
    entity_data = msg.data

    # Extract labels
    labels = [label["value"] for label in entity_data.get("labels", [])]

    # Only process entities with specific labels
    required_labels = self.config.my_connector.required_labels

    if not any(label in required_labels for label in labels):
        self.helper.connector_logger.debug(
            "Entity does not have required labels, skipping",
            {"labels": labels, "required": required_labels}
        )
        return

    # Process entity
    if msg.event == "create":
        self._handle_create(entity_data)
```

---

## Best Practices

### 1. Idempotent Operations

Ensure operations can be safely retried:

```python
def _handle_create(self, entity_data: dict) -> None:
    """Idempotent create operation."""
    entity_id = entity_data["id"]

    # Check if entity already exists in external system
    existing = self.client.get_entity_by_opencti_id(entity_id)

    if existing:
        self.helper.connector_logger.info(
            "Entity already exists, updating instead",
            {"entity_id": entity_id}
        )
        self._handle_update(entity_data)
        return

    # Create new entity
    external_data = self._transform_entity(entity_data)
    self.client.create_entity(external_data)
```

### 2. Batch Processing

For high-volume streams:

```python
class MyStreamConnector:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper
        self.client = MyExternalClient(...)

        # Batch buffer
        self.batch = []
        self.batch_size = 100
        self.last_flush = time.time()
        self.flush_interval = 30  # seconds

    def process_message(self, msg) -> None:
        """Add event to batch."""
        self.batch.append(msg)

        # Flush if batch is full or interval elapsed
        if len(self.batch) >= self.batch_size or \
           time.time() - self.last_flush >= self.flush_interval:
            self._flush_batch()

    def _flush_batch(self) -> None:
        """Process batched events."""
        if not self.batch:
            return

        self.helper.connector_logger.info(
            "Flushing batch",
            {"batch_size": len(self.batch)}
        )

        # Process batch
        for msg in self.batch:
            try:
                self._process_single_event(msg)
            except Exception as e:
                self.helper.connector_logger.error(
                    "Failed to process event",
                    {"error": str(e)}
                )

        # Clear batch
        self.batch = []
        self.last_flush = time.time()
```

### 3. Rate Limiting

```python
class MyStreamConnector:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper
        self.client = MyExternalClient(...)

        # Rate limiting
        self.request_tokens = 100
        self.token_refill_rate = 10  # tokens per second
        self.last_refill = time.time()

    def _acquire_token(self) -> bool:
        """Acquire token for rate limiting."""
        # Refill tokens based on elapsed time
        now = time.time()
        elapsed = now - self.last_refill
        tokens_to_add = elapsed * self.token_refill_rate

        self.request_tokens = min(
            100,
            self.request_tokens + tokens_to_add
        )
        self.last_refill = now

        # Check if token available
        if self.request_tokens >= 1:
            self.request_tokens -= 1
            return True
        else:
            return False

    def _handle_create(self, entity_data: dict) -> None:
        """Create with rate limiting."""
        # Wait for token
        while not self._acquire_token():
            time.sleep(0.1)

        # Proceed with create
        external_data = self._transform_entity(entity_data)
        self.client.create_entity(external_data)
```

### 4. Monitoring and Metrics

```python
class MyStreamConnector:
    def __init__(self, config, helper):
        self.config = config
        self.helper = helper
        self.client = MyExternalClient(...)

        # Metrics
        self.events_processed = 0
        self.events_failed = 0
        self.last_metric_log = time.time()

    def process_message(self, msg) -> None:
        """Process with metrics tracking."""
        try:
            # Process event
            if msg.event == "create":
                self._handle_create(msg.data)
            elif msg.event == "update":
                self._handle_update(msg.data)
            elif msg.event == "delete":
                self._handle_delete(msg.data)

            # Increment success counter
            self.events_processed += 1

        except Exception as e:
            # Increment failure counter
            self.events_failed += 1
            self.helper.connector_logger.error(
                "Event processing failed",
                {"error": str(e)}
            )

        # Log metrics every 60 seconds
        if time.time() - self.last_metric_log >= 60:
            self._log_metrics()

    def _log_metrics(self) -> None:
        """Log processing metrics."""
        self.helper.connector_logger.info(
            "Connector metrics",
            {
                "events_processed": self.events_processed,
                "events_failed": self.events_failed,
                "success_rate": self.events_processed / (self.events_processed + self.events_failed) if (self.events_processed + self.events_failed) > 0 else 0
            }
        )
        self.last_metric_log = time.time()
```

---

## Complete Example

```python
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from my_client import MyExternalClient


class MySIEMStreamConnector:
    """
    Stream connector for SIEM integration.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = MyExternalClient(
            self.helper,
            base_url=self.config.my_connector.api_base_url,
            api_key=self.config.my_connector.api_key,
        )

    def check_stream_id(self) -> None:
        """Validate stream ID configuration."""
        if (
            self.helper.connect_live_stream_id is None
            or self.helper.connect_live_stream_id == "ChangeMe"
        ):
            raise ValueError("Missing stream ID configuration")

    def _transform_entity(self, entity_data: dict) -> dict:
        """Transform OpenCTI entity to SIEM format."""
        return {
            "id": entity_data["id"],
            "type": entity_data.get("type"),
            "name": entity_data.get("name", ""),
            "description": entity_data.get("description", ""),
            "pattern": entity_data.get("pattern"),
            "confidence": entity_data.get("confidence", 50),
            "tlp": self._extract_tlp(entity_data),
            "labels": [label["value"] for label in entity_data.get("labels", [])],
            "created": entity_data.get("created_at"),
            "modified": entity_data.get("updated_at"),
        }

    def _extract_tlp(self, entity: dict) -> str:
        """Extract TLP marking."""
        for marking in entity.get("objectMarking", []):
            if marking.get("definition_type") == "TLP":
                return marking["definition"]
        return "TLP:CLEAR"

    def _handle_create(self, entity_data: dict) -> None:
        """Handle entity creation."""
        try:
            siem_data = self._transform_entity(entity_data)
            result = self.client.create_indicator(siem_data)

            self.helper.connector_logger.info(
                "Indicator pushed to SIEM",
                {"entity_id": entity_data["id"], "siem_id": result["id"]}
            )

        except Exception as e:
            self.helper.connector_logger.error(
                "Failed to push indicator to SIEM",
                {"entity_id": entity_data["id"], "error": str(e)}
            )

    def _handle_update(self, entity_data: dict) -> None:
        """Handle entity update."""
        try:
            siem_data = self._transform_entity(entity_data)
            self.client.update_indicator(entity_data["id"], siem_data)

            self.helper.connector_logger.info(
                "Indicator updated in SIEM",
                {"entity_id": entity_data["id"]}
            )

        except Exception as e:
            self.helper.connector_logger.error(
                "Failed to update indicator in SIEM",
                {"entity_id": entity_data["id"], "error": str(e)}
            )

    def _handle_delete(self, entity_data: dict) -> None:
        """Handle entity deletion."""
        try:
            self.client.delete_indicator(entity_data["id"])

            self.helper.connector_logger.info(
                "Indicator deleted from SIEM",
                {"entity_id": entity_data["id"]}
            )

        except Exception as e:
            self.helper.connector_logger.error(
                "Failed to delete indicator from SIEM",
                {"entity_id": entity_data["id"], "error": str(e)}
            )

    def process_message(self, msg) -> None:
        """Process stream event."""
        try:
            self.check_stream_id()

            event_type = msg.event
            entity_data = msg.data
            entity_type = entity_data.get("type")

            # Filter by entity type
            if entity_type not in ["indicator", "ipv4-addr", "domain-name"]:
                return

            self.helper.connector_logger.info(
                f"Processing {event_type} event",
                {"entity_id": entity_data["id"], "entity_type": entity_type}
            )

            # Route to handler
            if event_type == "create":
                self._handle_create(entity_data)
            elif event_type == "update":
                self._handle_update(entity_data)
            elif event_type == "delete":
                self._handle_delete(entity_data)

        except Exception as e:
            self.helper.connector_logger.error(
                "Event processing failed",
                {"error": str(e)}
            )

    def run(self) -> None:
        """Start the connector."""
        self.helper.connector_logger.info(
            "Starting SIEM stream connector",
            {"stream_id": self.helper.connect_live_stream_id}
        )

        self.helper.listen_stream(message_callback=self.process_message)
```

---

## Next Steps

- Review [Code Quality & Standards](./05-code-quality-standards.md)
- Test your stream connector thoroughly
- Monitor for processing errors and performance issues
