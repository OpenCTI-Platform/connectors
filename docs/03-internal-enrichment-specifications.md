# Internal Enrichment Connector Specifications

**Document:** 03-internal-enrichment-specifications.md
**Connector Type:** `INTERNAL_ENRICHMENT`

## Table of Contents

- [Overview](#overview)
- [Connector Architecture](#connector-architecture)
- [Event-Driven Processing](#event-driven-processing)
- [Entity Scope Validation](#entity-scope-validation)
- [TLP Marking Handling](#tlp-marking-handling)
- [Enrichment Process](#enrichment-process)
- [Playbook Compatibility](#playbook-compatibility)
- [Bundle Handling](#bundle-handling)
- [Best Practices](#best-practices)
- [Complete Example](#complete-example)

---

## Overview

Internal Enrichment connectors enrich entities that already exist in OpenCTI by adding additional context, relationships, and metadata from external sources.

### Purpose

- Enrich observables (IPs, domains, hashes, etc.)
- Add context to indicators, vulnerabilities, and other entities
- Create relationships between enriched entities and new information
- Support automated enrichment workflows (playbooks)

### Key Characteristics

- **Event-driven**: Triggered when entities are created or updated
- **Push-based**: OpenCTI pushes entities to the connector
- **Stateless**: Each enrichment request is independent
- **Scope-based**: Only processes configured entity types

### Use Cases

- IP/domain reputation enrichment
- File hash analysis
- Vulnerability information lookup
- Geolocation enrichment
- WHOIS data enrichment
- Threat actor attribution

---

## Connector Architecture

### Class Structure

```python
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from my_client import MyClient


class MyEnrichmentConnector:
    """
    Internal Enrichment connector for entity enrichment.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """Initialize the connector."""
        self.config = config
        self.helper = helper

        # Initialize API client
        self.client = MyClient(
            self.helper,
            base_url=self.config.my_connector.api_base_url,
            api_key=self.config.my_connector.api_key,
        )

        # Initialize STIX converter
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level="clear",
        )

        # Storage for enrichment results
        self.stix_objects_list = []

    def _collect_intelligence(self, value: str, obs_id: str) -> list:
        """
        Enrich entity and return STIX objects.
        """
        # Implementation here
        pass

    def entity_in_scope(self, data: dict) -> bool:
        """
        Check if entity type is in connector scope.
        """
        # Implementation here
        pass

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """
        Validate TLP markings.
        """
        # Implementation here
        pass

    def process_message(self, data: dict) -> str:
        """
        Process enrichment request.
        """
        # Implementation here
        pass

    def run(self) -> None:
        """
        Start listening for enrichment events.
        """
        self.helper.listen(message_callback=self.process_message)
```

### Required Methods

| Method                         | Purpose                                            |
| ------------------------------ | -------------------------------------------------- |
| `__init__`                     | Initialize connector, client, and converter        |
| `_collect_intelligence()`      | Fetch enrichment data and create STIX objects      |
| `entity_in_scope()`            | Validate entity type against connector scope       |
| `extract_and_check_markings()` | Validate TLP markings                              |
| `process_message()`            | Main processing logic for enrichment events        |
| `run()`                        | Start event listener with `helper.listen()` method |

---

## Event-Driven Processing

### Listening for Events

Internal enrichment connectors listen for entity events:

```python
def run(self) -> None:
    """
    Start listening for enrichment events.
    The helper continuously monitors the connector's queue.
    """
    self.helper.connector_logger.info(
        "Starting enrichment connector",
        {"connector_name": self.helper.connect_name}
    )

    self.helper.listen(message_callback=self.process_message)
```

### Event Data Structure

When an entity is created or modified, the connector receives:

```python
data = {
    "entity_id": "indicator--uuid",
    "entity_type": "Indicator",
    "enrichment_entity": {
        # Full entity data from OpenCTI
        "id": "indicator--uuid",
        "entity_type": "Indicator",
        "name": "Malicious IP",
        "objectMarking": [...],
        # ... other entity properties
    },
    "stix_entity": {
        # STIX representation of the entity
        "id": "indicator--uuid",
        "type": "indicator",
        "pattern": "[ipv4-addr:value = '192.0.2.1']",
        # ... other STIX properties
    },
    "stix_objects": [
        # Existing STIX bundle for the entity
        # Must be returned (potentially enriched) for playbook compatibility
    ],
}
```

### Processing Events

```python
def process_message(self, data: dict) -> str:
    """
    Process enrichment event.

    Args:
        data: Event data containing entity to enrich

    Returns:
        Status message
    """
    try:
        # Extract entity data
        opencti_entity = data["enrichment_entity"]
        stix_entity = data["stix_entity"]
        self.stix_objects_list = data["stix_objects"]

        # Validate TLP markings
        self.extract_and_check_markings(opencti_entity)

        # Check if entity is in scope
        if not self.entity_in_scope(data):
            # Return original bundle unchanged for playbook compatibility
            if not data.get("event_type"):
                self._send_bundle(self.stix_objects_list)
                return "Entity not in scope, returned original bundle"
            else:
                raise ValueError(
                    f"{opencti_entity['entity_type']} is not a supported entity type"
                )

        # Extract entity information
        entity_id = stix_entity["id"]
        entity_value = stix_entity.get("value")
        entity_type = stix_entity["type"]

        self.helper.connector_logger.info(
            "Processing entity",
            {"type": entity_type, "id": entity_id}
        )

        # Perform enrichment
        enriched_objects = self._collect_intelligence(entity_value, entity_id)

        if enriched_objects and len(enriched_objects) > 0:
            return self._send_bundle(enriched_objects)
        else:
            return "No enrichment data found"

    except Exception as e:
        self.helper.connector_logger.error(
            "Enrichment failed",
            {"error": str(e)}
        )
        return f"Error: {str(e)}"
```


## Entity Scope Validation

### Configuring Scope

Scope defines which entity types the connector can process:

```yaml
connector:
  scope: 'ipv4-addr,ipv6-addr,domain-name,url'
```

**Common scopes:**
- **Observables**: `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file`, `email-addr`
- **Indicators**: `indicator`
- **Vulnerabilities**: `vulnerability`
- **Malware**: `malware`
- **Threat Actors**: `threat-actor`

### Validating Scope

```python
def entity_in_scope(self, data: dict) -> bool:
    """
    Check if entity type is within connector scope.

    Args:
        data: Event data

    Returns:
        True if entity is in scope, False otherwise
    """
    # Parse scope from configuration
    scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")

    # Extract entity type from entity ID
    entity_id = data["entity_id"]
    entity_type = entity_id.split("--")[0].lower()

    # Check if entity type is in scope
    if entity_type in scopes:
        self.helper.connector_logger.debug(
            "Entity in scope",
            {"entity_type": entity_type}
        )
        return True
    else:
        self.helper.connector_logger.debug(
            "Entity not in scope",
            {"entity_type": entity_type, "allowed_scopes": scopes}
        )
        return False
```

### Multiple Entity Types

```python
def entity_in_scope(self, data: dict) -> bool:
    """Enhanced scope checking with type-specific validation."""
    scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
    entity_type = data["entity_id"].split("--")[0].lower()

    if entity_type not in scopes:
        return False

    # Additional validation for specific types
    if entity_type == "file":
        # Only process files with hashes
        stix_entity = data["stix_entity"]
        has_hash = any(
            key.startswith("hashes.") for key in stix_entity.keys()
        )
        if not has_hash:
            self.helper.connector_logger.debug(
                "File has no hashes, skipping"
            )
            return False

    return True
```

---

## TLP Marking Handling

### Extracting TLP Markings

```python
def extract_and_check_markings(self, opencti_entity: dict) -> None:
    """
    Extract TLP marking from entity and validate against max TLP.

    Args:
        opencti_entity: Entity data from OpenCTI

    Raises:
        ValueError: If entity TLP exceeds max allowed TLP
    """
    entity_tlp = None

    # Extract TLP from object markings
    if len(opencti_entity.get("objectMarking", [])) > 0:
        for marking in opencti_entity["objectMarking"]:
            if marking.get("definition_type") == "TLP":
                entity_tlp = marking["definition"]
                break

    # Validate against max TLP
    valid_max_tlp = self.helper.check_max_tlp(
        entity_tlp,
        self.config.my_connector.max_tlp_level
    )

    if not valid_max_tlp:
        raise ValueError(
            f"Entity TLP ({entity_tlp}) exceeds maximum allowed "
            f"TLP ({self.config.my_connector.max_tlp_level})"
        )

    self.helper.connector_logger.debug(
        "TLP validation passed",
        {"entity_tlp": entity_tlp, "max_tlp": self.config.my_connector.max_tlp_level}
    )
```

### TLP Hierarchy

The helper's `check_max_tlp()` method understands TLP hierarchy:

```
TLP:CLEAR (lowest) → TLP:WHITE → TLP:GREEN → TLP:AMBER → TLP:AMBER+STRICT → TLP:RED (highest)
```

**Configuration examples:**
- `max_tlp_level: "green"` - Process CLEAR, WHITE, and GREEN entities
- `max_tlp_level: "amber"` - Process up to and including AMBER
- `max_tlp_level: "red"` - Process all TLP levels

---

## Enrichment Process

### Collecting Intelligence

```python
def _collect_intelligence(self, value: str, entity_id: str) -> list:
    """
    Enrich entity by fetching additional data.

    Args:
        value: Entity value (e.g., IP address, domain)
        entity_id: STIX ID of the entity being enriched

    Returns:
        List of STIX objects (including original entity)
    """
    self.helper.connector_logger.info(
        "Starting enrichment",
        {"value": value, "entity_id": entity_id}
    )

    try:
        # Fetch enrichment data from external source
        enrichment_data = self.client.enrich(value)

    except Exception as e:
        self.helper.connector_logger.error(
            "Failed to fetch enrichment data",
            {"error": str(e)}
        )
        # Return original bundle on error for playbook compatibility
        return self.stix_objects_list

    # Convert enrichment data to STIX objects
    enriched_objects = []

    # Create author
    author = self.converter_to_stix.create_author()
    enriched_objects.append(author)

    # Create observable/indicator with enrichment
    enriched_entity = self.converter_to_stix.enrich_entity(
        entity_id,
        enrichment_data
    )
    enriched_objects.append(enriched_entity)

    # Create related objects
    for related in enrichment_data.get("related_items", []):
        related_obj = self.converter_to_stix.create_related(related)
        enriched_objects.append(related_obj)

        # Create relationship
        relationship = self.converter_to_stix.create_relationship(
            source_id=entity_id,
            target_id=related_obj["id"],
            relationship_type="related-to"
        )
        enriched_objects.append(relationship)

    # Add to existing bundle
    all_objects = self.stix_objects_list + enriched_objects

    self.helper.connector_logger.info(
        "Enrichment completed",
        {"new_objects": len(enriched_objects)}
    )

    return all_objects
```

### Creating Enrichment Objects

```python
class ConverterToStix:
    def __init__(self, helper, tlp_level="clear"):
        self.helper = helper
        self.author = self.create_author()
        self.tlp_marking = TLPMarking(level=tlp_level)

    def create_author(self):
        """Create author identity."""
        author = OrganizationAuthor(name="My Enrichment Service")
        return author.to_stix2_object()

    def enrich_entity(self, entity_id, enrichment_data):
        """
        Create enriched version of entity.

        Note: You typically don't recreate the entity, but add related objects.
        This example shows how to add custom properties.
        """
        from connectors_sdk.models import CustomObservable

        enriched = CustomObservable(
            id=entity_id,
            custom_properties={
                "x_reputation_score": enrichment_data.get("reputation"),
                "x_first_seen": enrichment_data.get("first_seen"),
                "x_last_seen": enrichment_data.get("last_seen"),
            }
        )
        return enriched.to_stix2_object()

    def create_related(self, related_data):
        """Create related observable/indicator."""
        if related_data["type"] == "domain":
            domain = DomainName(
                value=related_data["value"],
                author=self.author,
                markings=[self.tlp_marking],
            )
            return domain.to_stix2_object()
        # ... handle other types

    def create_relationship(self, source_id, target_id, relationship_type):
        """Create relationship between objects."""
        from stix2 import Relationship

        rel = Relationship(
            id=f"relationship--{uuid.uuid4()}",
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
        )
        return rel
```

---

## Playbook Compatibility

### Playbook Requirements

For playbook automation compatibility, connectors **MUST**:

1. **Always return a bundle** - Even if enrichment fails or entity is out of scope
2. **Include the original entity** - The enriched entity must be in the bundle
3. **Set `playbook_compatible=True`** when initializing the helper
4. **Set `playbook_supported: true`** in metadata

```python
        helper = OpenCTIConnectorHelper(
            config=settings.to_helper_config(),
            playbook_compatible=True,  # ! `playbook_compatible=True` only if a bundle is sent
        )
```

### Metadata Configuration

**File:** `__metadata__/connector_manifest.json`

```json
{
  "title": "My Enrichment Connector",
  "slug": "my-enrichment",
  "description": "Enrich observables with additional context",
  "playbook_supported": true,
  "container_type": "INTERNAL_ENRICHMENT",
  ...
}
```

### Returning Original Bundle

```python
def process_message(self, data: dict) -> str:
    try:
        opencti_entity = data["enrichment_entity"]
        self.stix_objects_list = data["stix_objects"]

        # Check scope
        if not self.entity_in_scope(data):
            # CRITICAL: Return original bundle for playbook compatibility
            if not data.get("event_type"):
                self._send_bundle(self.stix_objects_list)
                return "Entity not in scope, returned original bundle"
            else:
                raise ValueError("Entity type not supported")

        # Perform enrichment
        enriched_objects = self._collect_intelligence(
            opencti_entity["value"],
            opencti_entity["id"]
        )

        # Send enriched bundle (includes original)
        return self._send_bundle(enriched_objects)

    except Exception as e:
        self.helper.connector_logger.error(
            "Enrichment failed",
            {"error": str(e)}
        )
        # On error, return original bundle
        self._send_bundle(self.stix_objects_list)
        return f"Error occurred, returned original bundle: {str(e)}"
```



---

## Bundle Handling

### Sending Bundles

```python
def _send_bundle(self, stix_objects: list) -> str:
    """
    Send STIX bundle to OpenCTI.

    Args:
        stix_objects: List of STIX objects to send

    Returns:
        Status message
    """
    try:
        # Create bundle
        bundle = self.helper.stix2_create_bundle(stix_objects)

        # Send to OpenCTI
        bundles_sent = self.helper.send_stix2_bundle(bundle)

        message = f"Sent {len(bundles_sent)} bundle(s) with {len(stix_objects)} objects"

        self.helper.connector_logger.info(message)
        return message

    except Exception as e:
        self.helper.connector_logger.error(
            "Failed to send bundle",
            {"error": str(e)}
        )
        raise
```

### Bundle Composition

A complete enrichment bundle should include:

1. **Original entity** (from `data["stix_objects"]`)
2. **Enriched/updated entity** (if modified)
3. **New related entities** (created during enrichment)
4. **Relationships** (between original and new entities)
5. **Author identity**
6. **Markings** (TLP, etc.)

```python
def _collect_intelligence(self, value: str, entity_id: str) -> list:
    # Start with original bundle
    all_objects = list(self.stix_objects_list)

    # Add author
    author = self.converter_to_stix.create_author()
    all_objects.append(author)

    # Add new enrichment objects
    enrichment = self.client.enrich(value)

    for item in enrichment["items"]:
        new_obj = self.converter_to_stix.create_object(item)
        all_objects.append(new_obj)

        # Create relationship to original entity
        rel = self.converter_to_stix.create_relationship(
            entity_id,
            new_obj["id"],
            "related-to"
        )
        all_objects.append(rel)

    return all_objects
```

---

## Best Practices

Example with connector proofpoint-et-intelligence

### TLP Check — Always First

**Never query a paid external API before checking the TLP of the entity.** This is both a data handling best practice and a quota protection measure.

```python
def _check_tlp(self, opencti_entity: dict) -> bool:
    tlp = "TLP:CLEAR"
    for marking in opencti_entity.get("objectMarking", []):
        if marking["definition_type"] == "TLP":
            tlp = marking["definition"]
    return self.helper.check_max_tlp(tlp, self.config.connector.max_tlp)
```

Configure the maximum acceptable TLP in the connector config:

```yaml
# config.yml
connector:
  max_tlp: "TLP:AMBER"
```

If an entity is marked `TLP:RED` and your `max_tlp` is `TLP:AMBER`, the connector should skip it silently and return an informational message.

### Rate Limiting — Respect the API

The ET Intelligence API enforces per-key rate limits and returns HTTP `429` when exceeded. Handle this explicitly:

```python
def _query_with_retry(self, url: str, max_retries: int = 3) -> dict | None:
    for attempt in range(max_retries):
        response = self.session.get(url, headers=self.headers, timeout=10)
        if response.status_code == 200:
            return response.json().get("response")
        if response.status_code == 429:
            wait = 2 ** attempt  # exponential backoff: 1s, 2s, 4s
            self.helper.log_warning(f"Rate limit hit, waiting {wait}s before retry")
            time.sleep(wait)
            continue
        if response.status_code == 404:
            return None  # entity not found in ET Intel — not an error
        response.raise_for_status()
    return None
```

A `404` response from ET Intelligence means the IP or domain has no record in their database, this is **not an error** and should not surface as a connector failure. Return `None` and exit gracefully.

### `auto: false` for Quota-Based Sources

Proofpoint ET Intelligence is a paid, quota-limited API. **Never set `auto: true` for such connectors in production.** Automatic enrichment on every new observable creation will rapidly exhaust API quotas, especially on large platforms with hundreds of thousands of observables.

```yaml
connector:
  auto: false   # ← mandatory for quota-based paid sources
```

Enrichment should be triggered manually by analysts, or via Playbooks with controlled targeting.

### Build a Proper STIX Bundle

Always send enrichment results as a STIX 2.1 bundle via `send_stix2_bundle()`. Do not make direct API mutations on individual objects outside of the bundle flow — this bypasses confidence level checks and deduplication.

```python
def _send_bundle(self, stix_objects: list) -> None:
    if not stix_objects:
        return
    bundle = self.helper.stix2_create_bundle(stix_objects)
    self.helper.send_stix2_bundle(
        bundle,
        update=self.config.connector.update_existing_data,
        work_id=self.work_id,  # passed into _process_message by the Scheduler
    )
```


## Complete Example

```python
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connectors_sdk.models import DomainName, IPV4Address, TLPMarking
from pycti import OpenCTIConnectorHelper
from my_client import MyClient


class MyEnrichmentConnector:
    """
    Internal Enrichment connector for IP and domain enrichment.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = MyClient(
            self.helper,
            base_url=self.config.my_connector.api_base_url,
            api_key=self.config.my_connector.api_key,
        )

        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level="clear",
        )

        self.stix_objects_list = []

    def entity_in_scope(self, data: dict) -> bool:
        """Check if entity is in connector scope."""
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = data["entity_id"].split("--")[0].lower()
        return entity_type in scopes

    def extract_and_check_markings(self, opencti_entity: dict) -> None:
        """Extract and validate TLP markings."""
        entity_tlp = None

        for marking in opencti_entity.get("objectMarking", []):
            if marking.get("definition_type") == "TLP":
                entity_tlp = marking["definition"]
                break

        valid_max_tlp = self.helper.check_max_tlp(
            entity_tlp,
            self.config.my_connector.max_tlp_level
        )

        if not valid_max_tlp:
            raise ValueError(
                f"Entity TLP ({entity_tlp}) exceeds maximum allowed "
                f"TLP ({self.config.my_connector.max_tlp_level})"
            )

    def _collect_intelligence(self, value: str, entity_id: str) -> list:
        """Collect enrichment intelligence."""
        self.helper.connector_logger.info(
            "Starting enrichment",
            {"value": value}
        )

        try:
            # Fetch enrichment data
            enrichment = self.client.enrich(value)

            if not enrichment:
                self.helper.connector_logger.info("No enrichment data found")
                return self.stix_objects_list

        except Exception as e:
            self.helper.connector_logger.error(
                "Failed to fetch enrichment",
                {"error": str(e)}
            )
            return self.stix_objects_list

        # Start with original bundle
        enriched_objects = list(self.stix_objects_list)

        # Add author
        author = self.converter_to_stix.create_author()
        enriched_objects.append(author)

        # Create related observables
        for related_ip in enrichment.get("related_ips", []):
            ip_obj = IPV4Address(
                value=related_ip,
                author=author,
                markings=[TLPMarking(level="green")],
            )
            enriched_objects.append(ip_obj.to_stix2_object())

            # Create relationship
            rel = self.converter_to_stix.create_relationship(
                entity_id,
                ip_obj.to_stix2_object()["id"],
                "related-to"
            )
            enriched_objects.append(rel)

        self.helper.connector_logger.info(
            "Enrichment completed",
            {"new_objects": len(enriched_objects) - len(self.stix_objects_list)}
        )

        return enriched_objects

    def _send_bundle(self, stix_objects: list) -> str:
        """Send STIX bundle to OpenCTI."""
        bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(bundle)

        message = f"Sent {len(bundles_sent)} bundle(s) with {len(stix_objects)} objects"
        self.helper.connector_logger.info(message)
        return message

    def process_message(self, data: dict) -> str:
        """Process enrichment event."""
        try:
            opencti_entity = data["enrichment_entity"]
            stix_entity = data["stix_entity"]
            self.stix_objects_list = data["stix_objects"]

            # Validate TLP
            self.extract_and_check_markings(opencti_entity)

            # Check scope
            if not self.entity_in_scope(data):
                if not data.get("event_type"):
                    self._send_bundle(self.stix_objects_list)
                    return "Entity not in scope, returned original bundle"
                else:
                    raise ValueError(
                        f"{opencti_entity['entity_type']} not supported"
                    )

            # Extract entity info
            entity_id = stix_entity["id"]
            entity_value = stix_entity.get("value")
            entity_type = stix_entity["type"]

            self.helper.connector_logger.info(
                "Processing entity",
                {"type": entity_type, "value": entity_value}
            )

            # Perform enrichment
            enriched_objects = self._collect_intelligence(entity_value, entity_id)

            return self._send_bundle(enriched_objects)

        except Exception as e:
            self.helper.connector_logger.error(
                "Enrichment failed",
                {"error": str(e)}
            )
            # Return original bundle on error
            self._send_bundle(self.stix_objects_list)
            return f"Error: {str(e)}"

    def run(self) -> None:
        """Start the connector."""
        self.helper.connector_logger.info(
            "Starting enrichment connector",
            {"connector_name": self.helper.connect_name}
        )

        self.helper.listen(message_callback=self.process_message)
```

---

## Next Steps

- Review [Stream Connector Specifications](./04-stream-specifications.md)
- Review [Code Quality & Standards](./05-code-quality-standards.md)
