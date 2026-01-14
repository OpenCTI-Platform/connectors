# External Import Connector Specifications

**Document:** 02-external-import-specifications.md
**Connector Type:** `EXTERNAL_IMPORT`

## Table of Contents

- [Overview](#overview)
- [Connector Architecture](#connector-architecture)
- [Scheduling and Execution](#scheduling-and-execution)
- [Work Management](#work-management)
- [State Management](#state-management)
- [Data Collection](#data-collection)
- [STIX Bundle Creation](#stix-bundle-creation)
- [Rate Limiting](#rate-limiting)
- [Incremental Import Strategies](#incremental-import-strategies)
- [Best Practices](#best-practices)
- [Complete Example](#complete-example)

---

## Overview

External Import connectors fetch data from external sources (APIs, feeds, databases) and import it into OpenCTI as STIX 2.1 objects.

### Purpose

- Import threat intelligence from external sources
- Periodically fetch and synchronize data
- Convert external data formats to STIX 2.1
- Maintain state for incremental imports

### Key Characteristics

- **Scheduled execution**: Runs at configured intervals
- **Pull-based**: Connector initiates data fetching
- **Stateful**: Tracks what has been imported
- **Autonomous**: Runs independently without user triggers

### Use Cases

- Threat intelligence feed ingestion
- OSINT data collection
- Vendor API integration
- Custom data source imports
- RSS/Atom feed parsing

---

## Connector Architecture

### Class Structure

```python
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from my_client import MyClient


class MyConnector:
    """
    External Import connector for fetching threat intelligence.
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
            author_name="My Threat Feed",
            tlp_level=self.config.my_connector.tlp_level,
        )

    def _collect_intelligence(self) -> list:
        """
        Collect intelligence from the source.
        Returns list of STIX objects.
        """
        # Implementation here
        pass

    def process_message(self) -> None:
        """
        Main processing method called by scheduler.
        """
        # Implementation here
        pass

    def run(self) -> None:
        """
        Start the connector and schedule execution.
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
```

### Required Methods

| Method | Purpose |
|--------|---------|
| `__init__` | Initialize connector, client, and converter |
| `_collect_intelligence()` | Fetch and convert external data to STIX |
| `process_message()` | Main processing logic, work management |
| `run()` | Start scheduler and begin execution |

---

## Scheduling and Execution

### Configuration

External import connectors use `duration_period` for scheduling:

```yaml
connector:
  duration_period: 'PT1H'  # ISO-8601 duration format
```

**Common durations:**
- `PT5M` - Every 5 minutes
- `PT1H` - Every hour
- `PT6H` - Every 6 hours
- `PT24H` - Every 24 hours (daily)

### Scheduler Implementation

```python
def run(self) -> None:
    """
    Start the connector and schedule periodic execution.
    """
    self.helper.schedule_process(
        message_callback=self.process_message,
        duration_period=self.config.connector.duration_period.total_seconds(),
    )
```

### Queue Threshold

The scheduler automatically checks the connector's queue size before each run:

```yaml
connector:
  queue_threshold: 500  # MB
```

If the queue exceeds this threshold, the next run is postponed until the queue is processed.

### First Run

The connector runs immediately on startup, then follows the schedule:

```python
def process_message(self) -> None:
    current_state = self.helper.get_state()

    if current_state is None or "last_run" not in current_state:
        self.helper.connector_logger.info("First run of connector")
    else:
        self.helper.connector_logger.info(
            "Connector last run",
            {"last_run": current_state["last_run"]}
        )

    # Continue processing...
```

---

## Work Management

Work management tracks individual connector runs in OpenCTI.

### Initiating Work

```python
def process_message(self) -> None:
    # Create friendly name for this work
    friendly_name = f"{self.helper.connect_name} - {datetime.now().isoformat()}"

    # Initiate work
    work_id = self.helper.api.work.initiate_work(
        self.helper.connect_id,
        friendly_name
    )

    self.helper.connector_logger.info(
        "Work initiated",
        {"work_id": work_id}
    )

    # Perform data collection
    stix_objects = self._collect_intelligence()

    # Send bundle
    if len(stix_objects) > 0:
        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(
            bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )

    # Mark work as completed
    message = f"Imported {len(stix_objects)} objects"
    self.helper.api.work.to_processed(work_id, message)
    self.helper.connector_logger.info(message)
```

### Work Status

Work can have different statuses:
- **In Progress**: Work is being processed
- **Completed**: Work finished successfully
- **Failed**: Work encountered an error

### Error Handling in Work

```python
try:
    # Processing logic
    stix_objects = self._collect_intelligence()

    # Send bundle
    bundle = self.helper.stix2_create_bundle(stix_objects)
    self.helper.send_stix2_bundle(bundle, work_id=work_id)

    # Mark as completed
    self.helper.api.work.to_processed(
        work_id,
        f"Successfully imported {len(stix_objects)} objects"
    )

except Exception as e:
    self.helper.connector_logger.error(
        "Import failed",
        {"error": str(e)}
    )
    # Work will remain in "In Progress" or be marked as failed
    raise
```

---

## State Management

State management enables incremental imports and tracks connector progress.

### State Structure

```python
state = {
    "last_run": "2026-01-14 10:30:00",
    "last_timestamp": 1705229400,
    "cursor": "abc123xyz",
    "items_processed": 1542,
}
```

### Reading State

```python
def process_message(self) -> None:
    # Get current state
    current_state = self.helper.get_state()

    # Initialize state if first run
    if current_state is None:
        current_state = {
            "last_run": None,
            "last_timestamp": None,
        }

    # Use state to determine what to fetch
    if current_state["last_timestamp"]:
        start_time = current_state["last_timestamp"]
    else:
        # First run - use configured start date
        start_time = self.config.my_connector.import_from_date
```

### Updating State

```python
def process_message(self) -> None:
    # ... processing logic ...

    # Update state after successful import
    now = datetime.now(timezone.utc)
    new_state = {
        "last_run": now.strftime("%Y-%m-%d %H:%M:%S"),
        "last_timestamp": int(now.timestamp()),
        "items_processed": len(stix_objects),
    }

    self.helper.set_state(new_state)
    self.helper.connector_logger.info(
        "State updated",
        {"state": new_state}
    )
```

### State Best Practices

1. **Update after successful processing** - Don't update state if processing fails
2. **Include enough context** - Store what you need to resume
3. **Use timestamps for time-based imports** - More reliable than dates
4. **Store cursors for paginated APIs** - Resume exactly where you left off
5. **Keep state minimal** - Don't store large objects

---

## Data Collection

### Collection Method

```python
def _collect_intelligence(self) -> list:
    """
    Collect intelligence from external source and convert to STIX.

    Returns:
        List of STIX objects
    """
    stix_objects = []

    # Get current state to determine what to fetch
    current_state = self.helper.get_state()
    start_date = self._get_start_date(current_state)

    self.helper.connector_logger.info(
        "Collecting intelligence",
        {"start_date": start_date}
    )

    # Fetch data from external source
    try:
        data = self.client.get_threat_data(since=start_date)
    except Exception as e:
        self.helper.connector_logger.error(
            "Failed to fetch data",
            {"error": str(e)}
        )
        raise

    # Convert each item to STIX objects
    for item in data:
        try:
            # Convert to STIX
            converted_objects = self.converter_to_stix.convert_item(item)
            stix_objects.extend(converted_objects)

        except Exception as e:
            self.helper.connector_logger.warning(
                "Failed to convert item, skipping",
                {"item_id": item.get("id"), "error": str(e)}
            )
            continue

    # Add author and marking
    if len(stix_objects) > 0:
        stix_objects.append(self.converter_to_stix.author)
        stix_objects.append(self.converter_to_stix.tlp_marking)

    self.helper.connector_logger.info(
        "Intelligence collected",
        {"objects_count": len(stix_objects)}
    )

    return stix_objects
```

### Pagination Handling

```python
def _collect_intelligence(self) -> list:
    """Collect with pagination support."""
    stix_objects = []
    page = 1
    has_more = True

    while has_more:
        self.helper.connector_logger.debug(
            "Fetching page",
            {"page": page}
        )

        # Fetch page
        response = self.client.get_data(page=page, per_page=100)
        items = response["items"]

        # Convert items
        for item in items:
            converted = self.converter_to_stix.convert_item(item)
            stix_objects.extend(converted)

        # Check if more pages
        has_more = len(items) == 100
        page += 1

    return stix_objects
```

---

## STIX Bundle Creation

### Bundle Structure

A STIX bundle must include:
1. **Knowledge objects** (indicators, observables, etc.)
2. **Author** (identity object)
3. **Markings** (TLP, statement markings)
4. **Relationships** (between objects)

### Creating the Bundle

```python
def process_message(self) -> None:
    # Collect STIX objects
    stix_objects = self._collect_intelligence()

    if len(stix_objects) > 0:
        # Create bundle
        bundle = self.helper.stix2_create_bundle(stix_objects)

        # Send to OpenCTI
        bundles_sent = self.helper.send_stix2_bundle(
            bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )

        self.helper.connector_logger.info(
            "Bundle sent",
            {"bundles_count": len(bundles_sent), "objects_count": len(stix_objects)}
        )
    else:
        self.helper.connector_logger.info("No new data to import")
```

### Bundle Best Practices

1. **Always include author** - Required for proper attribution
2. **Include appropriate markings** - TLP, PAP, statement markings
3. **Create relationships** - Link related objects
4. **Validate before sending** - Use `cleanup_inconsistent_bundle=True`
5. **Batch appropriately** - Don't send too many objects at once (< 1000 recommended)

### Large Dataset Handling

```python
def process_message(self) -> None:
    stix_objects = self._collect_intelligence()

    # Split into batches of 500 objects
    batch_size = 500
    for i in range(0, len(stix_objects), batch_size):
        batch = stix_objects[i:i + batch_size]

        # Always include author and marking in each batch
        batch_with_meta = batch + [
            self.converter_to_stix.author,
            self.converter_to_stix.tlp_marking
        ]

        bundle = self.helper.stix2_create_bundle(batch_with_meta)
        self.helper.send_stix2_bundle(
            bundle,
            work_id=work_id,
            cleanup_inconsistent_bundle=True,
        )

        self.helper.connector_logger.info(
            "Batch sent",
            {"batch": i // batch_size + 1, "objects": len(batch)}
        )
```

---

## Rate Limiting

### API Rate Limit Handling

```python
class MyClient:
    def __init__(self, helper, base_url, api_key):
        self.helper = helper
        self.base_url = base_url
        self.api_key = api_key
        self.rate_limit_remaining = None
        self.rate_limit_reset = None

    def get_data(self, endpoint):
        """Fetch data with rate limit handling."""
        # Check if we need to wait
        if self.rate_limit_remaining == 0:
            wait_time = self.rate_limit_reset - time.time()
            if wait_time > 0:
                self.helper.connector_logger.warning(
                    "Rate limit reached, waiting",
                    {"wait_seconds": int(wait_time)}
                )
                time.sleep(wait_time)

        # Make request
        response = requests.get(
            f"{self.base_url}/{endpoint}",
            headers={"Authorization": f"Bearer {self.api_key}"}
        )

        # Update rate limit info from headers
        self.rate_limit_remaining = int(
            response.headers.get("X-RateLimit-Remaining", 100)
        )
        self.rate_limit_reset = int(
            response.headers.get("X-RateLimit-Reset", time.time() + 3600)
        )

        response.raise_for_status()
        return response.json()
```

### Request Throttling

```python
import time

class MyClient:
    def __init__(self, helper, base_url, api_key, requests_per_minute=60):
        self.helper = helper
        self.base_url = base_url
        self.api_key = api_key
        self.min_interval = 60 / requests_per_minute
        self.last_request_time = 0

    def _throttle(self):
        """Ensure minimum interval between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    def get_data(self, endpoint):
        """Fetch data with throttling."""
        self._throttle()
        response = requests.get(
            f"{self.base_url}/{endpoint}",
            headers={"Authorization": f"Bearer {self.api_key}"}
        )
        response.raise_for_status()
        return response.json()
```

---

## Incremental Import Strategies

### Time-Based Incremental Import

```python
def _collect_intelligence(self) -> list:
    """Collect only new/updated data since last run."""
    current_state = self.helper.get_state()

    # Determine start time
    if current_state and "last_timestamp" in current_state:
        start_time = current_state["last_timestamp"]
    else:
        # First run - use configured start date
        start_time = self._parse_date(
            self.config.my_connector.import_from_date
        )

    # Fetch only data modified after start_time
    data = self.client.get_data(modified_since=start_time)

    # Convert to STIX
    stix_objects = []
    for item in data:
        converted = self.converter_to_stix.convert_item(item)
        stix_objects.extend(converted)

    return stix_objects
```

### Cursor-Based Incremental Import

```python
def _collect_intelligence(self) -> list:
    """Collect using cursor pagination."""
    current_state = self.helper.get_state()
    cursor = current_state.get("cursor") if current_state else None

    stix_objects = []
    has_more = True

    while has_more:
        # Fetch data with cursor
        response = self.client.get_data(cursor=cursor)

        # Convert items
        for item in response["items"]:
            converted = self.converter_to_stix.convert_item(item)
            stix_objects.extend(converted)

        # Update cursor for next run
        cursor = response.get("next_cursor")
        has_more = cursor is not None

        # Save state periodically
        if cursor:
            self.helper.set_state({"cursor": cursor})

    return stix_objects
```

### ID-Based Tracking

```python
def _collect_intelligence(self) -> list:
    """Track processed items by ID."""
    current_state = self.helper.get_state()
    processed_ids = set(current_state.get("processed_ids", []))

    # Fetch all data
    data = self.client.get_data()

    stix_objects = []
    new_ids = []

    for item in data:
        item_id = item["id"]

        # Skip if already processed
        if item_id in processed_ids:
            continue

        # Convert to STIX
        converted = self.converter_to_stix.convert_item(item)
        stix_objects.extend(converted)
        new_ids.append(item_id)

    # Update state with new IDs (keep last 10000)
    all_ids = list(processed_ids) + new_ids
    self.helper.set_state({
        "processed_ids": all_ids[-10000:]
    })

    return stix_objects
```

---

## Best Practices

### 1. Error Recovery

```python
def process_message(self) -> None:
    work_id = self.helper.api.work.initiate_work(
        self.helper.connect_id,
        friendly_name
    )

    try:
        stix_objects = self._collect_intelligence()

        if len(stix_objects) > 0:
            bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(bundle, work_id=work_id)

        self.helper.api.work.to_processed(
            work_id,
            f"Successfully imported {len(stix_objects)} objects"
        )

        # Only update state after successful completion
        self.helper.set_state({"last_run": datetime.now().isoformat()})

    except Exception as e:
        self.helper.connector_logger.error(
            "Import failed",
            {"error": str(e)}
        )
        # Don't update state - will retry with same parameters next run
        raise
```

### 2. Graceful Degradation

```python
def _collect_intelligence(self) -> list:
    """Collect from multiple sources, continue on partial failure."""
    stix_objects = []

    # Try primary source
    try:
        primary_data = self.client.get_primary_feed()
        stix_objects.extend(self._convert_data(primary_data))
    except Exception as e:
        self.helper.connector_logger.error(
            "Primary feed failed",
            {"error": str(e)}
        )
        # Continue with other sources

    # Try secondary source
    try:
        secondary_data = self.client.get_secondary_feed()
        stix_objects.extend(self._convert_data(secondary_data))
    except Exception as e:
        self.helper.connector_logger.error(
            "Secondary feed failed",
            {"error": str(e)}
        )

    return stix_objects
```

### 3. Data Validation

```python
def _convert_item(self, item):
    """Convert item with validation."""
    # Validate required fields
    required_fields = ["id", "type", "value"]
    for field in required_fields:
        if field not in item:
            raise ValueError(f"Missing required field: {field}")

    # Validate data format
    if not self._is_valid_ip(item["value"]):
        raise ValueError(f"Invalid IP address: {item['value']}")

    # Convert to STIX
    return self.converter_to_stix.create_observable(item)
```

### 4. Deduplication

```python
def _collect_intelligence(self) -> list:
    """Collect with deduplication."""
    data = self.client.get_data()

    # Deduplicate by ID
    seen_ids = set()
    unique_items = []

    for item in data:
        item_id = item["id"]
        if item_id not in seen_ids:
            seen_ids.add(item_id)
            unique_items.append(item)

    # Convert to STIX
    stix_objects = []
    for item in unique_items:
        converted = self.converter_to_stix.convert_item(item)
        stix_objects.extend(converted)

    return stix_objects
```

### 5. Logging

```python
def process_message(self) -> None:
    self.helper.connector_logger.info("Starting import run")

    work_id = self.helper.api.work.initiate_work(
        self.helper.connect_id,
        friendly_name
    )

    start_time = time.time()

    stix_objects = self._collect_intelligence()

    elapsed = time.time() - start_time

    self.helper.connector_logger.info(
        "Import completed",
        {
            "objects_collected": len(stix_objects),
            "duration_seconds": round(elapsed, 2)
        }
    )

    # Send bundle and complete work...
```

---

## Complete Example

```python
from datetime import datetime, timedelta, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from my_client import MyClient


class MyThreatFeedConnector:
    """
    External Import connector for My Threat Feed.
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
            author_name="My Threat Feed",
            tlp_level=self.config.my_connector.tlp_level,
        )

    def _get_start_date(self, current_state):
        """Determine start date for import."""
        if current_state and "last_timestamp" in current_state:
            return datetime.fromtimestamp(
                current_state["last_timestamp"],
                tz=timezone.utc
            )
        else:
            # First run
            return datetime.strptime(
                self.config.my_connector.import_from_date,
                "%Y-%m-%d"
            ).replace(tzinfo=timezone.utc)

    def _collect_intelligence(self) -> list:
        """Collect intelligence from My Threat Feed."""
        current_state = self.helper.get_state()
        start_date = self._get_start_date(current_state)

        self.helper.connector_logger.info(
            "Collecting intelligence",
            {"start_date": start_date.isoformat()}
        )

        # Fetch data
        data = self.client.get_threat_data(since=start_date)

        # Convert to STIX
        stix_objects = []
        for item in data:
            try:
                converted = self.converter_to_stix.convert_item(item)
                stix_objects.extend(converted)
            except Exception as e:
                self.helper.connector_logger.warning(
                    "Failed to convert item",
                    {"item_id": item.get("id"), "error": str(e)}
                )
                continue

        # Add author and marking
        if len(stix_objects) > 0:
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return stix_objects

    def process_message(self) -> None:
        """Main processing method."""
        self.helper.connector_logger.info("Starting import run")

        # Initialize work
        friendly_name = f"My Threat Feed import - {datetime.now().isoformat()}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            friendly_name
        )

        try:
            # Collect intelligence
            stix_objects = self._collect_intelligence()

            # Send bundle if we have data
            if len(stix_objects) > 0:
                bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                message = f"Successfully imported {len(stix_objects)} objects"
                self.helper.connector_logger.info(message)
            else:
                message = "No new data to import"
                self.helper.connector_logger.info(message)

            # Mark work as completed
            self.helper.api.work.to_processed(work_id, message)

            # Update state
            now = datetime.now(timezone.utc)
            self.helper.set_state({
                "last_run": now.strftime("%Y-%m-%d %H:%M:%S"),
                "last_timestamp": int(now.timestamp()),
            })

        except Exception as e:
            self.helper.connector_logger.error(
                "Import failed",
                {"error": str(e)}
            )
            raise

    def run(self) -> None:
        """Start the connector."""
        self.helper.connector_logger.info(
            "Starting My Threat Feed connector",
            {"duration_period": str(self.config.connector.duration_period)}
        )

        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
```

---

## Next Steps

- Review [Internal Enrichment Specifications](./03-internal-enrichment-specifications.md)
- Review [Stream Connector Specifications](./04-stream-specifications.md)
- Review [Code Quality & Standards](./05-code-quality-standards.md)
