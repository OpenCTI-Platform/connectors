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

### Recommended Methods and Purpose

| Method                    | Purpose                                     |
| ------------------------- | ------------------------------------------- |
| `__init__`                | Initialize connector, client, and converter |
| `_collect_intelligence()` | Fetch and convert external data to STIX     |
| `process_message()`       | Main processing logic, work management      |
| `run()`                   | Start scheduler and begin execution         |

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

When the RabbitMQ queue capacity exceeds the defined threshold (for example, if queue_message_size is at 9.90 MB and queue_threshold is configured to 8 MB), the connector automatically switches to ‘Buffering’ mode.

In ‘Buffering’ mode, the connector’s execution is paused until the queue capacity falls below the specified threshold. The user interface displays visual indicators to signal this state change, including a warning message and a color change in the ‘Server Capacity’ section.

Buffering mode displayed on OpenCTI UI
![Buffering mode](./media/ui_buffering.png)

More details on our Filigran blog: [Auto backpressure Contrtol Article](https://filigran.io/auto-backpressue-control-octi-connectors/#:~:text=Display%20of%20Details%20for%20Connectors%20in%20%E2%80%98Buffering%E2%80%99%20Mode)

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

Here a reminder for work mannagement on [Common Implementation](./01-common-implementation.md#work-management)

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

### Collection Example Method

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

### Pagination Handling Example

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
4. **Batch appropriately** - Don't send too many objects at once (< 1000 recommended)

Reminder about cleanup_inconsistent_bundle: [Caution Clean Up Inconsistent Bundle](./01-common-implementation.md#creating-and-sending-bundles)

### Large Dataset Handling

When handling large datasets (e.g., 200k+ entities), batch processing is essential to avoid memory issues and provide progress visibility.

**Use case:** Importing a large MISP instance with hundreds of thousands of indicators.

Example of implementation

```python
def process_message(self) -> None:
    """Process large datasets in batches with individual work tracking."""
    stix_objects = self._collect_intelligence()

    batch_size = 500
    total_batches = (len(stix_objects) + batch_size - 1) // batch_size

    self.helper.connector_logger.info(
        "Processing large dataset",
        {"total_objects": len(stix_objects), "batch_size": batch_size, "total_batches": total_batches}
    )

    for batch_num, i in enumerate(range(0, len(stix_objects), batch_size), start=1):
        batch = stix_objects[i:i + batch_size]

        # Each batch gets its own work for progress tracking
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id,
            f"Import - Batch {batch_num}/{total_batches}"
        )

        # Include author and marking in each batch
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

        # Mark batch as complete
        self.helper.api.work.to_processed(
            work_id,
            f"Batch {batch_num}/{total_batches} - {len(batch)} objects"
        )

        # Update state after each batch to avoid data loss on failure
        self.helper.set_state({
            "last_batch": batch_num,
            "last_run": datetime.now(timezone.utc).isoformat()
        })

        self.helper.connector_logger.info(
            "Batch processed",
            {"batch": batch_num, "total": total_batches, "objects": len(batch)}
        )
```

**Key points:**
- **One work per batch** - Allows progress tracking in OpenCTI UI
- **Include metadata in each batch** - Author and markings must be in every bundle when using `cleanup_inconsistent_bundle=True`
- **Update state after each batch** - If the connector fails mid-import, the next run can resume from the last successful batch instead of restarting from scratch
- **Log progress** - Essential for monitoring long-running imports

---

## Rate Limiting

Use the `limiter` library for rate limiting and `tenacity` for retry logic:

```python
import requests
from limiter import Limiter
from tenacity import retry, stop_after_attempt, wait_exponential_jitter


class MyClient:
    def __init__(self, helper, base_url: str, api_key: str):
        self.helper = helper
        self.base_url = base_url
        self.api_key = api_key

        # Rate limiter: 10 requests per second, bucket capacity of 20
        self.rate_limiter = Limiter(
            rate=10,
            capacity=20,
            bucket="my_connector",
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential_jitter(initial=1, max=60, jitter=1),
    )
    def _request(self, endpoint: str):
        """Make request with retry logic."""
        response = requests.get(
            f"{self.base_url}/{endpoint}",
            headers={"Authorization": f"Bearer {self.api_key}"}
        )
        response.raise_for_status()
        return response.json()

    def get_data(self, endpoint: str):
        """Fetch data with rate limiting and retry."""
        with self.rate_limiter:
            return self._request(endpoint)
```

- **`limiter`** - Controls request rate to avoid hitting API limits
- **`tenacity`** - Retries failed requests with exponential backoff

See also: [Retry Logic in Common Implementation](./01-common-implementation.md#retry-logic)

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

### 1. Error Recovery Example

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

### 2. Graceful Degradation Example

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

Use case: A connector fetches from 3 different API endpoints. If one endpoint is down,
you still want to import data from the other 2 rather than failing the entire run.   

When to use it:
- Multiple independent data sources
- Optional enrichment steps
- Non-critical metadata fetching

When NOT to use it:
- Core authentication fails
- Critical data source is unavailable
- Data integrity depends on all sources

### 3. Deduplication Example

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

### 4. Logging Example

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

### API Client (src/my_client/api_client.py)

```python
import requests
from limiter import Limiter
from tenacity import retry, stop_after_attempt, wait_exponential_jitter


class MyClient:
    """API client with rate limiting and retry logic."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.rate_limiter = Limiter(rate=10, capacity=20, bucket="my_client")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential_jitter(initial=1, max=60, jitter=1),
    )
    def _request(self, endpoint: str, params: dict = None):
        response = requests.get(
            f"{self.base_url}/{endpoint}",
            headers={"Authorization": f"Bearer {self.api_key}"},
            params=params,
        )
        response.raise_for_status()
        return response.json()

    def get_threat_data(self, since: str) -> list:
        with self.rate_limiter:
            return self._request("threats", params={"since": since})
```

### Connector (src/connector/connector.py)

```python
import sys
from datetime import datetime, timezone

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from my_client import MyClient
from pycti import OpenCTIConnectorHelper


class MyThreatFeedConnector:
    """External Import connector for My Threat Feed."""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.work_id = None

        self.client = MyClient(
            base_url=str(self.config.my_connector.api_base_url),
            api_key=self.config.my_connector.api_key,
        )

        self.converter_to_stix = ConverterToStix(
            self.helper,
            author_name="My Threat Feed",
            tlp_level=self.config.my_connector.tlp_level,
        )

    def _initiate_work(self, name: str) -> str:
        self.work_id = self.helper.api.work.initiate_work(self.helper.connect_id, name)
        return self.work_id

    def _complete_work(self, message: str) -> None:
        if self.work_id:
            self.helper.api.work.to_processed(self.work_id, message)
            self.work_id = None

    def _collect_intelligence(self, since: str) -> list:
        """Collect intelligence from external source."""
        self.helper.connector_logger.info(
            "[CONNECTOR] Collecting intelligence", {"since": since}
        )

        data = self.client.get_threat_data(since=since)

        stix_objects = []
        for item in data:
            try:
                converted = self.converter_to_stix.convert_item(item)
                stix_objects.extend(converted)
            except Exception as e:
                self.helper.connector_logger.warning(
                    "[CONNECTOR] Failed to convert item",
                    {"item_id": item.get("id"), "error": str(e)},
                )
                continue

        return stix_objects

    def _send_bundle(self, stix_objects: list) -> None:
        """Send STIX bundle to OpenCTI."""
        # Add author and marking to bundle
        stix_objects.append(self.converter_to_stix.author)
        stix_objects.append(self.converter_to_stix.tlp_marking)

        bundle = self.helper.stix2_create_bundle(stix_objects)
        self.helper.send_stix2_bundle(
            bundle,
            work_id=self.work_id,
            cleanup_inconsistent_bundle=True,
        )

        self.helper.connector_logger.info(
            "[CONNECTOR] Bundle sent", {"objects_count": len(stix_objects)}
        )

    def process_message(self) -> None:
        """Main processing method."""
        try:
            current_start_time = datetime.now(timezone.utc).isoformat()
            current_state = self.helper.get_state()

            # Retrieve previous run information
            last_run_start = current_state.get("last_run_start") if current_state else None
            last_run_with_data = current_state.get("last_run_with_data") if current_state else None

            self.helper.connector_logger.info(
                "[CONNECTOR] Starting connector...",
                {
                    "connector_name": self.config.connector.name,
                    "last_run_start": last_run_start or "Never run",
                    "last_run_with_data": last_run_with_data or "Never ingested data",
                },
            )

            # Determine start date for fetching
            since = last_run_with_data or self.config.my_connector.import_from_date

            # Collect intelligence
            stix_objects = self._collect_intelligence(since)

            if stix_objects:
                # Initiate work and send data
                self._initiate_work(f"My Threat Feed - {current_start_time}")
                self._send_bundle(stix_objects)
                self._complete_work(f"Imported {len(stix_objects)} objects")
                last_run_with_data = datetime.now(timezone.utc).isoformat()
            else:
                self.helper.connector_logger.info("[CONNECTOR] No new data to import")

            # Update state
            new_state = {"last_run_start": current_start_time}
            if last_run_with_data:
                new_state["last_run_with_data"] = last_run_with_data

            self.helper.set_state(new_state)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[CONNECTOR] Connector stopped...")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """Start the connector with scheduled execution."""
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
```

### Entry Point (src/main.py)

```python
import traceback

from connector import ConnectorSettings, MyThreatFeedConnector
from pycti import OpenCTIConnectorHelper

if __name__ == "__main__":
    try:
        settings = ConnectorSettings()
        helper = OpenCTIConnectorHelper(config=settings.to_helper_config())

        connector = MyThreatFeedConnector(config=settings, helper=helper)
        connector.run()
    except Exception:
        traceback.print_exc()
        exit(1)
```

> [!TIP]
> A ready-to-use template with the base implementation is available at [templates/external-import](../templates/external-import). See the [CONTRIBUTING guidelines](../CONTRIBUTING.md) for step-by-step instructions on how to copy and set up the template.

---

## Next Steps

- Review [Internal Enrichment Specifications](./03-internal-enrichment-specifications.md)
- Review [Stream Connector Specifications](./04-stream-specifications.md)
- Review [Code Quality & Standards](./05-code-quality-standards.md)
