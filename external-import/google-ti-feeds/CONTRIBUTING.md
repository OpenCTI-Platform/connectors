# Google TI Feeds Connector - Architecture Guide & Contribution Documentation

This document provides a comprehensive overview of the Google TI Feeds connector architecture, highlighting its modular design and explaining how to contribute to the project.

## 1. Introduction to the Connector Architecture

The Google Threat Intelligence Feeds connector is structured to efficiently retrieve, process, and transform threat intelligence data from Google into STIX 2.1 format for ingestion into OpenCTI. The architecture follows a modular, layered approach that separates concerns and enables easy extension through independent pipelines for each use case.

### Key Architectural Layers

```
connector/
├── src/
│   ├── custom/             # Domain-specific implementation
│   │   ├── configs/        # Connector-specific configuration
│   │   ├── exceptions/     # Custom exceptions
│   │   ├── fetchers/       # Data retrieval components (organized by use case)
│   │   ├── interfaces/     # Protocol definitions
│   │   ├── mappers/        # Data transformation components (organized by use case)
│   │   ├── meta/           # Metadata definitions
│   │   ├── models/         # Data models (organized by use case)
│   │   ├── processors/     # Data processors (organized by use case)
│   │   └── utils/          # Custom utility functions
│   ├── octi/               # OpenCTI integration layer
│   ├── stix/               # STIX data model layer
│   └── utils/              # Utility components and helpers
```

## 2. Core Components

### 2.1 OpenCTI Integration Layer (`src/octi/`)

This layer manages the interaction with the OpenCTI platform:

- `connector.py` - Main entry point implementing the connector interface
- `work_manager.py` - Manages work initialization and processing
- `batch_collector.py` - Accumulates objects into batches for efficient processing
- `pubsub.py` - Internal publish/subscribe mechanism for communication between components
- `global_config.py` - Configuration management

### 2.2 STIX Data Layer (`src/stix/`)

Provides a robust foundation for STIX 2.1 object manipulation:

- `v21/models/` - Comprehensive Pydantic models mapping to STIX 2.1 objects
- `octi/models/` - OpenCTI-specific extensions to standard STIX objects

### 2.3 Utilities (`src/utils/`)

Contains reusable components:

- `api_engine/` - Robust API client with circuit breaking, retries, and rate limiting

### 2.4 Custom Implementation Layer (`src/custom/`)

This is where domain-specific logic resides and where most contributions will occur. Each use case gets its own independent pipeline implementation.

## 3. Data Flow Architecture

### 3.1 Pipeline Pattern

Each use case in the connector follows its own independent pipeline pattern:

```
┌────────────┐     ┌────────────┐     ┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│          │     │          │     │           │     │           │     │            │
│ Fetchers ├────►│ Processors├────►│  Mappers  ├────►│   Batch   ├────►│ OpenCTI    │
│          │     │          │     │           │     │ Collector │     │ Work Queue │
└────────────┘     └────────────┘     └─────────────┘     └─────────────┘     └──────────────┘
     │                ▲                               ▲
     │                │                                │
     │                │                                │
     └───────────────────┴───────────────────────────────────────┘
            Pub/Sub Message Passing
```
The connector follows a pipeline pattern for data processing:

1. **Fetching** - External data retrieval (fetchers)
2. **Processing** - Data transformation and normalization (processors)
3. **Mapping** - Conversion to STIX objects (mappers)
4. **Batching** - Efficient bundling of objects (batch_collector)
5. **Sending** - Delivery to OpenCTI (work_manager)
### 3.2 Implemented Workflow for GTI Reports

The currently implemented use case is for Google Threat Intelligence Reports:

```
            │
            ▼
┌───────────────────────┐
│                   │
│    FetchReports   │
│                   │
└───────────┬───────────┘
          │
          ▼
┌───────────────────────┐         ┌─────────────────────────┐
│                   │         │  ProcessReports     |
| Reports published |        |  Convert reports to  │
│ to REPORTS_BROKER ├────────►│   STIX objects via   │
│                   │         │      mappers        │
└───────────────────────┘         └─────────┬──────────────┘
                                      │
                                      ▼
                                  ┌─────────────────────────┐
                                  │ Publish STIX objects│
                                  │  to FINAL_BROKER    │
                                  │                     │
                                  └─────────────┬───────────┘
                                              │
                                              ▼
                                  ┌─────────────────────────┐
                                  │ BatchCollector sends│
                                  │  to OpenCTI via     │
                                  │   WorkManager       │
                                  └─────────────────────────┘
```

## 4. Modularity and Extension

The `src/custom` directory is structured to facilitate easy extension through independent pipelines for different use cases.

### 4.1 One Pipeline Per Use Case

Each use case has its own dedicated pipeline orchestrator that:

1. Defines fetchers specific to the use case
2. Defines processors specific to the use case
3. Establishes communication channels via pub/sub
4. Orchestrates the flow of data from fetching to processing to bundling

### 4.2 Pipeline Initialization in connector.py

The main connector.py initializes and runs the appropriate pipelines:

```python
#3080-google-ti-feeds/git/external-import/google-ti-feeds/connector/src/octi/connector.py#L60-L89
def _process_callback(self) -> None:
    """Connector main process to collect intelligence.

    For now, it only imports reports from Google Threat Intelligence.
    But it can be extended to import other types of intelligence in the future.
    """
    error_flag = True
    split_work = self._config.connector_config.split_work
    try:
        gti_config = self._config.get_config_class(GTIConfig)
        if gti_config.import_reports:
            orchestrator = PipelineReportsOrchestrator(
                gti_config=gti_config,
                work_manager=self.work_manager,
                tlp_level=self._config.connector_config.tlp_level.lower(),
                batch_size=500,
                flush_interval=300,
                http_timeout=60,
                max_failures=5,
                cooldown_time=60,
                max_requests=20,
                period=60,
                max_retries=5,
                backoff=2,
                logger=self._logger,
                split_work=split_work,
            )
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                error_flag = loop.run_until_complete(orchestrator.run())
            finally:
                loop.run_until_complete(orchestrator.shutdown())
                loop.close()
    # Error handling code...
```

## 5. Contribution Guide: Adding a New Use Case

This section outlines the process for adding a new use case with its own pipeline to the connector.

### 5.1 Create a New Configuration Class

First, create a configuration class for your use case in `src/custom/configs/`:

```python
"""Configuration for your new use case."""

from typing import ClassVar, List

from pydantic import field_validator
from pydantic_settings import SettingsConfigDict

from connector.src.octi.interfaces.base_config import BaseConfig


class NewUseCaseConfig(BaseConfig):
    """Configuration for the new use case part of the connector."""

    yaml_section: ClassVar[str] = "new_usecase"
    model_config = SettingsConfigDict(env_prefix="new_usecase_")

    api_key: str
    api_url: str
    # Add other configuration parameters as needed

    # Add validators as needed
```

### 5.2 Create Data Models

Define Pydantic models for your use case in `src/custom/models/new_usecase/`:

```python
"""Models for the new use case."""

from pydantic import BaseModel, Field
from typing import List, Optional


class NewUseCaseEntity(BaseModel):
    """Model representing an entity in the new use case."""

    id: str = Field(..., description="Entity identifier")
    name: str = Field(..., description="Entity name")
    description: Optional[str] = Field(None, description="Entity description")
    # Add other fields as needed


class NewUseCaseResponse(BaseModel):
    """Model representing a response from the API."""

    data: List[NewUseCaseEntity]
    # Add metadata fields as needed
```

### 5.3 Implement Fetchers

Create fetchers for your use case in `src/custom/fetchers/new_usecase/`:

```python
"""Fetcher for the new use case."""

import logging
from typing import Dict, List, Optional

from connector.src.custom.interfaces.base_fetcher import BaseFetcher
from connector.src.custom.models.new_usecase.models import NewUseCaseEntity, NewUseCaseResponse
from connector.src.octi.pubsub import broker
from connector.src.custom.meta.new_usecase.meta import NEW_USECASE_BROKER, SENTINEL


class FetchNewUseCase(BaseFetcher):
    """Fetcher for the new use case."""

    def __init__(
        self,
        config,
        api_client,
        state: Dict[str, str],
        logger=None
    ):
        """Initialize the fetcher."""
        self._config = config
        self._api_client = api_client
        self._state = state
        self._logger = logger or logging.getLogger(__name__)

    async def fetch(self) -> bool:
        """Fetch data for the new use case."""
        try:
            # Implement your fetching logic

            # Publish the fetched data to the broker
            await broker.publish(NEW_USECASE_BROKER, data)

            # Signal the end of data
            await broker.publish(NEW_USECASE_BROKER, SENTINEL)

            return True
        except Exception as e:
            self._logger.error(f"Error fetching data: {str(e)}")
            return False
```

### 5.4 Create Mappers

Implement mappers for your use case in `src/custom/mappers/new_usecase/`:

```python
"""Maps entities from the new use case to STIX objects."""

from stix2.v21 import Identity, MarkingDefinition

from connector.src.custom.models.new_usecase.models import NewUseCaseEntity
from connector.src.stix.octi.models.entity_model import OctiEntityModel


class NewUseCaseToSTIXMapper:
    """Maps new use case entities to STIX objects."""

    def __init__(self, entity: NewUseCaseEntity, organization: Identity, tlp_marking: MarkingDefinition):
        """Initialize the mapper."""
        self.entity = entity
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self):
        """Convert the entity to a STIX object."""
        # Implement your mapping logic

        # Example:
        stix_object = OctiEntityModel.create(
            name=self.entity.name,
            description=self.entity.description,
            organization_id=self.organization.id,
            marking_ids=[self.tlp_marking.id]
        ).to_stix2_object()

        return stix_object
```

### 5.5 Create Processors

Implement processors for your use case in `src/custom/processors/new_usecase/`:

```python
"""Processor for the new use case."""

import logging
from typing import Optional

from connector.src.custom.interfaces.base_processor import BaseProcessor
from connector.src.custom.mappers.new_usecase.mapper import NewUseCaseToSTIXMapper
from connector.src.custom.meta.new_usecase.meta import NEW_USECASE_BROKER, FINAL_BROKER, SENTINEL
from connector.src.octi.pubsub import broker


class ProcessNewUseCase(BaseProcessor):
    """Processor for the new use case."""

    def __init__(self, organization, tlp_marking, logger=None):
        """Initialize the processor."""
        self.queue = broker.subscribe(NEW_USECASE_BROKER)
        self.organization = organization
        self.tlp_marking = tlp_marking
        self._logger = logger or logging.getLogger(__name__)

    async def process(self) -> bool:
        """Process the data from the broker queue."""
        while True:
            data = await self.queue.get()
            try:
                if data is SENTINEL:
                    break

                # Process the data
                stix_objects = []
                for entity in data:
                    mapper = NewUseCaseToSTIXMapper(entity, self.organization, self.tlp_marking)
                    stix_objects.append(mapper.to_stix())

                # Publish the STIX objects to the final broker
                await broker.publish(FINAL_BROKER, stix_objects)

            except Exception as e:
                self._logger.error(f"Error processing data: {str(e)}")
                return False
            finally:
                self.queue.task_done()

        return True
```

### 5.6 Create a Pipeline Orchestrator

Create a dedicated pipeline orchestrator for your use case:

```python
"""Pipeline orchestrator for the new use case."""

import asyncio
import logging
from typing import List, Optional

from connector.src.custom.fetchers.new_usecase.fetcher import FetchNewUseCase
from connector.src.custom.processors.new_usecase.processor import ProcessNewUseCase
from connector.src.custom.meta.new_usecase.meta import FINAL_BROKER, SENTINEL
from connector.src.octi.batch_collector import BatchCollector
from connector.src.octi.pubsub import broker
from connector.src.stix.octi.models.identity_organization_model import OctiOrganizationModel
from connector.src.stix.octi.models.tlp_marking_model import TLPMarkingModel
from connector.src.utils.api_engine.aio_http_client import AioHttpClient
from connector.src.utils.api_engine.api_client import ApiClient
from connector.src.utils.api_engine.circuit_breaker import CircuitBreaker
from connector.src.utils.api_engine.retry_request_strategy import RetryRequestStrategy


class PipelineNewUseCaseOrchestrator:
    """Pipeline orchestrator for the new use case."""

    def __init__(
        self,
        config,
        work_manager,
        tlp_level: str,
        batch_size: int,
        flush_interval: int,
        logger=None,
        **kwargs
    ):
        """Initialize the pipeline orchestrator."""
        self._config = config
        self._work_manager = work_manager
        self.tlp_level = tlp_level
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._logger = logger or logging.getLogger(__name__)

        # Initialize API client
        http_client = AioHttpClient(default_timeout=kwargs.get('http_timeout', 60), logger=self._logger)
        breaker = CircuitBreaker(max_failures=kwargs.get('max_failures', 5), cooldown_time=kwargs.get('cooldown_time', 60))
        limiter_config = {
            "key": f"new-usecase-api",
            "max_requests": kwargs.get('max_requests', 10),
            "period": kwargs.get('period', 60),
        }
        retry_request_strategy = RetryRequestStrategy(
            http=http_client,
            breaker=breaker,
            limiter=limiter_config,
            hooks=None,
            max_retries=kwargs.get('max_retries', 5),
            backoff=kwargs.get('backoff', 2),
            logger=self._logger,
        )
        self.api_client = ApiClient(strategy=retry_request_strategy, logger=self._logger)

        # Initialize work tracking
        self.work_id = self._work_manager.initiate_work(name="Google TI Feeds - New Use Case")
        self._running_tasks = []

    def _orchestration(self) -> None:
        """Set up the orchestration pipeline."""
        state = self._work_manager.get_state()

        # Create fetchers and processors
        self.fetchers = [
            FetchNewUseCase(self._config, self.api_client, state, self._logger)
        ]

        self.processors = [
            ProcessNewUseCase(self.organization, self.tlp_marking, self._logger)
        ]

    async def _create_tlp_marking(self) -> bool:
        """Create and publish the TLP marking."""
        try:
            self.tlp_marking = TLPMarkingModel(level=self.tlp_level.lower()).to_stix2_object()
            await broker.publish(FINAL_BROKER, self.tlp_marking)
            return True
        except Exception as e:
            self._logger.error(f"Failed to create TLP marking: {str(e)}")
            return False

    async def _create_organization(self) -> bool:
        """Create and publish the organization identity."""
        try:
            self.organization = OctiOrganizationModel.create(
                name="Google TI Feeds",
                description="Google Threat Intelligence Feeds.",
                contact_information="https://gtidocs.virustotal.com",
                organization_type="vendor",
                reliability=None,
                aliases=["GTI"],
            ).to_stix2_object()
            await broker.publish(FINAL_BROKER, self.organization)
            return True
        except Exception as e:
            self._logger.error(f"Failed to create organization: {str(e)}")
            return False

    async def run(self) -> bool:
        """Run the pipeline."""
        # Setup batch collector
        self.batch_collector = BatchCollector(
            topic=FINAL_BROKER,
            batch_size=self.batch_size,
            flush_interval=self.flush_interval,
            send_func=self.send_batch,
            sentinel_obj=SENTINEL,
        )
        batch_task = asyncio.create_task(self.batch_collector.run())
        self._running_tasks = [batch_task]

        # Create base objects
        org_success = await self._create_organization()
        tlp_success = await self._create_tlp_marking()

        # Setup pipeline
        self._orchestration()

        # Start processors
        proc_tasks = [asyncio.create_task(p.process()) for p in self.processors]
        self._running_tasks.extend(proc_tasks)

        # Start fetchers
        fetch_tasks = [asyncio.create_task(f.fetch()) for f in self.fetchers]
        self._running_tasks.extend(fetch_tasks)

        # Wait for fetchers to complete
        fetch_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)

        # Signal end of data
        await broker.publish(FINAL_BROKER, SENTINEL)

        # Wait for batch processor
        batch_success = await batch_task

        # Wait for processors
        proc_results = await asyncio.gather(*proc_tasks, return_exceptions=True)

        # Check for success
        all_success = (
            org_success and tlp_success and batch_success.success and
            all(not isinstance(r, Exception) for r in fetch_results) and
            all(not isinstance(r, Exception) for r in proc_results)
        )

        return all_success

    async def send_batch(self, batch: List) -> None:
        """Send a batch of entities for ingestion."""
        if not batch:
            return

        self._work_manager.send_bundle(work_id=self.work_id, bundle=batch)

    async def shutdown(self, timeout: int = 60) -> None:
        """Gracefully shutdown the pipeline."""
        for task in self._running_tasks:
            task.cancel()

        await asyncio.wait(
            self._running_tasks, timeout=timeout, return_when=asyncio.ALL_COMPLETED
        )

        await self.batch_collector.shutdown()

        self._work_manager.process_all_remaining_works()
```

### 5.7 Update the Connector.py

Modify the connector's `_process_callback` method to initialize your new pipeline:

```python
def _process_callback(self) -> None:
    """Connector main process to collect intelligence."""
    error_flag = True
    split_work = self._config.connector_config.split_work
    try:
        # Get configurations
        gti_config = self._config.get_config_class(GTIConfig)
        new_usecase_config = self._config.get_config_class(NewUseCaseConfig)

        # Initialize pipelines based on configuration
        if gti_config.import_reports:
            await self._run_pipeline(
                PipelineReportsOrchestrator(
                    gti_config=gti_config,
                    work_manager=self.work_manager,
                    tlp_level=self._config.connector_config.tlp_level.lower(),
                    batch_size=500,
                    flush_interval=300,
                    # Additional parameters...
                )
            )

        if new_usecase_config.enabled:
            await self._run_pipeline(
                PipelineNewUseCaseOrchestrator(
                    config=new_usecase_config,
                    work_manager=self.work_manager,
                    tlp_level=self._config.connector_config.tlp_level.lower(),
                    batch_size=500,
                    flush_interval=300,
                    # Additional parameters...
                )
            )

    except Exception as err:
        self._logger.error(f"An unexpected error occurred: {str(err)}")
    finally:
        # Cleanup code...

async def _run_pipeline(self, orchestrator):
    """Run a single pipeline orchestrator."""
    loop = asyncio.new_event_loop()
    try:
        asyncio.set_event_loop(loop)
        await orchestrator.run()
    finally:
        await orchestrator.shutdown()
        loop.close()
```

### 5.8 Create Metadata for Your Use Case

In `src/custom/meta/new_usecase/meta.py`:

```python
"""Metadata for the new use case pipeline."""

# Sentinel object to signal end of data
SENTINEL = object()

# Broker topics
PREFIX_BROKER = "new_usecase_ingest"
NEW_USECASE_BROKER = f"{PREFIX_BROKER}/entities"
FINAL_BROKER = f"{PREFIX_BROKER}/final"

# State keys
LAST_WORK_START_DATE_STATE_KEY = "last_work_start_date"
LAST_INGESTED_ENTITY_DATE_STATE_KEY = "last_ingested_entity_date"
```

### 5.9 Register Your Configuration

In `connector/__main__.py`, make sure your configuration is added to the global config:

```python
def main() -> None:
    """Define the main function to run the connector."""
    try:
        # Loading environment and configuration

        from connector.src.custom.configs.gti_config import GTIConfig
        from connector.src.custom.configs.new_usecase_config import NewUseCaseConfig
        from connector.src.octi.global_config import GlobalConfig

        global_config = GlobalConfig()
        global_config.add_config_class(GTIConfig)
        global_config.add_config_class(NewUseCaseConfig)

        # Initialize OpenCTI helper and connector
```

## 6. Key Design Patterns

Several design patterns facilitate the connector's modularity:

### 6.1 Pipeline Pattern

Each use case is implemented as an independent pipeline with its own fetchers, processors, and orchestrator. This enables:

- Independent configuration per use case
- Isolated error handling
- Separate state tracking
- Custom runtime behavior

### 6.2 Publish/Subscribe Pattern

Data flows between pipeline stages through a lightweight pub/sub system:

```3080-google-ti-feeds/git/external-import/google-ti-feeds/connector/src/octi/pubsub.py#L4-L36
"""The pubsub module provides a simple publish/subscribe mechanism using asyncio queues."""

import asyncio
from typing import Any, Dict, List, Optional


class PubSubBroker:
    """A singleton class that manages a publish/subscribe mechanism using asyncio queues."""

    _instance: Optional["PubSubBroker"] = None

    def __init__(self) -> None:
        """Initialize the PubSubBroker instance."""
        if hasattr(self, "_initialized"):
            return
        self._names: Dict[str, List[asyncio.Queue[Any]]] = {}
        self._initialized = True

    def __new__(cls) -> "PubSubBroker":
        """Create a singleton instance of the PubSubBroker class."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def subscribe(self, name: str) -> asyncio.Queue[Any]:
        """Subscribe to a queue for receiving messages."""
        queue: asyncio.Queue[Any] = asyncio.Queue()
        self._names.setdefault(name, []).append(queue)
        return queue

    async def publish(self, name: str, message: Any) -> None:
        """Publish a message to all subscribers of a given name."""
        for q in self._names.get(name, []):
            await q.put(message)


broker = PubSubBroker()
```

### 6.3 Protocol-Based Interface Definition

The connector uses Python's Protocol class for interface definitions:

```3080-google-ti-feeds/git/external-import/google-ti-feeds/connector/src/custom/interfaces/base_processor.py#L3-L13
"""The module defines a base processor interface for processing tasks asynchronously."""

from typing import Protocol


class BaseProcessor(Protocol):
    """Base interface for processors."""

    async def process(self) -> bool:
        """Process the task asynchronously."""
        ...
```

## 7. Error Handling

The connector implements a comprehensive error handling strategy:

```3080-google-ti-feeds/git/external-import/google-ti-feeds/connector/src/custom/exceptions/gti_base_error.py#L1-L8
"""Base class for GTI exceptions."""


class GTIBaseError(Exception):
    """Base class for GTI exceptions."""

    ...
```

Custom exception types for each use case help categorize issues:

- `GTIConfigurationError` - Configuration issues
- `GTIFetchingError` - Data retrieval problems
- `GTIProcessingError` - Data processing failures
- `GTISTIXMappingError` - STIX conversion issues

## 8. Contribution Guidelines

When contributing a new use case to this project:

1. **Maintain isolation** - Each use case should have its own dedicated pipeline
2. **Follow the structure** - Organize files by use case in each folder (fetchers, processors, mappers, etc.)
3. **Register configuration** - Add a dedicated configuration class for your use case
4. **Implement the interfaces** - Ensure your components implement the appropriate base classes
5. **Add pipeline orchestration** - Create a dedicated orchestrator for your pipeline
6. **Update connector.py** - Add logic to initialize your pipeline based on configuration
7. **Document your code** - Include clear docstrings and explanatory comments

## 9. Testing Your Contribution

1. **Local testing**:
   - Set up a development environment with the required dependencies
   - Use `.env` file to configure your connector or `config.yml` and start with env var `CONNECTOR_DEV_MODE=True`
   - Run the connector locally with `python -m connector`

2. **Configuration testing**:
   - Ensure your component handles configuration errors gracefully
   - Validate configuration parameters before use

3. **Pipeline testing**:
   - Test your pipeline's ability to handle errors
   - Verify proper shutdown behavior
   - Test the pipeline with varying load sizes

## Conclusion

The Google TI Feeds connector's modular architecture enables easy extension through independent pipelines for different use cases. By following the established pattern of one pipeline per use case, you can add new data sources and entity types while maintaining separation of concerns and robust error handling.

When contributing, create a complete pipeline for your use case and register it within the main connector to maintain the project's modular design.
