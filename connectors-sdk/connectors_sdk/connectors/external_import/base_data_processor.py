"""Data processor module.

This module provides the abstract ``BaseDataProcessor`` base class that defines the contract
for collecting, transforming, and sending intelligence data from external sources.

Pipeline::

    process():
        with self.work_manager:
            self.send(self.transform(self.collect()))

``send()`` handles both cases transparently:

- ``transform()`` returns a ``list`` → sent as a single bundle
- ``transform()`` yields multiple ``list``s → each is sent as a separate bundle

A connector may have multiple ``BaseDataProcessor`` instances for different data types.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Generator
from typing import TYPE_CHECKING, Any, ClassVar

from connectors_sdk.connectors.external_import._work_manager import WorkManager
from connectors_sdk.logging.logger import Logger
from connectors_sdk.logging.sdk_logger import sdk_logger

if TYPE_CHECKING:
    from connectors_sdk.logging._base_logger import BaseLogger
    from connectors_sdk.settings.base_settings import BaseConnectorSettings
    from connectors_sdk.states.states import ExternalImportConnectorState
    from pycti import OpenCTIConnectorHelper


class BaseDataProcessor(ABC):
    """Abstract base class defining the data processing contract.

    Each ``BaseDataProcessor`` is responsible for:

    - Fetching raw data (``collect()``)
    - Converting it to bundle objects (``transform()``)
    - Sending them to OpenCTI (``send()``)

    ``transform()`` can either return a list (single bundle) or yield
    multiple lists (streaming). ``send()`` detects this and acts accordingly.

    The ``settings``, ``state`` and ``work_manager`` attributes are injected by
    ``ExternalImportConnector`` via ``inject_dependencies()``.

    The processor can read and write state fields (e.g. cursors, checkpoints)
    via ``self.state``, but it must **not** call ``state.load()`` or
    ``state.save()`` — that is handled by the base connector.

    Subclasses can override ``__init__`` to accept custom arguments
    (e.g. API clients, configuration values).

    Lifecycle:
        1. ``__init__()`` — called by connector code (custom args allowed)
        2. ``inject_dependencies()`` — called by the base connector (injects dependencies, creates WorkManager)
        3. ``post_init()`` — called by the base connector after ``inject_dependencies()`` (override for setup that needs dependencies)
        4. ``process()`` — called by the base connector (runs the pipeline)

    Attributes:
        _logger: A child of ``Logger``, named after the processor class.
        settings: The connector settings, injected via ``inject_dependencies()``.
        state: The ``ExternalImportConnectorState`` instance, injected via ``inject_dependencies()``.
        work_manager: The ``WorkManager`` instance, created in ``inject_dependencies()``.
        work_name: A human-readable name for the work created by this processor.
            Changing ``work_name`` between calls to ``send()`` (or between iterations
            in a generator-based ``transform()``) will close the current work and
            open a new one with the updated name.
    """

    logger: ClassVar[BaseLogger] = sdk_logger.get_child("BaseDataProcessor")

    settings: BaseConnectorSettings
    state: ExternalImportConnectorState
    work_manager: WorkManager
    work_name: str

    @classmethod
    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Attach a logger child named after the concrete `BaseDataProcessor` subclass."""
        super().__init_subclass__(**kwargs)
        package_name = cls.__module__.split(".")[0]
        cls.logger = Logger(f"{package_name}.{cls.__name__}")

    def inject_dependencies(
        self,
        settings: BaseConnectorSettings,
        state: ExternalImportConnectorState,
        helper: OpenCTIConnectorHelper,
    ) -> None:
        """Inject dependencies from the base connector and create the WorkManager.

        Called by ``ExternalImportConnector`` after helper initialization.
        Sets ``settings``, ``state``, and creates the ``WorkManager`` for this processor.

        Args:
            settings: The connector configuration settings.
            state: The ``ExternalImportConnectorState`` instance.
            helper: The ``OpenCTIConnectorHelper`` instance.
        """
        self.settings = settings
        self.state = state
        self.work_manager = WorkManager(helper)

    def post_init(self) -> None:  # noqa: B027
        """Hook called after ``inject_dependencies()`` wires up dependencies.

        Override this method to perform initialization that requires
        the injected dependencies (logger, state, settings, etc.).
        Called by ``ExternalImportConnector._init_dependencies()``.

        By default, does nothing.
        """

    def process(self) -> None:
        """Run the full processing pipeline: collect → transform → send.

        Opens a work via the ``WorkManager`` context manager, then
        composes ``send(transform(collect()))``.

        The work is automatically closed on exit (success, fail, or delete).
        """
        with self.work_manager:
            self.send(self.transform(self.collect()))

    @abstractmethod
    def collect(self) -> Any:
        """Collect raw intelligence from external sources.

        This method should fetch data from the external source (API, file, feed, etc.)
        and return it in its raw form. No STIX conversion should happen here.

        Can return a single value or yield multiple chunks for streaming::

            # All at once
            def collect(self):
                return api_client.get_all_indicators()

            # Streaming
            def collect(self):
                for page in api_client.get_indicators_paginated():
                    yield page

        Returns:
            Raw data from the external source, or a generator yielding chunks.
        """
        ...

    @abstractmethod
    def transform(self, data: Any) -> list[Any] | Generator[list[Any], None, None]:
        """Transform raw data into bundle objects.

        This method should convert the raw data from ``collect()`` into
        STIX 2.1 objects (using stix2 library objects or connectors-sdk model instances).

        Can return a single list or yield multiple lists for streaming::

            # Single bundle
            def transform(self, data):
                return [Indicator(...), Observable(...)]

            # Streaming — data is a generator from collect()
            def transform(self, data):
                for chunk in data:
                    yield [Indicator(...) for item in chunk]

        Args:
            data: The raw data returned (or yielded) by ``collect()``.

        Returns:
            A list of STIX/SDK objects, or a generator yielding lists.
        """
        ...

    def send(
        self, bundle_objects: list[Any] | Generator[list[Any], None, None]
    ) -> None:
        """Send bundle objects to OpenCTI via the work manager.

        If ``bundle_objects`` is a generator, each yielded list is sent
        as a separate bundle. Otherwise the list is sent as a single bundle.

        Args:
            bundle_objects: A list of STIX/SDK objects, or a generator yielding lists.
        """
        if isinstance(bundle_objects, Generator):
            for chunk in bundle_objects:
                if chunk:
                    self.work_manager.send(chunk, self.work_name)
        else:
            if bundle_objects:
                self.work_manager.send(bundle_objects, self.work_name)
