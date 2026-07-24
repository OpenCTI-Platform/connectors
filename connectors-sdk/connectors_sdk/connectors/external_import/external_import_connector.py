"""Base external import connector module.

This module provides the ``ExternalImportConnector`` class that serves as the foundation
for all external import connectors. It handles the common orchestration logic:
state management, scheduling, error handling, and running data processors.

Architecture::

    ExternalImportConnector
    ├── OpenCTIConnectorHelper       → pycti bridge (created in _init_dependencies)
    ├── Logger                       → Logging (stdlib logging with pycti's CustomJsonFormatter)
    ├── ExternalImportConnectorState → State persistence (last_run, custom fields)
    └── BaseDataProcessor[]          → process(): with work_manager: send(transform(collect()))
        └── WorkManager              → context manager: open work → send → close work
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, ClassVar

from connectors_sdk.connectors.external_import.base_data_processor import (
    BaseDataProcessor,
)
from connectors_sdk.logging.logger import Logger
from connectors_sdk.logging.sdk_logger import sdk_logger
from connectors_sdk.settings.base_settings import BaseConnectorSettings
from connectors_sdk.states.states import ExternalImportConnectorState
from pycti import OpenCTIConnectorHelper

if TYPE_CHECKING:
    from connectors_sdk.logging._base_logger import BaseLogger


class ExternalImportConnector:
    """Base class for external import connectors.

    This class provides the common orchestration logic for external import connectors:

    - State management (``last_run`` tracking via ``ExternalImportConnectorState``)
    - Scheduling (periodic execution via ``schedule_process``)
    - Error handling and logging
    - Running one or more ``BaseDataProcessor`` instances

    The ``OpenCTIConnectorHelper`` is created lazily in ``_init_dependencies()``
    (called by ``start()``), so the connector can be instantiated without
    connecting to OpenCTI. This makes it easier to test.

    A connector may have **multiple processors** to handle different data types
    (e.g. one for indicators, one for reports, one for vulnerabilities).

    Attributes:
        logger(ClassVar): A ``Logger``'s child for logging, named after the connector class.
        settings: The connector configuration (subclass of ``BaseConnectorSettings``).
        state: The ``ExternalImportConnectorState`` for persisting connector state.
        data_processors: The list of ``BaseDataProcessor`` instances.

    Example:
        >>> class IndicatorProcessor(BaseDataProcessor):
        ...     work_name = "Indicators import"
        ...     def collect(self):
        ...         return api_client.get_indicators()
        ...     def transform(self, data):
        ...         return [to_stix(d) for d in data]
        ...     # send() inherited — handles list or generator from transform()
        ...
        >>> settings = MyConnectorSettings()
        >>> connector = ExternalImportConnector(
        ...     settings=settings,
        ...     data_processors=[IndicatorProcessor()],
        ... )
        >>> connector.start()
    """

    logger: ClassVar[BaseLogger] = sdk_logger.get_child("ExternalImportConnector")

    @classmethod
    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Attach a logger child named after the concrete `ExternalImportConnector` subclass."""
        super().__init_subclass__(**kwargs)
        package_name = cls.__module__.split(".")[0]
        cls.logger = Logger(f"{package_name}.{cls.__name__}")

    def __init__(
        self,
        settings: BaseConnectorSettings,
        data_processors: list[BaseDataProcessor],
        state: ExternalImportConnectorState | None = None,
    ) -> None:
        """Initialize the base external import connector.

        The ``OpenCTIConnectorHelper`` is **not** created here. It will be
        created when ``start()`` is called (via ``_init_dependencies()``).

        Args:
            settings: The connector configuration settings.
            data_processors: The list of ``BaseDataProcessor`` instances to run.
            state: Optional custom state instance. If ``None``, a default
                ``ExternalImportConnectorState`` is created in ``_init_dependencies()``.
        """
        if not data_processors:
            raise ValueError("At least one BaseDataProcessor must be provided.")
        self.data_processors = data_processors
        self.settings = settings
        self.state = state if state is not None else ExternalImportConnectorState()

        self.logger.debug(
            f"{self.__class__.__name__} instantiated successfully with {len(data_processors)} processor(s)",
            {"data_processors": [p.__class__.__name__ for p in data_processors]},
        )

    def _init_dependencies(self) -> None:
        """Create the OpenCTI connector helper and wire up all components.

        This method:
        1. Creates the ``OpenCTIConnectorHelper`` from the config
        2. Initializes the state and injects dependencies
        3. Calls ``inject_dependencies()`` on each data processor
        """
        self._helper = OpenCTIConnectorHelper(config=self.settings.to_helper_config())
        self.state.inject_dependencies(self._helper)
        for processor in self.data_processors:
            processor.inject_dependencies(
                settings=self.settings,
                helper=self._helper,
                state=self.state,
            )
            processor.post_init()

    def callback(self) -> None:
        """Main processing method for the connector.

        This method orchestrates the full processing pipeline:

        1. Load the connector state from OpenCTI
        2. Run each ``BaseDataProcessor`` inside its ``WorkManager`` context
        3. Update state with ``last_run``

        Override this method for fully custom processing logic.
        """
        self.logger.info("Connector's run starting")

        try:
            self.state.load(force=True)
            self.logger.info(
                "Connector's state loaded from OpenCTI",
                {"state": self.state.to_json()},
            )

            if self.state.last_run:
                self.logger.info(
                    "Connector's 'last_run' datetime found in state",
                    {"last_run": self.state.last_run.isoformat()},
                )
            else:
                self.logger.info("Connector has never run before")

            self.logger.info("Running connector's data processors")
            for processor in self.data_processors:
                processor.process()

            self.state.last_run = datetime.now(tz=timezone.utc)
            self.state.save()
            self.logger.info(
                "Connector's state saved on OpenCTI",
                {"state": self.state.to_json()},
            )

            self.logger.info(
                "Connector's run completed, 'last_run' datetime stored in state",
                {"last_run": self.state.last_run.isoformat()},
            )

        except (KeyboardInterrupt, SystemExit):
            self.logger.info("Connector stopped by user or system")
            sys.exit(0)
        except Exception as err:
            self.logger.error(f"Unexpected error: {err}")

    def start(self) -> None:
        """Start the connector with scheduled execution.

        Calls ``_init_dependencies()`` to create the helper and wire up components,
        then uses ``OpenCTIConnectorHelper.schedule_process`` to run ``callback``
        at the interval defined by ``connector.duration_period`` in the configuration.

        The scheduler also checks the connector's queue size. If ``CONNECTOR_QUEUE_THRESHOLD``
        is set and the queue exceeds the threshold, the main process will be paused
        until the queue is reduced.

        Note:
            The ``settings.connector`` must be a ``BaseExternalImportConnectorConfig``
            (or subclass) with a ``duration_period`` field.
        """
        self.logger.info("Connector's starting")

        self._init_dependencies()
        self._helper.schedule_process(
            message_callback=self.callback,
            duration_period=self.settings.connector.duration_period.total_seconds(),  # type: ignore[attr-defined]
        )
