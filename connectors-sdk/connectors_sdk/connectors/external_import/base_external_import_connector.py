"""Base external import connector module.

This module provides the ``BaseExternalImportConnector`` class that serves as the foundation
for all external import connectors. It handles the common orchestration logic:
state management, scheduling, error handling, and running data processors.

Architecture::

    BaseExternalImportConnector
    ├── OpenCTIConnectorHelper → pycti bridge (created in _init_infrastructure)
    ├── ConnectorLogger        → Logging (wraps helper's AppLogger)
    ├── ExternalImportConnectorState → State persistence (last_run, custom fields)
    └── BaseDataProcessor[]    → process(): with work_manager: send(transform(collect()))
        └── WorkManager        → context manager: open work → send → close work
"""

import sys
from datetime import datetime, timezone

from connectors_sdk.connectors.external_import.base_data_processor import (
    BaseDataProcessor,
)
from connectors_sdk.connectors.external_import.logger import ConnectorLogger
from connectors_sdk.settings.base_settings import BaseConnectorSettings
from connectors_sdk.states.states import ExternalImportConnectorState
from pycti import OpenCTIConnectorHelper


class BaseExternalImportConnector:
    """Base class for external import connectors.

    This class provides the common orchestration logic for external import connectors:

    - State management (``last_run`` tracking via ``ExternalImportConnectorState``)
    - Scheduling (periodic execution via ``schedule_process``)
    - Error handling and logging
    - Running one or more ``BaseDataProcessor`` instances

    The ``OpenCTIConnectorHelper`` is created lazily in ``_init_infrastructure()``
    (called by ``start()``), so the connector can be instantiated without
    connecting to OpenCTI. This makes it easier to test.

    A connector may have **multiple processors** to handle different data types
    (e.g. one for indicators, one for reports, one for vulnerabilities).

    Attributes:
        config: The connector configuration (subclass of ``BaseConnectorSettings``).
        logger: The ``ConnectorLogger`` for logging without direct pycti dependency.
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
        >>> connector = BaseExternalImportConnector(
        ...     config=settings,
        ...     data_processors=[IndicatorProcessor()],
        ... )
        >>> connector.start()
    """

    def __init__(
        self,
        config: BaseConnectorSettings,
        data_processors: list[BaseDataProcessor],
        state: ExternalImportConnectorState | None = None,
    ) -> None:
        """Initialize the base external import connector.

        The ``OpenCTIConnectorHelper`` is **not** created here. It will be
        created when ``start()`` is called (via ``_init_infrastructure()``).

        Args:
            config: The connector configuration settings.
            data_processors: The list of ``BaseDataProcessor`` instances to run.
            state: Optional custom state instance. If ``None``, a default
                ``ExternalImportConnectorState`` is created in ``_init_infrastructure()``.
        """
        if not data_processors:
            raise ValueError("At least one BaseDataProcessor must be provided.")
        self.config = config
        self.data_processors = data_processors
        self._state = state

    def _init_infrastructure(self) -> None:
        """Create the OpenCTI connector helper and wire up all components.

        This method:
        1. Creates the ``OpenCTIConnectorHelper`` from the config
        2. Creates the ``ConnectorLogger``
        3. Initializes the state and attaches the helper to it
        4. Calls ``inject_dependencies()`` on each data processor
        """
        self._helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())
        self.logger = ConnectorLogger(self._helper)
        self.state = (
            self._state if self._state is not None else ExternalImportConnectorState()
        )
        self.state.attach_opencti_connector_helper(self._helper)
        for processor in self.data_processors:
            processor.inject_dependencies(
                config=self.config,
                helper=self._helper,
                logger=self.logger,
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
        connector_name = self.config.connector.name
        self.logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": connector_name},
        )

        try:
            self.state.load(force=True)

            if self.state.last_run:
                self.logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": str(self.state.last_run)},
                )
            else:
                self.logger.info("[CONNECTOR] Connector has never run...")

            self.logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": connector_name},
            )

            for processor in self.data_processors:
                processor.process()

            self.state.last_run = datetime.now(tz=timezone.utc)
            self.state.save()

            self.logger.info(
                f"{connector_name} connector successfully run, "
                f"storing last_run as {self.state.last_run}"
            )

        except (KeyboardInterrupt, SystemExit):
            self.logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": connector_name},
            )
            sys.exit(0)
        except Exception as err:
            self.logger.error(str(err))

    def start(self) -> None:
        """Start the connector with scheduled execution.

        Calls ``_init_infrastructure()`` to create the helper and wire up components,
        then uses ``OpenCTIConnectorHelper.schedule_process`` to run ``callback``
        at the interval defined by ``connector.duration_period`` in the configuration.

        The scheduler also checks the connector's queue size. If ``CONNECTOR_QUEUE_THRESHOLD``
        is set and the queue exceeds the threshold, the main process will be paused
        until the queue is reduced.

        Note:
            The ``config.connector`` must be a ``BaseExternalImportConnectorConfig``
            (or subclass) with a ``duration_period`` field.
        """
        self._init_infrastructure()
        self._helper.schedule_process(
            message_callback=self.callback,
            duration_period=self.config.connector.duration_period.total_seconds(),  # type: ignore[attr-defined]
        )
