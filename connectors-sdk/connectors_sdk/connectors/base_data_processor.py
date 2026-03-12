"""Base data processor for connectors.

The data processor is responsible for collecting, transforming, and sending intelligence data to OpenCTI.
It provides a simple interface to customize the intelligence logic layer, like
fetching APIs and/or transforming external data to STIX 2.1 bundle.
All connectors should use a subclass of `BaseDataProcessor` and
at least implement their methods `collect` and `transform`.

Architecture:
- BaseDataProcessor: Collect, transform and send intelligence data to OpenCTI
- OpenCTIConnectorHelper: Communicate with OpenCTI platform (read/write data)
- WorkManager: Bundle data into works and send them in OpenCTI
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Generator

from connectors_sdk.connectors._work_manager import WorkManager, WorkManagerError
from connectors_sdk.logger.sdk_logger import sdk_logger as logger

if TYPE_CHECKING:
    from connectors_sdk.models import BaseIdentifiedObject
    from connectors_sdk.settings.base_settings import BaseConnectorSettings
    from connectors_sdk.state_manager.base_state_manager import (
        BaseConnectorStateManager,
    )
    from pycti import OpenCTIConnectorHelper


class BaseDataProcessor(ABC):
    """Base data processor for connectors.
    The data processor is responsible for collecting, transforming, and sending intelligence data to OpenCTI.
    MUST be subclassed to implement the `collect` and `transform` methods.
    The `send` method can be used as-is or overridden if needed.
    """

    def __init__(
        self,
        config: "BaseConnectorSettings",
        helper: "OpenCTIConnectorHelper",
        state_manager: "BaseConnectorStateManager",
    ):
        """Initialize the data processor with its dependencies."""
        self.config = config
        self.helper = helper
        self.state_manager = state_manager
        self.work_manager = WorkManager(helper)

        # Ensure OpenCTIConnectorHelper's logger is attached to SDK's logger as soon as it's reachable
        logger.attach_connector_helper_logger(self.helper)
        self._logger = logger.get_child("data_processor")

        self._logger.debug(f"{self.__class__.__name__} initialized succesfully")

    @abstractmethod
    def collect(self) -> Any:
        """Collect data from external sources (typically APIs). This method MUST be implemented in each connector.

        Notes:
            - The `collect` method can use the `self.config` to access the connector's configuration and
            make decisions based on it (e.g., fetch data from specific endpoints, use certain parameters, etc.).
            - The `collect` method can use the `self.state_manager` to access the connector's state and
            make decisions based on it (e.g., fetch data updated since the last run).
            - The returned value can be of any type, and will be passed as-is to the `transform` method for processing.
        """
        raise NotImplementedError  # pragma: no cover

    @abstractmethod
    def transform(
        self, data: Any
    ) -> (
        list["BaseIdentifiedObject"]
        | Generator[list["BaseIdentifiedObject"], None, None]
    ):
        """Transform the collected data into OpenCTI objects. This method MUST be implemented in each connector.

        Notes:
            - The `transform` method receives the data collected by the `collect` method as a
            parameter, and is responsible for transforming it into a format suitable for ingestion into OpenCTI.
            - The `transform` method can use the `self.config` to access the connector's configuration and
            make decisions based on it (e.g., transform data differently based on certain parameters).
            - The `transform` method can use the `self.state_manager` to access the connector's state and
            make decisions based on it (e.g., avoid transforming data that has already been ingested).
            - The returned value MUST be an iterable of `BaseIdentifiedObject` (OCTI models from `connectors_sdk.models`),
            or a generator yielding iterables of `BaseIdentifiedObject` (to handle large data sets in multiple bundles),
            and will be passed to the `send` method for sending to OpenCTI.
        """
        raise NotImplementedError  # pragma: no cover

    def send(
        self,
        data: (
            list["BaseIdentifiedObject"]
            | Generator[list["BaseIdentifiedObject"], None, None]
        ),
    ) -> None:
        """Send the transformed data to OpenCTI. This method can be used as-is or overridden if needed.

        Notes:
            - The `send` method receives the data transformed by the `transform` method as a parameter,
            and is responsible for sending it to OpenCTI.
            - The `send` method uses the `self.helper` to send data to OpenCTI (e.g., using `self.helper.send_stix2_bundle`).
            - The `send` method uses the `self.work_manager` to manage works in OpenCTI.
        """
        octi_objects_lists = data if isinstance(data, Generator) else [data]

        for octi_objects in octi_objects_lists:
            if octi_objects:
                now = datetime.now(timezone.utc)

                work_id = self.work_manager.init_work(
                    name=f"Work @ {now.isoformat(timespec='seconds')}"
                )

                try:
                    self._logger.debug(
                        "Converting OCTI objects to STIX format",
                        {"work_id": work_id, "octi_objects_count": len(octi_objects)},
                    )

                    stix_objects = [
                        obj.to_stix2_object()
                        for obj in octi_objects
                        if hasattr(obj, "to_stix2_object")
                    ]

                    self._logger.debug(
                        "OCTI objects converted to STIX format",
                        {"work_id": work_id, "stix_objects_count": len(stix_objects)},
                    )

                    self.work_manager.send_bundle(
                        work_id=work_id, stix_objects=stix_objects
                    )

                    self.work_manager.complete_work(
                        work_id=work_id,
                        message="Work completed successfully",
                    )
                except WorkManagerError as e:
                    self._logger.error(
                        "Failed to send bundle for work",
                        {"work_id": work_id, "error": str(e)},
                    )

                    self.work_manager.delete_work(work_id)
