"""Core connector as defined in the OpenCTI connector template."""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from connector.src.octi.global_config import GlobalConfig
    from pycti import OpenCTIConnectorHelper as OctiHelper  # type: ignore


class Connector:
    """Specifications of the external import connector.

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.

    ---

    Attributes
        - `config (ConfigConnector())`:
            Initialize the connector with necessary configuration environment variables

        - `helper (OpenCTIConnectorHelper(config))`:
            This is the helper to use.
            ALL connectors have to instantiate the connector helper with configurations.
            Doing this will do a lot of operations behind the scene.

        - `converter_to_stix (ConnectorConverter(helper))`:
            Provide methods for converting various types of input data into STIX 2.1 objects.

    ---

    Best practices
        - `self.helper.api.work.initiate_work(...)` is used to initiate a new work
        - `self.helper.schedule_iso()` is used to encapsulate the main process in a scheduler
        - `self.helper.connector_logger.[info/debug/warning/error]` is used when logging a message
        - `self.helper.stix2_create_bundle(stix_objects)` is used when creating a bundle
        - `self.helper.send_stix2_bundle(stix_objects_bundle)` is used to send the bundle to RabbitMQ
        - `self.helper.set_state()` is used to set state

    """

    def __init__(self, config: "GlobalConfig", helper: "OctiHelper") -> None:
        """Initialize the connector with necessary configuration environment variables
        and the helper to use.

        Arguments:

        ----------
        config : GlobalConfig
            Configuration object containing the connector's configuration variables.
        helper : OpenCTIConnectorHelper
            This is the helper from the OpenCTI client python library.

        """
        self._config = config
        self._helper = helper
        self._logger = self._helper.connector_logger

    def _process_callback(self) -> None:
        """Connector main process to collect intelligence."""
        ...

    def run(self) -> None:
        """Run the main process encapsulated in a scheduler.

        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        """
        self._helper.schedule_iso(
            message_callback=self._process_callback,
            duration_period=self._config.connector_config.duration_period,
        )
