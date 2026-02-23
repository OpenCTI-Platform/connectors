"""
This module contains the implementation of the `IndicatorProcessor` class for the `PouetPouetConnector`.
"""

from time import sleep
from typing import TYPE_CHECKING, override

from connector.converter_to_stix import ConverterToStix
from connectors_sdk import BaseDataProcessor
from connectors_sdk.models import BaseIdentifiedObject
from pouet_pouet_client.api_client import PouetPouetClient

if TYPE_CHECKING:
    from connector.settings import ConnectorSettings
    from connector.state_manager import ConnectorStateManager
    from pycti import OpenCTIConnectorHelper


class IndicatorProcessor(BaseDataProcessor):
    """
    Indicator processor implementation for the `PouetPouetConnector`.
    This class inherits from `BaseDataProcessor` and is used to process the indicators retrieved
    from the Pouet API before it is ingested into OpenCTI.
    """

    def __init__(
        self,
        config: "ConnectorSettings",
        helper: "OpenCTIConnectorHelper",
        state_manager: "ConnectorStateManager",
    ):
        """
        Initialize the `IndicatorProcessor` with its dependencies.
        """
        super().__init__(
            config=config,
            helper=helper,
            state_manager=state_manager,
        )
        # Redundant assignments kept for typing purposes
        self.config = config
        self.state_manager = state_manager

        self.api_client = PouetPouetClient(
            helper=helper,
            base_url=self.config.pouet_pouet.api_base_url,
            api_key=self.config.pouet_pouet.api_key,
        )
        self.converter_to_stix = ConverterToStix(
            helper=helper,
            tlp_level=self.config.pouet_pouet.tlp_level,
        )

    @override
    def collect(self) -> list[dict]:
        """
        Collect data from the Pouet API.
        This method return retrieved data as a generator of dictionaries,
        where each dictionary represents an indicator to be ingested into OpenCTI.
        """
        pouet_indicators = self.api_client.get_indicators()

        return pouet_indicators

    @override
    def transform(self, data: list[dict]) -> list[list[BaseIdentifiedObject]]:
        """
        Transform the collected data into OCTI objects.
        This method takes the raw data collected from the Pouet API and transform it into
        the format expected by OpenCTI for ingestion.
        Returns a generator of lists of `BaseIdentifiedObject`, where each list contains the OCTI objects of one bundle.
        """
        octi_objects = [
            self.converter_to_stix.tlp_marking,
            self.converter_to_stix.author,
        ]

        for pouet_indicator in data:
            sleep(1)  # simulate long running conversion
            octi_indicator = self.converter_to_stix.create_indicator(pouet_indicator)
            octi_objects.append(octi_indicator)

        return octi_objects
