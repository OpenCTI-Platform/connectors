from datetime import datetime, timezone
from typing import Literal

from connectors_sdk.models import OrganizationAuthor, Report, TLPMarking
from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
        - `generate_id()` methods from `pycti` library MUST be used to generate the `id` of each entity (except observables),
        e.g. `pycti.Identity.generate_id(name="Source Name", identity_class="organization")` for a STIX Identity.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
    ):
        """
        Initialize the converter with necessary configuration.
        For log purpose, the connector's helper CAN be injected.
        Other arguments CAN be added (e.g. `tlp_level`) if necessary.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
            tlp_level (str): The TLP level to add to the created STIX entities.
        """
        self.helper = helper

        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.lower())

    @staticmethod
    def create_author() -> OrganizationAuthor:
        return OrganizationAuthor(
            name="Pouet Pouet",
            description="Pouet Pouet is a platform for pouetpoueting.",
        )

    @staticmethod
    def _create_tlp_marking(level):
        return TLPMarking(level=level)

    def create_report(self, report_data: dict) -> Report:
        return Report(
            name=report_data["name"],
            publication_date=datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            author=self.author,
            markings=[self.tlp_marking],
        )
