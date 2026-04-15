from connectors_sdk.models import OrganizationAuthor
from pycti import OpenCTIConnectorHelper


class ConverterToStix:
    """
    Provides methods for converting various types of input data into
    STIX 2.1 objects with connectors_sdk models.
    """

    def __init__(self, helper: OpenCTIConnectorHelper) -> None:
        """
        Initialize the converter with necessary configuration.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
        """
        self.helper = helper
        self.author = self.create_author()

    def create_author(self) -> OrganizationAuthor:
        """
        Create Author
        """
        author = OrganizationAuthor(
            name="Criminal IP", description="Criminal IP Cyber Threat Intelligence"
        )
        return author
