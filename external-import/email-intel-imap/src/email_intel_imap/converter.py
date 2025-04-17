from typing import Any, Generator

import stix2
from base_connector.converter import BaseConverter
from imap_tools.message import MailMessage
from stix2.v21.vocab import REPORT_TYPE_THREAT_REPORT


class ConnectorConverter(BaseConverter[MailMessage, dict[str, Any]]):
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    author_name: str = "Email Intel IMAP"
    author_description: str = "Email Intel IMAP Connector"

    def to_stix(self, entity: MailMessage) -> Generator[stix2.Report, None, None]:
        """
        Convert the data into STIX 2.1 objects by using default parent class object definition.
        """
        try:
            if not (name := entity.subject):
                name = f"<no subject> from {entity.from_}"
            yield self._create_report(
                name=name,
                published=entity.date,
                report_types=[REPORT_TYPE_THREAT_REPORT],
                x_opencti_content=entity.text,
            )
        except Exception as e:
            self.helper.connector_logger.warning(
                "An error occurred while creating the Report, skipping...",
                {"error": str(e)},
            )
            # FIXME: Handle failed/retry somehow, maybe save state + email ID and more details
