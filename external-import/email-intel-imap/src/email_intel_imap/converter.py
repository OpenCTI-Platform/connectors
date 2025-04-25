from typing import Generator, Literal

import stix2
from base_connector import BaseConverter, ConnectorWarning
from base_connector.models import OpenCTIFile
from imap_tools.message import MailMessage
from pycti import OpenCTIConnectorHelper
from stix2.v21.vocab import REPORT_TYPE_THREAT_REPORT


class ConnectorConverter(BaseConverter):
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author_name: str,
        author_description: str,
        tlp_level: Literal["clear", "white", "green", "amber", "amber+strict", "red"],
        attachments_mime_types: list[str],
    ) -> None:
        super().__init__(
            helper=helper,
            author_name=author_name,
            author_description=author_description,
            tlp_level=tlp_level,
        )
        self.attachments_mime_types = attachments_mime_types

    def to_stix_objects(
        self, entity: MailMessage
    ) -> Generator[stix2.Report, None, None]:
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
                x_opencti_files=[
                    OpenCTIFile(
                        name=attachment.filename,
                        mime_type=attachment.content_type,
                        data=attachment.payload,
                    )
                    for attachment in entity.attachments
                    if attachment.content_disposition == "attachment"
                    and attachment.content_type in self.attachments_mime_types
                ],
            )
        except Exception as e:
            raise ConnectorWarning(
                "An error occurred while creating the Report, skipping..."
            ) from e
