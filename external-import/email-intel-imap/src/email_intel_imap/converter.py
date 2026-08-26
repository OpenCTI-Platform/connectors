import base64
import html
import logging
from typing import Generator, Literal

import stix2
from base_connector import BaseConverter, ConnectorWarning
from base_connector.models import OpenCTIFile
from imap_tools.message import MailAttachment, MailMessage
from pycti import OpenCTIConnectorHelper
from stix2.v21.vocab import REPORT_TYPE_THREAT_REPORT

logger = logging.getLogger(__name__)


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

    @staticmethod
    def _get_html_body(entity: MailMessage) -> str:
        """
        Return the email body as HTML, ready to be stored in the Report content.

        `imap_tools` only fills `entity.html` when the message has a `text/html` part.
        For `text/plain` messages we fall back to `entity.text`, which is a raw string:
        its line breaks would be collapsed by the HTML renderer of the Report content
        field. Escape the body and materialize its newlines as `<br>` so that it is
        rendered the way it was sent.
        """
        if entity.html:
            return entity.html
        if not entity.text:
            # `x_opencti_content` is a required string: never return None, otherwise the
            # whole Report would be skipped for an email with an empty body.
            return ""
        normalized_text = entity.text.replace("\r\n", "\n").replace("\r", "\n")
        return html.escape(normalized_text, quote=False).replace("\n", "<br>\n")

    def to_stix_objects(
        self, entity: MailMessage
    ) -> Generator[stix2.Report, None, None]:
        """
        Convert the data into STIX 2.1 objects by using default parent class object definition.
        """

        def _is_supported(attachment: MailAttachment) -> bool:
            if attachment.content_disposition == "attachment":
                if attachment.content_type in self.attachments_mime_types:
                    return True
                logger.info(
                    f"{attachment.content_type} not in EMAIL_INTEL_ATTACHMENTS_MIME_TYPES{self.attachments_mime_types}, skipping..."
                )
            return False

        try:
            if not (name := entity.subject):
                name = f"<no subject> from {entity.from_}"
            attachments = [
                attachment
                for attachment in entity.attachments
                if _is_supported(attachment)
            ]
            yield self._create_report(
                name=name,
                published=entity.date,
                report_types=[REPORT_TYPE_THREAT_REPORT],
                x_opencti_content=self._get_html_body(entity),
                x_opencti_files=[
                    OpenCTIFile(
                        name=attachment.filename,
                        mime_type=attachment.content_type,
                        data=base64.b64encode(attachment.payload),
                        object_marking_refs=[self.tlp_marking.id],
                    )
                    for attachment in attachments
                ],
                description=(
                    f"**Email Received From**: {entity.from_}  \n"
                    f"**Email Received At**: {entity.date}  \n"
                    f"**Email Subject**: {name}  \n"
                    f"**Email Attachment Count**: {len(attachments)}  \n"
                    "  \n"
                    "Please consult the content section to view the email content."
                ),
            )
        except Exception as e:
            raise ConnectorWarning(
                "An error occurred while creating the Report, skipping..."
            ) from e
