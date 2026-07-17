from typing import Literal

from connectors_sdk.models import (
    URL,
    DomainName,
    ExternalReference,
    Note,
    OrganizationAuthor,
    TLPMarking,
)
from connectors_sdk.models.reference import Reference
from pycti import OpenCTIConnectorHelper

AUTHOR_NAME = "Doppel"
AUTHOR_DESCRIPTION = (
    "Doppel is a brand protection and digital risk protection platform used to "
    "detect and take down phishing sites, fraudulent domains and other online threats."
)
AUTHOR_URL = "https://www.doppel.com"

TLPLevel = Literal["clear", "white", "green", "amber", "amber+strict", "red"]

# Mapping from OpenCTI TLP marking definition to connectors_sdk TLPMarking level
TLP_DEFINITION_TO_LEVEL: dict[str, TLPLevel] = {
    "TLP:CLEAR": "clear",
    "TLP:WHITE": "white",
    "TLP:GREEN": "green",
    "TLP:AMBER": "amber",
    "TLP:AMBER+STRICT": "amber+strict",
    "TLP:RED": "red",
}


class ConverterToStix:
    """
    Provides methods for converting Doppel data into STIX 2.1 objects.

    Deterministic IDs are handled by the `connectors_sdk` models (author, note, ...)
    so stix2 never auto-generates non-deterministic IDs for SDOs.
    """

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
    ):
        """
        Initialize the converter.

        Args:
            helper (OpenCTIConnectorHelper): The helper of the connector. Used for logs.
        """
        self.helper = helper
        self.author = OrganizationAuthor(
            name=AUTHOR_NAME,
            description=AUTHOR_DESCRIPTION,
            external_references=[
                ExternalReference(source_name=AUTHOR_NAME, url=AUTHOR_URL)
            ],
        )

    @staticmethod
    def marking_from_tlp(tlp_definition: str | None) -> TLPMarking | None:
        """
        Build a TLP marking from an OpenCTI TLP definition (e.g. "TLP:AMBER").

        :param tlp_definition: The TLP definition of the source observable, if any.
        :return: A `TLPMarking` SDK model, or None if no/unknown TLP.
        """
        if not tlp_definition:
            return None
        level = TLP_DEFINITION_TO_LEVEL.get(tlp_definition.upper())
        if level is None:
            return None
        return TLPMarking(level=level)

    @staticmethod
    def build_external_reference(alert: dict) -> ExternalReference:
        """
        Build an external reference pointing to the created Doppel alert.

        :param alert: The alert payload returned by the Doppel API.
        :return: An `ExternalReference` SDK model.
        """
        return ExternalReference(
            source_name="Doppel Alert",
            url=alert.get("doppel_link"),
            external_id=alert.get("id"),
            description="Doppel alert created from the enriched observable.",
        )

    def build_observable(
        self,
        observable_type: str,
        value: str,
        external_reference: ExternalReference,
        marking: TLPMarking | None = None,
    ) -> URL | DomainName:
        """
        Rebuild the enriched observable with the Doppel external reference attached.

        The SDK generates a deterministic STIX id from the observable value, so the
        returned object merges with the original observable in OpenCTI.

        :param observable_type: The OpenCTI observable type ("url" or "domain-name").
        :param value: The observable value.
        :param external_reference: The Doppel alert external reference to attach.
        :param marking: The TLP marking of the source observable, if any.
        :return: A URL or DomainName SDK model.
        """
        common = {
            "value": value,
            "author": self.author,
            "markings": [marking] if marking is not None else None,
            "external_references": [external_reference],
        }
        if observable_type == "url":
            return URL(**common)
        return DomainName(**common)

    def build_note(
        self,
        observable_ref: str,
        alert: dict,
        takedown_requested: bool,
        takedown_comment: str,
        marking: TLPMarking | None = None,
    ) -> Note:
        """
        Build a Note summarizing the Doppel alert and the takedown request.

        :param observable_ref: The STIX id of the enriched observable.
        :param alert: The alert payload returned by the Doppel API.
        :param takedown_requested: Whether the takedown request succeeded.
        :param takedown_comment: The comment used for the takedown request.
        :param marking: The TLP marking of the source observable, if any.
        :return: A `Note` SDK model.
        """
        takedown_line = (
            f"- Takedown requested: {takedown_comment}"
            if takedown_requested
            else "- Takedown request failed (see connector logs)."
        )
        content = "\n".join(
            [
                "## Doppel Alert",
                "",
                f"- Alert ID: `{alert.get('id')}`",
                f"- Entity: {alert.get('entity')}",
                f"- Archetype: {alert.get('archetype')}",
                f"- Doppel link: {alert.get('doppel_link')}",
                takedown_line,
            ]
        )
        return Note(
            content=content,
            abstract=f"Doppel alert {alert.get('id')}",
            author=self.author,
            markings=[marking] if marking is not None else None,
            objects=[Reference(id=observable_ref)],
        )
