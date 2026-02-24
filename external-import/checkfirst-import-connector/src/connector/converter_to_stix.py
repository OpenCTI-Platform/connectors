from __future__ import annotations

"""STIX conversion helpers.

This file is adapted from the external-import template's `converter_to_stix.py`.
It provides a small conversion layer used by this connector to generate STIX
entities and build a bundle payload for `pycti`.

Notes:
- `pycti.*.generate_id()` is used for OpenCTI custom entities (e.g., Channel).
- STIX observables (e.g., URL) are created without explicit IDs.
"""

import ipaddress
from datetime import datetime
from typing import Iterable, Literal

import stix2

try:
    import validators  # type: ignore
except Exception:  # noqa: BLE001
    validators = None

from pycti import (
    Channel,
    CustomObjectChannel,
    CustomObservableMediaContent,
    Identity,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)


class ConverterToStix:
    """Convert dataset rows into STIX 2.1 objects + bundles."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        tlp_level: Literal[
            "clear",
            "white",
            "green",
            "amber",
            "amber+strict",
            "red",
        ] = "clear",
    ):
        self.helper = helper

        self.author = self.create_author()
        self.author_id = self.author["id"]
        self.tlp_marking = self._create_tlp_marking(level=tlp_level.lower())
        self.tlp_marking_id = (
            self.tlp_marking.get("id")
            if isinstance(self.tlp_marking, dict)
            else getattr(self.tlp_marking, "id", None)
        )

    @staticmethod
    def create_author() -> stix2.Identity:
        author = stix2.Identity(
            id=Identity.generate_id(name="CheckFirst", identity_class="organization"),
            name="CheckFirst",
            identity_class="organization",
            description="CheckFirst dataset import connector",
            allow_custom=True,
        )
        return author

    @staticmethod
    def _create_tlp_marking(
        level: str,
    ) -> stix2.MarkingDefinition | dict:
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                allow_custom=True,
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    def create_channel(
        self, *, name: str, source_url: str | None = None
    ) -> CustomObjectChannel:
        external_refs: list[stix2.ExternalReference] = []
        if source_url:
            external_refs.append(
                stix2.ExternalReference(source_name="source", url=source_url)
            )

        channel = CustomObjectChannel(
            id=Channel.generate_id(name=name),
            name=name,
            channel_types=["dataset"],
            created_by_ref=self.author_id,
            object_marking_refs=[self.tlp_marking_id] if self.tlp_marking_id else [],
            external_references=external_refs,
            allow_custom=True,
        )
        return channel

    def create_media_content(
        self,
        *,
        title: str | None,
        description: str | None,
        url: str,
        publication_date: datetime,
    ) -> CustomObservableMediaContent:
        media = CustomObservableMediaContent(
            title=title,
            description=description,
            url=url,
            publication_date=publication_date,
            custom_properties={
                "x_opencti_created_by_ref": self.author_id,
            },
        )
        return media

    def create_url(self, *, value: str) -> stix2.URL:
        return stix2.URL(
            value=value,
            custom_properties={
                "x_opencti_created_by_ref": self.author_id,
            },
        )

    def create_relationship(
        self,
        *,
        source_id: str,
        relationship_type: str,
        target_id: str,
        start_time: datetime | None = None,
    ) -> stix2.Relationship:
        rel = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type,
                source_id,
                target_id,
            ),
            relationship_type=relationship_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author_id,
            object_marking_refs=[self.tlp_marking_id] if self.tlp_marking_id else [],
            allow_custom=True,
            start_time=start_time,
        )
        return rel

    # ---------------------------
    # Template examples preserved
    # ---------------------------

    @staticmethod
    def _is_ipv6(value: str) -> bool:
        try:
            ipaddress.IPv6Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv4(value: str) -> bool:
        try:
            ipaddress.IPv4Address(value)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_domain(value: str) -> bool:
        if validators is None:
            return False
        return bool(validators.domain(value))

    def create_obs(
        self, value: str
    ) -> stix2.IPv4Address | stix2.IPv6Address | stix2.DomainName | None:
        if self._is_ipv6(value):
            return stix2.IPv6Address(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author_id,
                },
            )
        if self._is_ipv4(value):
            return stix2.IPv4Address(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author_id,
                },
            )
        if self._is_domain(value):
            return stix2.DomainName(
                value=value,
                custom_properties={
                    "x_opencti_created_by_ref": self.author_id,
                },
            )

        self.helper.connector_logger.error(
            "This observable value is not a valid IPv4 or IPv6 address nor DomainName",
            {"value": value},
        )
        return None

    def bundle_serialize(self, objects: Iterable[object]) -> str:
        """Create a STIX2 bundle JSON string for `helper.send_stix2_bundle()`."""
        stix_objects = [self.tlp_marking, self.author]
        stix_objects.extend(list(objects))
        bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)
        return bundle.serialize()
