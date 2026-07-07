from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import pycti
import stix2
from connector.settings import (
    CTRL_CHAR_RE,
    HTML_TAG_RE,
    PORTAL_LINK_DEFAULT_LABEL,
    ConfigConnector,
)


class ConversionError(Exception):
    pass


class StixPayloadUtils:
    @staticmethod
    def _sanitize(message: str) -> str:
        """Strip control chars; keep \\n, \\r, \\t (valid markdown formatting)."""
        if not message:
            return ""
        return CTRL_CHAR_RE.sub("", str(message))

    @staticmethod
    def _remove_html_tags(message: str) -> str:
        return HTML_TAG_RE.sub("", message)

    @staticmethod
    def _extract_domain(url: str, suffix: str = "") -> str:
        if not isinstance(url, str) or not url:
            return ""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
        except ValueError:
            # Obfuscated hosts (e.g. example.web[.]app/) break urlparse.
            rest = url.split("://", 1)[-1]
            domain = rest.split("/", 1)[0]
            path = "/" + rest.split("/", 1)[1] if "/" in rest else ""

        if path and path != "/":
            return domain + suffix
        return domain

    @staticmethod
    def is_ipv4(ipv4: str) -> bool:
        try:
            ipaddress.IPv4Address(ipv4)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def is_ipv6(ipv6: str) -> bool:
        try:
            ipaddress.IPv6Address(ipv6)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def determine_hash_algorithm_by_length(file_hash: str) -> str:
        if len(file_hash) == 64:
            return "SHA-256"
        elif len(file_hash) == 40:
            return "SHA-1"
        elif len(file_hash) == 32:
            return "MD5"
        msg = f"Could not determine hash type for {file_hash}. Only MD5, SHA1 and SHA256 hashes are supported"
        raise ValueError(msg)

    @staticmethod
    def _generate_tlp_obj(color: str) -> Any:
        if not color:
            return ConfigConnector.STIX_TLP_MAP.get("white")
        return ConfigConnector.STIX_TLP_MAP.get(
            str(color).lower(), ConfigConnector.STIX_TLP_MAP.get("white")
        )

    @staticmethod
    def _generate_main_observable_type(obj_type: str) -> str:
        return ConfigConnector.STIX_MAIN_OBSERVABLE_TYPE_MAP.get(obj_type)

    @staticmethod
    def _generate_malware_type(obj_type: str) -> str | None:
        if obj_type.lower() in ConfigConnector.STIX_MALWARE_TYPE_MAP:
            return obj_type.lower()
        else:
            return None

    @staticmethod
    def _generate_country_by_cc(country_code: str) -> str | None:
        return ConfigConnector.COUNTRIES.get(country_code)

    @staticmethod
    def _generate_stix_report_type(report_type: str) -> str:
        return ConfigConnector.STIX_REPORT_TYPE_MAP.get(report_type)


class BaseEntity(StixPayloadUtils):

    def __init__(
        self, name: str | list[str], c_type: str, tlp_color: str | None
    ) -> None:
        self.name = name
        self.c_type = c_type
        self.author = self._generate_author()
        self.tlp = self._generate_tlp_obj(tlp_color)
        self.config = ConfigConnector()
        self.statement_marking = self._generate_statement_marking()
        self.is_ioc = False
        self.description = ""

        self.valid_from = None
        self.valid_until: datetime = datetime.now(timezone.utc)

        self.stix_indicator = None
        self.stix_observable = None
        self.stix_sdo = None
        self.stix_common = None
        self.stix_relationships = list()

        self.external_references = list()

        self.stix_main_object = None
        self.stix_objects = None

    @staticmethod
    def _generate_author() -> Any:
        return stix2.Identity(
            id=pycti.Identity.generate_id(ConfigConnector.AUTHOR, "organization"),
            name=ConfigConnector.AUTHOR,
            identity_class="organization",
        )

    def _generate_statement_marking(self) -> Any | None:
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            marking_id = pycti.MarkingDefinition.generate_id(
                "statement", ConfigConnector.AUTHOR
            )
            statement_marking = stix2.MarkingDefinition(
                id=marking_id,
                definition_type="statement",
                definition={"statement": ConfigConnector.AUTHOR},
            )
            return statement_marking
        return None

    def get_markings(self) -> list[Any]:
        markings = [self.tlp]
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            markings.append(self.statement_marking)
        return markings

    def _labels_kv(self) -> dict[str, Any]:
        # preserve_manual_labels: omit x_opencti_labels so OpenCTI does not overwrite analyst labels on update.
        if self.config.get_extra_settings_bool("preserve_manual_labels", default=False):
            return {}
        return {"x_opencti_labels": getattr(self, "labels", None)}

    @staticmethod
    def stix_escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace("'", "\\'")

    def _generate_indicator(self) -> Any | None:
        return

    def _generate_observable(self) -> Any | None:
        return

    def _generate_sdo(self) -> Any | None:
        return

    def _generate_common(self) -> Any | None:
        return

    def set_description(self, text: str) -> None:
        if text is not None:
            self.description = (
                self._remove_html_tags(self._sanitize(text)) if text else ""
            )

    def set_valid_from(self, valid_from: datetime | None) -> None:
        if valid_from:
            self.valid_from = valid_from

    def set_valid_until(self, valid_until: datetime | None) -> None:
        if valid_until:
            self.valid_until = valid_until

    def _generate_relationship(
        self, source_id: str, target_id: str, relation_type: str = "based-on"
    ) -> Any:
        return stix2.Relationship(
            id=pycti.StixCoreRelationship.generate_id(
                relation_type, source_id, target_id
            ),
            relationship_type=relation_type,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
        )

    def generate_relationship(
        self,
        source_object: Any,
        target_object: Any,
        relation_type: str = "based-on",
    ) -> None:
        self.stix_relationships.append(
            self._generate_relationship(
                source_object.id, target_object.id, relation_type
            )
        )

    def _generate_external_reference(
        self, ref_id: str, ref_url: str, ref_desc: str
    ) -> Any:
        name_str = self.name if isinstance(self.name, str) else None
        if not name_str and isinstance(self.name, list) and self.name:
            name_str = next((n for n in self.name if isinstance(n, str)), None)
        source_name = (
            f"{PORTAL_LINK_DEFAULT_LABEL}: {name_str}"
            if name_str
            else PORTAL_LINK_DEFAULT_LABEL
        )
        return stix2.ExternalReference(
            external_id=pycti.ExternalReference.generate_id(
                ref_url, self._extract_domain(ref_url), ref_id
            ),
            source_name=source_name,
            url=ref_url,
            description=ref_desc or None,
        )

    def generate_external_references(
        self, reference_objects: list[tuple[str, str, str]]
    ) -> list[stix2.ExternalReference]:
        if reference_objects:
            self.external_references = [
                self._generate_external_reference(ref_id, ref_url, ref_desc)
                for ref_id, ref_url, ref_desc in reference_objects
            ]
        else:
            self.external_references = []
        return self.external_references

    def generate_stix_objects(self) -> BaseEntity:
        self.stix_observable = self._generate_observable()
        self.stix_sdo = self._generate_sdo()
        self.stix_common = self._generate_common()
        if self.is_ioc:
            self.stix_indicator = self._generate_indicator()
            if isinstance(self.stix_indicator, list):
                self.stix_objects = [
                    _
                    for _ in [
                        self.stix_observable,
                        self.stix_sdo,
                        self.stix_common,
                    ]
                    if _
                ]
                self.stix_objects += self.stix_indicator
            else:
                self.stix_objects = [
                    _
                    for _ in [
                        self.stix_indicator,
                        self.stix_observable,
                        self.stix_sdo,
                        self.stix_common,
                    ]
                    if _
                ]
            return self
        else:
            self.stix_objects = [
                _
                for _ in [
                    self.stix_observable,
                    self.stix_sdo,
                    self.stix_common,
                ]
                if _
            ]
            # Report may attach a labels Note; only Report sets _labels_note_sdo.
            labels_note_sdo = getattr(self, "_labels_note_sdo", None)
            if labels_note_sdo is not None:
                self.stix_objects.append(labels_note_sdo)
            return self

    def add_relationships_to_stix_objects(self) -> list[Any] | None:
        if self.stix_relationships:
            self.stix_objects += self.stix_relationships
        return self.stix_objects

    def bundle(self) -> stix2.Bundle:
        return stix2.Bundle(objects=self.stix_objects, allow_custom=True)


class _BaseIndicator(BaseEntity):
    def __init__(
        self,
        name: str | list[str],
        c_type: str,
        tlp_color: str,
        labels: list[str] | None,
        risk_score: str | None,
    ) -> None:
        super().__init__(name, c_type, tlp_color)

        self.labels = labels
        self.risk_score = risk_score

    def _create_pattern(self, pattern_name: str) -> str | None:
        return None

    def _generate_indicator(self) -> Any:
        return stix2.Indicator(
            id=pycti.Indicator.generate_id(self.name),
            name=self.name,
            description=self.description,
            pattern_type="stix",
            valid_from=self.valid_from,
            valid_until=self.valid_until,
            pattern=self._create_pattern(self.name),
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
            custom_properties={
                "x_opencti_score": self.risk_score or None,
                "x_opencti_main_observable_type": self._generate_main_observable_type(
                    self.c_type
                ),
                **self._labels_kv(),
            },
        )


class _BaseSDO(BaseEntity):
    def __init__(
        self,
        name: str,
        c_type: str,
        tlp_color: str,
        labels: list[str] | None,
        risk_score: str | None,
    ) -> None:
        super().__init__(name, c_type, tlp_color)

        self.labels = labels
        self.risk_score = risk_score


class _BaseCommon(BaseEntity):
    def __init__(
        self,
        name: str,
        c_type: str,
        tlp_color: str,
        labels: list[str] | None,
        risk_score: str | None,
    ) -> None:
        super().__init__(name, c_type, tlp_color)

        self.labels = labels
        self.risk_score = risk_score
