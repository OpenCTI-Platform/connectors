from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Any

import models as ds
import pycti
import stix2
from ciaops.collections_meta.ti import TICollections
from connector.settings import (
    COLLECTION_DISPLAY_LABEL,
    DEFAULT_TTL_DAYS,
    DOMAIN_RE,
    EMAIL_RE,
    NOTE_MAX_CONTENT,
    PORTAL_LINK_DEFAULT_LABEL,
    SEVERITY_COLOR_MAP,
    TI_NOTE_ID_ANCHOR,
    ConfigConnector,
)
from stix2.patterns import HashConstant
from support.portal_external_refs import portal_external_ref_rows
from support.text_normalize import normalize_description as _normalize_description_impl


class AdapterCoreMixin:
    def __init__(
        self,
        mitre_mapper: dict[str, str],
        collection: str,
        tlp_color: str | None,
        helper: Any,
        is_ioc: bool = False,
        threat_actor_name: str | None = None,
        config: ConfigConnector | None = None,
    ) -> None:
        self.mitre_mapper = mitre_mapper
        self.collection = collection
        self.helper = helper
        self.ta_global_label = self._set_global_label(self.collection)
        self.tlp_color = tlp_color
        self.is_ioc = is_ioc
        self.threat_actor_name = threat_actor_name
        self.config = config or ConfigConnector()
        self.helper.connector_logger.info("Initializing DataToSTIXAdapter")
        _dummy = ds.BaseEntity("", "", "amber")
        self.author = _dummy.author
        self.statement_marking = _dummy.statement_marking
        # Last-resort TLP for bundles that have no Report/Threat-Actor/Intrusion-Set
        # to inherit from. We default to amber (not white) so unknown-provenance data
        # is treated as moderately sensitive by downstream consumers.
        self.tlp_fallback = _dummy.tlp
        self.helper.connector_logger.info(
            f"DataToSTIXAdapter initialized with collection: {collection}, tlp_color: {tlp_color}, is_ioc: {is_ioc}"
        )

    def _format_threat_actor_label(self, name: str | None) -> str | None:
        return name.strip() if name and name.strip() else None

    def _format_malware_label(self, name: str | None) -> str | None:
        return name.strip() if name and name.strip() else None

    def _compose_account_group_labels(
        self,
        malware_names: list[str] | None = None,
        threat_actor_names: list[str] | None = None,
        source_types: list[str] | None = None,
        include_malware_labels: bool = True,
        include_threat_actor_labels: bool = True,
        include_source_type_labels: bool = True,
    ) -> tuple[list[str], list[str] | None]:
        return self._resolve_entity_labels(
            collection_label=self.collection,
            malware_names=malware_names if include_malware_labels else [],
            threat_actor_names=(
                threat_actor_names if include_threat_actor_labels else []
            ),
            source_types=source_types if include_source_type_labels else [],
        )

    @staticmethod
    def _normalize_list(value: Any) -> list[Any]:
        if not value:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _flatten_cell(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, list):
            if len(value) == 1:
                return str(value[0])
            if len(value) == 0:
                return ""
            return ", ".join(str(v) for v in value)
        return str(value)

    @staticmethod
    def _extract_name_list(values: Any) -> list[str]:
        result = []
        for item in AdapterCoreMixin._normalize_list(values):
            if isinstance(item, dict):
                name = item.get("name") or item.get("title")
                if name:
                    result.append(name)
            elif isinstance(item, str):
                result.append(item)
        return result

    @staticmethod
    def _map_severity(raw: str | None) -> str | None:
        if not raw:
            return raw
        return SEVERITY_COLOR_MAP.get(str(raw).lower(), raw)

    @staticmethod
    def _extract_string_value(item: Any) -> str | None:
        if isinstance(item, dict):
            val = item.get("value") or item.get("hash") or item.get("domain")
            return str(val).strip() if val else None
        if isinstance(item, str) and item.strip():
            return item.strip()
        return None

    def _get_text_preview(
        self, collection_key: str, text: str, default_max_len: int = 2000
    ) -> str:
        use_full = self.config.get_collection_settings(collection_key, "full_data")
        if use_full and str(use_full).lower() in ("true", "1", "yes"):
            return text
        max_len = self.config.get_collection_settings(
            collection_key, "data_preview_max_len"
        )
        try:
            max_len = int(max_len) if max_len is not None else default_max_len
        except (ValueError, TypeError):
            max_len = default_max_len
        if len(text) <= max_len:
            return text
        return text[:max_len] + "..."

    def _log_skipped(
        self, kind: str, value: Any, reason: str = "invalid format"
    ) -> None:
        """Single funnel for every value dropped before STIX emission.

        Logged at ``info`` so operators can audit exactly which upstream
        data never reached OpenCTI and why.
        """
        self.helper.connector_logger.info(
            f"{self.collection}: skipped {kind} ({reason}): " f"{str(value)[:256]!r}"
        )

    def _build_non_ioc_observable(
        self, cls: type, name: str, c_type: str, labels: list[str]
    ) -> Any:
        obj = cls(
            name=name,
            c_type=c_type,
            tlp_color=self._resolve_tlp_color(c_type),
            labels=labels,
        )
        obj.is_ioc = False
        obj.generate_stix_objects()
        return obj

    def _assemble_incident_bundle(
        self,
        related_objects: list[Any],
        incident: Any,
        note: stix2.Note,
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        stix_objects = []
        for obj in related_objects + [incident]:
            stix_objects += obj.stix_objects
        stix_objects.append(note)
        author_identity = self.author
        reliability = json_eval_obj.get("reliability")
        if reliability is not None:
            author_identity = stix2.Identity(
                id=author_identity.id,
                name=author_identity.name,
                identity_class=author_identity.identity_class,
                created=author_identity.created,
                modified=author_identity.modified,
                custom_properties={"x_opencti_reliability": str(reliability)},
                allow_custom=True,
            )
        stix_objects.append(author_identity)
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects.append(self.statement_marking)
        entities = [
            o for o in stix_objects if getattr(o, "type", None) != "relationship"
        ]
        relationships = [
            o for o in stix_objects if getattr(o, "type", None) == "relationship"
        ]
        return entities + relationships

    @staticmethod
    def _make_note(
        *,
        id_anchor: datetime,
        id_key: str,
        content: str,
        object_refs: list[str],
        author_id: str,
        markings: list[str],
        now: datetime,
        labels: list[str] | None = None,
        ext_refs: list[Any] | None = None,
        created: datetime | None = None,
        modified: datetime | None = None,
        max_len: int = NOTE_MAX_CONTENT,
    ) -> stix2.Note:
        """Single canonical factory for STIX 2.1 Notes.

        ID is derived from ``pycti.Note.generate_id(id_anchor, id_key)`` where
        ``id_key`` is a stable logical string such as ``"note_type:incident_id"``.
        This guarantees idempotent ingestion — re-pushing the same event updates
        the existing Note instead of creating a duplicate.
        """
        ts_created = created or now
        return stix2.Note(
            id=pycti.Note.generate_id(id_anchor, id_key),
            content=content[:max_len],
            object_refs=object_refs,
            created_by_ref=author_id,
            object_marking_refs=markings,
            created=ts_created,
            modified=modified or ts_created,
            labels=labels[:50] if labels else None,
            external_references=ext_refs if ext_refs else None,
            allow_custom=True,
        )

    @staticmethod
    def _portal_ext_refs(
        portal_links: list[Any],
        entity_name: str | None = None,
    ) -> list[stix2.ExternalReference]:
        """Convert portal-link tuples to ``stix2.ExternalReference`` objects.

        ``source_name`` is set to ``"Group-IB TI portal: <entity_name>"`` so
        the OpenCTI UI's Source column identifies the linked record at a
        glance; falls back to the bare portal label when no name is supplied.
        """
        source_name = (
            f"{PORTAL_LINK_DEFAULT_LABEL}: {entity_name}"
            if entity_name
            else PORTAL_LINK_DEFAULT_LABEL
        )
        refs = []
        for ref_id, ref_url, ref_desc in portal_links:
            if not ref_url:
                continue
            domain = ref_url.split("/")[2] if "://" in ref_url else ref_url
            refs.append(
                stix2.ExternalReference(
                    external_id=pycti.ExternalReference.generate_id(
                        ref_url, domain, ref_id
                    ),
                    source_name=source_name,
                    url=ref_url,
                    description=ref_desc or None,
                )
            )
        return refs

    def _finalize_stix_note(
        self,
        *,
        name: str,
        content: str,
        object_refs: list[str],
        labels: list[str] | None = None,
        portal_links: list[Any] | None = None,
        created: datetime | None = None,
        modified: datetime | None = None,
    ) -> stix2.Note:
        """Build and return a ``stix2.Note`` with a stable, content-independent ID.

        ID key: ``"{name}:{first_object_ref}"`` — unique per (incident, note role).
        Re-ingestion of the same event always produces the same ID in OpenCTI.
        """
        tlp = self._tlp_marking_for("note")
        id_key = f"{name}:{object_refs[0] if object_refs else 'unknown'}"
        return self._make_note(
            id_anchor=TI_NOTE_ID_ANCHOR,
            id_key=id_key,
            content=content,
            object_refs=object_refs,
            author_id=self.author.id,
            markings=[tlp.id],
            now=datetime.now(timezone.utc),
            labels=labels,
            ext_refs=(
                self._portal_ext_refs(portal_links, entity_name=name)
                if portal_links
                else None
            ),
            created=created,
            modified=modified,
        )

    def _compose_observable_labels(self) -> tuple[list[str], list[str] | None]:
        ta_names = []
        if (
            self.config.get_setting_bool(
                self.collection,
                "add_threat_actor_label_to_observables",
                default=False,
            )
            and self.threat_actor_name
        ):
            ta_names = [self.threat_actor_name]
        return self._resolve_entity_labels(
            collection_label=self.collection,
            threat_actor_names=ta_names,
        )

    def _log_tlp_applied(
        self, ds_obj: Any, sdo_type: str, name: str | None = None
    ) -> None:
        tlp_str = self._resolve_tlp_color(sdo_type)
        try:
            bundle_json = ds_obj.bundle().serialize(pretty=True)
        except Exception:
            try:
                bundle_json = str(ds_obj.bundle())
            except Exception:
                bundle_json = repr(ds_obj)
        obj_name = name or getattr(ds_obj, "name", None) or "<no-name>"
        self.helper.connector_logger.debug(
            f"TLP '{tlp_str}' applied to object type='{sdo_type}', name='{obj_name}'. Full object (bundle):\n{bundle_json}"
        )

    def _resolve_tlp_color(self, sdo_type: str) -> str:
        """Return the TLP color name (``"white"|"green"|"amber"|"red"|...``)."""
        try:
            incoming = str(self.tlp_color).lower() if self.tlp_color else None
        except Exception:
            incoming = None

        if incoming in ConfigConnector.STIX_TLP_MAP:
            return incoming

        default_map = getattr(ConfigConnector, "DEFAULT_TLP_BY_SDO", {})
        return default_map.get(sdo_type, "amber")

    def _tlp_marking_for(self, sdo_type: str) -> Any:
        """Return the ``stix2.MarkingDefinition`` object for an SDO's TLP.

        ``_resolve_tlp_color`` returns the *color name* (a string), suitable
        for ``ds.X(tlp_color=...)`` constructors that internally convert it.
        For places that need to emit the marking SDO into a STIX bundle or
        reference it via ``object_marking_refs``, use this method.
        """
        color = self._resolve_tlp_color(sdo_type)
        return ConfigConnector.STIX_TLP_MAP.get(
            color, ConfigConnector.STIX_TLP_MAP["white"]
        )

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

    @classmethod
    def is_valid_domain(cls, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        v = value.strip()
        if not v or len(v) > 253:
            return False
        if "://" in v or " " in v or "/" in v:
            return False
        return bool(DOMAIN_RE.match(v))

    @classmethod
    def is_valid_url(cls, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        v = value.strip()
        if not v or " " in v:
            return False
        # Minimal: must have a scheme and a host part.
        return v.startswith(("http://", "https://", "ftp://", "ftps://"))

    @classmethod
    def is_valid_email(cls, value: Any) -> bool:
        if not isinstance(value, str):
            return False
        v = value.strip().strip("<>").strip()
        if not v or len(v) > 254:
            return False
        return bool(EMAIL_RE.match(v))

    @classmethod
    def normalize_email(cls, value: Any) -> str | None:
        """Return canonical lowercased-domain form, or None if invalid."""
        if not isinstance(value, str):
            return None
        v = value.strip().strip("<>").strip()
        if not cls.is_valid_email(v):
            return None
        local, _, domain = v.rpartition("@")
        return f"{local}@{domain.lower()}"

    @staticmethod
    def normalize_description(value):
        """Clean an upstream HTML/text description for OpenCTI rendering.

        Delegates to ``support.text_normalize.normalize_description``.
        """
        return _normalize_description_impl(value)

    @staticmethod
    def _valid_hash(hash_value: str, hash_type: str) -> bool:
        try:
            HashConstant(value=hash_value, type=hash_type)
            return True
        except ValueError:
            return False

    def _set_global_label(self, collection: str) -> str | None:
        self.helper.connector_logger.info(
            f"Setting global label for collection: {collection}"
        )
        if collection in ["apt/threat", "apt/threat_actor"]:
            self.helper.connector_logger.debug("Collection identified as nation_state")
            return "nation_state"
        elif collection in ["hi/threat", "hi/threat_actor", "hi/open_threats"]:
            self.helper.connector_logger.debug("Collection identified as criminal")
            return "cybercriminal"
        self.helper.connector_logger.warning(
            f"No global label set for collection: {collection}"
        )
        return None

    def _store_report_labels_in_note(self) -> bool:
        return self.config.get_setting_bool(
            self.collection, "store_report_labels_in_note", default=False
        )

    def _should_include_label_type(self, label_type: str) -> bool:
        key = f"include_{label_type}"
        if label_type == "threat_actor_name":
            key = "include_threat_actor_labels"
        elif label_type == "malware_name":
            key = "include_malware_labels"
        elif label_type == "source_type":
            key = "include_source_type_labels"
        elif label_type == "nation_state":
            key = "include_nation_state_label"
        elif label_type == "cybercriminal":
            key = "include_cybercriminal_label"
        elif label_type == "context":
            key = "include_context_label"
        return self.config.get_setting_bool(self.collection, key, default=True)

    def _resolve_entity_labels(
        self,
        collection_label: str | None = None,
        threat_actor_names: list[str] | None = None,
        malware_names: list[str] | None = None,
        source_types: list[str] | None = None,
        context_labels: list[str] | None = None,
        include_nation_state: bool = False,
        include_cybercriminal: bool = False,
    ) -> tuple[list[str], list[str] | None]:
        out = []
        local_custom_tag = self.config.get_collection_settings(
            self.collection.replace("/", "_"), "local_custom_tag"
        )
        if local_custom_tag is not None:
            s = str(local_custom_tag).strip()
            if s and s.lower() not in ("null", "none"):
                out.append(s)
        if collection_label:
            out.append(COLLECTION_DISPLAY_LABEL.get(collection_label, collection_label))
        if self._should_include_label_type("threat_actor_name"):
            for n in threat_actor_names or []:
                lb = self._format_threat_actor_label(n)
                if lb:
                    out.append(lb)
        if self._should_include_label_type("malware_name"):
            for n in malware_names or []:
                lb = self._format_malware_label(n)
                if lb:
                    out.append(lb)
        if self._should_include_label_type("source_type"):
            for s in source_types or []:
                if s:
                    out.append(str(s))
        if include_nation_state and self._should_include_label_type("nation_state"):
            out.append("nation_state")
        if include_cybercriminal and self._should_include_label_type("cybercriminal"):
            out.append("cybercriminal")
        if self._should_include_label_type("context"):
            for c in context_labels or []:
                if c:
                    out.append(c)
        return (out, None)

    @staticmethod
    def _retrieve_link(
        obj: dict[str, Any] | list[Any],
    ) -> list[tuple[str, str, str]]:
        return portal_external_ref_rows(obj)

    def _retrieve_date(
        self, obj: dict[str, Any], key: str, alter_key: str | None = None
    ) -> datetime:
        self.helper.connector_logger.debug(
            f"Retrieving date for key: {key}, alternate key: {alter_key}"
        )
        date_raw = obj.get(key, "")
        if not date_raw and alter_key:
            date_raw = obj.get(alter_key, "")

        if not date_raw:
            return datetime.now(timezone.utc)

        if date_raw.startswith("00"):
            self.helper.connector_logger.warning(f"Wrong format of date: {date_raw}")
            return datetime.now(timezone.utc)

        try:
            _datetime = datetime.fromisoformat(date_raw)
            self.helper.connector_logger.debug(f"Successfully parsed date: {date_raw}")
        except (Exception,):
            self.helper.connector_logger.warning(
                f"Failed to format date: {date_raw!r}. Using default."
            )
            _datetime = datetime.now(timezone.utc)

        return _datetime

    def _retrieve_ttl_dates(
        self, obj: dict[str, Any]
    ) -> tuple[datetime | None, datetime | None]:
        self.helper.connector_logger.debug("Retrieving TTL dates")
        ttl = obj.get("ttl")
        if not ttl:
            ttl = DEFAULT_TTL_DAYS
            self.helper.connector_logger.debug(
                f"No TTL provided, using default: {DEFAULT_TTL_DAYS} days"
            )

        date_modified_raw = obj.get("date-modified", "")
        date_created_raw = obj.get("date-created", "")

        if date_modified_raw:
            if date_modified_raw.startswith("00"):
                self.helper.connector_logger.warning(
                    f"Wrong format of date_modified: {date_modified_raw}"
                )
                date_modified_raw = None

        if date_created_raw:
            if date_created_raw.startswith("00"):
                self.helper.connector_logger.warning(
                    f"Wrong format of date_created: {date_created_raw}"
                )
                date_created_raw = None

        if not date_modified_raw and not date_created_raw:
            self.helper.connector_logger.warning(
                "No correct date found. "
                "'None' will be used to further set the value by the user or system"
            )
            base_ttl_datetime = None
        else:
            if date_modified_raw:
                base_ttl_raw_date = date_modified_raw
            else:
                base_ttl_raw_date = date_created_raw

            try:
                base_ttl_datetime = datetime.fromisoformat(base_ttl_raw_date)
                self.helper.connector_logger.debug(
                    f"Successfully parsed base TTL date: {base_ttl_raw_date}"
                )
            except (Exception,):
                self.helper.connector_logger.warning(
                    f"Failed to format base_ttl_raw_date: {base_ttl_raw_date}. "
                    "'None' will be used to further set the value by the user or system."
                )
                base_ttl_datetime = None

        valid_from = base_ttl_datetime
        valid_until = (
            base_ttl_datetime + timedelta(days=ttl)
            if base_ttl_datetime
            else base_ttl_datetime
        )
        self.helper.connector_logger.info(
            f"TTL dates set: valid_from={valid_from}, valid_until={valid_until}"
        )
        return valid_from, valid_until

    def _resolve_ttl_days(
        self,
        collection_key: str,
        json_date_obj: dict[str, Any] | None = None,
        default: int = DEFAULT_TTL_DAYS,
    ) -> int:
        for raw in (
            self.config.get_collection_settings(collection_key, "ttl"),
            (json_date_obj or {}).get("ttl"),
        ):
            if raw is not None:
                try:
                    val = int(raw)
                    if val > 0:
                        return val
                    self.helper.connector_logger.warning(
                        f"{collection_key}: non-positive TTL ignored: {raw!r}"
                    )
                except (TypeError, ValueError):
                    self.helper.connector_logger.warning(
                        f"{collection_key}: non-integer TTL ignored: {raw!r}"
                    )
                    continue
        return default

    @staticmethod
    def _generate_relations(
        main_obj: Any,
        related_objects: list[Any],
        helper: Any,
        relation_type: str | None = None,
        is_ioc: bool = False,
    ) -> Any:
        relation_type_map = {
            "incident": {
                "user-account": "related-to",
                "domain-name": "related-to",
                "url": "related-to",
                "ipv4-addr": "related-to",
                "ipv6-addr": "related-to",
                "file": "related-to",
                "indicator": "related-to",
                "malware": "uses",
                "threat-actor": "attributed-to",
                "intrusion-set": "attributed-to",
                "email-addr": "related-to",
                # Financial observables (compromised card / account data).
                "payment-card": "related-to",
                "bank-account": "related-to",
                # Locations (city / country / region) attached to compromised
                # incidents (e.g. masked_card → card_issuer + cnc countries).
                # OpenCTI does not allow incident --[located-at]-->; use the
                # generic relationship.
                "location": "related-to",
            },
            "threat-actor": {
                # SDO
                "attack-pattern": "uses",
                "malware": "uses",
                "vulnerability": "targets",
                # Common
                "base-location": "located-at",
                "target-location": "targets",
            },
            "intrusion-set": {
                # SDO
                "attack-pattern": "uses",
                "malware": "uses",
                "vulnerability": "targets",
                # Common
                "base-location": "originates-from",
                "target-location": "targets",
                # Threat
                "threat-actor": "attributed-to",
            },
            "indicator": {
                # Observable
                "file": "based-on",
                "domain-name": "based-on",
                "url": "based-on",
                "ipv4-addr": "based-on",
                "ipv6-addr": "based-on",
                "email-addr": "based-on",
                # Threat
                "threat-actor": "indicates",
                "intrusion-set": "indicates",
                "malware": "indicates",
            },
            "ipv4-addr": {
                # SDO
                "threat-actor": "related-to",
                "intrusion-set": "related-to",
                # OpenCTI allows "communicates-with" only FROM Malware TO an
                # observable; observable-first edges use the generic type.
                "malware": "related-to",
                # Observable
                "domain-name": "related-to",
                "url": "related-to",
                "ipv4-addr": "related-to",
                # Geo: DDoS target country → Location SDO
                "location": "related-to",
                "target-location": "related-to",
            },
            "ipv6-addr": {
                # SDO
                "threat-actor": "related-to",
                "intrusion-set": "related-to",
                "malware": "related-to",
                # Observable
                "domain-name": "related-to",
                "url": "related-to",
                "ipv6-addr": "related-to",
                "location": "related-to",
                "target-location": "related-to",
            },
            "domain-name": {
                # SDO
                "threat-actor": "related-to",
                "intrusion-set": "related-to",
                "malware": "related-to",
                # Observable
                "domain-name": "related-to",
                # STIX 2.1: domain-name → ipv4/ipv6 is "resolves-to". OpenCTI
                # accepts the same vocab for the relationship type. Needed
                # for malware/cnc bundles where the CnC primary is a domain
                # with one or more resolved IP secondaries.
                "ipv4-addr": "resolves-to",
                "ipv6-addr": "resolves-to",
                "url": "related-to",
                "location": "related-to",
                "target-location": "related-to",
            },
            "url": {
                # SDO
                "threat-actor": "related-to",
                "intrusion-set": "related-to",
                "malware": "related-to",
                # Observable
                "url": "related-to",
                "domain-name": "related-to",
                "ipv4-addr": "related-to",
                "ipv6-addr": "related-to",
                "location": "related-to",
                "target-location": "related-to",
            },
            "file": {
                # SDO
                "threat-actor": "related-to",
                "intrusion-set": "related-to",
                "malware": "related-to",
                # Observable
                "file": "related-to",
                # malware/cnc primary may be a file (sample hash); CnC
                # network endpoints linked back as context.
                "domain-name": "related-to",
                "url": "related-to",
                "ipv4-addr": "related-to",
                "ipv6-addr": "related-to",
            },
            "vulnerability": {},
            "report": {},
            "malware": {
                # Malware (main) to CnC observables (related)
                "ipv4-addr": "communicates-with",
                "ipv6-addr": "communicates-with",
                # Companion graph emitted by _build_malware_companions:
                # ta_list / threat_actor_list → Threat-Actor, linked_malware
                # → sibling Malware, mitre_matrix → Attack-Pattern,
                # source_countries → Location (typed as base-location).
                "threat-actor": "authored-by",
                "intrusion-set": "authored-by",
                "malware": "related-to",
                "attack-pattern": "uses",
                "base-location": "originates-from",
            },
            "yara": {
                # SDO
                "malware": "indicates"
            },
            "suricata": {
                # SDO
                "malware": "indicates"
            },
            "email-addr": {
                # Observable
                "file": "related-to"
            },
            "user-account": {
                "domain-name": "related-to",
                "url": "related-to",
                "ipv4-addr": "related-to",
                "incident": "related-to",
                # OpenCTI vocab: User-Account → Identity (Organization)
                # supports only "related-to" (not "attributed-to").
                "identity": "related-to",
            },
        }

        def _gen_rel(
            mo: Any,
            mo_type: str,
            ro: Any,
            ro_type: str,
            gen_rel_processor: Any = main_obj.generate_relationship,
        ) -> None:
            r_type = relation_type_map.get(mo_type, {}).get(ro_type, None)
            if not r_type:
                raise AttributeError(
                    f"No relation type defined. Main object type: [{mo_type}], "
                    f"Related object type: {ro_type}, Relation type: {relation_type}"
                )
            gen_rel_processor(
                mo,
                ro,
                relation_type=r_type,
            )

        _main_object = main_obj.stix_main_object
        _main_object_c_type = main_obj.c_type
        helper.connector_logger.debug(
            f"Generating relations for main object type: {_main_object_c_type}, is_ioc: {is_ioc}"
        )

        # generate relationship: Indicator --based-on--> Observable
        if (
            is_ioc
            and main_obj.stix_indicator
            and main_obj.c_type not in ["yara", "suricata"]
        ):
            _indicator = main_obj.stix_indicator
            helper.connector_logger.debug(
                f"Processing indicator relationships for {_main_object_c_type}"
            )

            if isinstance(_indicator, list):
                for _ind in _indicator:
                    helper.connector_logger.debug(
                        f"Generating relationship: {_ind.type} -> {_main_object_c_type}"
                    )
                    _gen_rel(_ind, _ind.type, _main_object, _main_object_c_type)
            else:
                helper.connector_logger.debug(
                    f"Generating relationship: {_indicator.type} -> {_main_object_c_type}"
                )
                _gen_rel(
                    _indicator,
                    _indicator.type,
                    _main_object,
                    _main_object_c_type,
                )

        if not related_objects:
            helper.connector_logger.debug(
                "No related objects provided for relationship generation"
            )
            return main_obj

        for _rel_obj in related_objects:
            if _rel_obj:
                if isinstance(_rel_obj, list) and _rel_obj:
                    for _ro in _rel_obj:
                        # generate relationship: Indicator --indicates--> Threat
                        if (
                            is_ioc
                            and main_obj.stix_indicator
                            and _ro.c_type
                            in ["threat-actor", "intrusion-set", "malware"]
                        ):
                            _indicator = main_obj.stix_indicator
                            if isinstance(_indicator, list):
                                for _ind in _indicator:
                                    helper.connector_logger.debug(
                                        f"Generating indicator-threat relationship: {_ind.type} -> {_ro.c_type}"
                                    )
                                    _gen_rel(
                                        _ind,
                                        _ind.type,
                                        _ro.stix_main_object,
                                        _ro.c_type,
                                    )
                            else:
                                helper.connector_logger.debug(
                                    f"Generating indicator-threat relationship: {_indicator.type} -> {_ro.c_type}"
                                )
                                _gen_rel(
                                    _indicator,
                                    _indicator.type,
                                    _ro.stix_main_object,
                                    _ro.c_type,
                                )
                        # generate relationship:
                        # - Observable --related-to--> Threat
                        # - Observable/SDO/Threat/Common --any--> Any
                        else:
                            helper.connector_logger.debug(
                                f"Generating relationship: {_main_object_c_type} -> {_ro.c_type}"
                            )
                            _gen_rel(
                                _main_object,
                                _main_object_c_type,
                                _ro.stix_main_object,
                                _ro.c_type,
                            )
                else:

                    if (
                        is_ioc
                        and main_obj.stix_indicator
                        and _rel_obj.c_type
                        in ["threat-actor", "intrusion-set", "malware"]
                    ):
                        _indicator = main_obj.stix_indicator
                        if isinstance(_indicator, list):
                            for _ind in _indicator:
                                helper.connector_logger.debug(
                                    f"Generating indicator-threat relationship: {_ind.type} -> {_rel_obj.c_type}"
                                )
                                _gen_rel(
                                    _ind,
                                    _ind.type,
                                    _rel_obj.stix_main_object,
                                    _rel_obj.c_type,
                                )
                        else:
                            helper.connector_logger.debug(
                                f"Generating indicator-threat relationship: {_indicator.type} -> {_rel_obj.c_type}"
                            )
                            _gen_rel(
                                _indicator,
                                _indicator.type,
                                _rel_obj.stix_main_object,
                                _rel_obj.c_type,
                            )

                    else:
                        helper.connector_logger.debug(
                            f"Generating relationship: {_main_object_c_type} -> {_rel_obj.c_type}"
                        )
                        _gen_rel(
                            _main_object,
                            _main_object_c_type,
                            _rel_obj.stix_main_object,
                            _rel_obj.c_type,
                        )

        helper.connector_logger.info(
            f"Completed generating relations for main object type: {_main_object_c_type}"
        )
        return main_obj

    def _generate_mitre_matrix(self, obj_events: list[Any]) -> dict[str, Any]:
        self.helper.connector_logger.debug("Generating MITRE matrix")
        mitre_matrix = {
            _e.get("attack_pattern"): {
                "kill_chain_phases": list(),
                "portal_links": list(),
            }
            for _e in obj_events
            if _e.get("attack_pattern")
        }
        for _e in obj_events:
            if _e.get("attack_pattern"):
                mitre_matrix[_e.get("attack_pattern")]["kill_chain_phases"].append(
                    _e.get("kill_chain_phase")
                )
                mitre_matrix[_e.get("attack_pattern")]["portal_links"] = (
                    self._retrieve_link(_e)
                )
        self.helper.connector_logger.debug(
            f"MITRE matrix generated with {len(mitre_matrix)} attack patterns"
        )
        return mitre_matrix

    def generate_kill_chain_phases(self, obj_types: list[Any]) -> list[Any]:
        self.helper.connector_logger.debug(
            f"Generating kill chain phases for types: {obj_types}"
        )
        _name = "mitre-attack"
        _label = "mitre"

        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            context_labels=[_label],
        )
        kill_chain_phases = []
        for _phase_type in obj_types:
            kc = ds.KillChainPhase(
                name=_name,
                c_type=_phase_type,
                labels=entity_labels,
            )
            kc.generate_stix_objects()
            kill_chain_phases.append(kc.stix_main_object)
        self.helper.connector_logger.info(
            f"Generated {len(kill_chain_phases)} kill chain phases"
        )
        return kill_chain_phases

    def _parse_iso_utc(self, raw_value: Any) -> datetime | None:
        if not raw_value:
            return None
        try:
            s = str(raw_value).strip()
            if s.startswith("00"):
                self.helper.connector_logger.warning(
                    f"{self.collection}: unparsable date dropped "
                    f"(zero-year placeholder): {s!r}"
                )
                return None
            s = s.replace("Z", "+00:00")
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            self.helper.connector_logger.warning(
                f"{self.collection}: unparsable date dropped "
                f"(not ISO-8601): {str(raw_value)[:64]!r}"
            )
            return None

    def _extract_first_last_seen(
        self, json_date_obj: dict[str, Any] | None
    ) -> tuple[datetime | None, datetime | None]:
        """Read first-seen / last-seen from the mapped date object."""
        if not json_date_obj:
            return None, None
        first_raw = json_date_obj.get("first-seen") or json_date_obj.get("date-created")
        last_raw = json_date_obj.get("last-seen") or json_date_obj.get("date-modified")
        return self._parse_iso_utc(first_raw), self._parse_iso_utc(last_raw)

    def _build_actor_extra_labels(self, obj: dict[str, Any]) -> list[str]:
        return []

    def _apply_incident_description(self, incident: Any) -> None:
        static_desc = TICollections.DESCRIPTIONS.get(self.collection, "")

        desc_in_ext = self.config.get_setting_bool(
            self.collection,
            "description_in_external_references",
            default=False,
        )

        if desc_in_ext:
            incident.set_description("")
            if static_desc:
                incident.external_references.append(
                    stix2.ExternalReference(
                        source_name="Incident description",
                        description=static_desc,
                    )
                )
        else:
            incident.set_description(static_desc)

        incident.generate_stix_objects()
        incident.add_relationships_to_stix_objects()
