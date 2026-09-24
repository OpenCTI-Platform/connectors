# -*- coding: utf-8 -*-
"""Lamis Network STIX 2.1 bundle builder."""

import logging
import time
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import stix2
from pycti import (
    STIX_EXT_OCTI_SCO,
)
from pycti import Indicator as PyctiIndicator
from pycti import Location as PyctiLocation
from pycti import MarkingDefinition as PyctiMarkingDefinition
from pycti import (
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixCoreRelationship,
)
from stix2 import (
    AutonomousSystem,
    ExternalReference,
    Indicator,
    Location,
    Relationship,
)

logger = logging.getLogger(__name__)


def _stix_quote(value: str) -> str:
    """Escape single quotes and backslashes for STIX pattern literals."""
    return (value or "").replace("\\", "\\\\").replace("'", "\\'")


def _make_tlp_marking(definition: str) -> stix2.MarkingDefinition:
    """Return stix2.MarkingDefinition for OpenCTI custom TLP values."""
    return stix2.MarkingDefinition(
        id=PyctiMarkingDefinition.generate_id("TLP", definition),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition=definition,
    )


_TLP_MAP: Dict[str, stix2.MarkingDefinition] = {
    "TLP:CLEAR": _make_tlp_marking("TLP:CLEAR"),
    "TLP:WHITE": stix2.TLP_WHITE,
    "TLP:GREEN": stix2.TLP_GREEN,
    "TLP:AMBER": stix2.TLP_AMBER,
    "TLP:AMBER+STRICT": _make_tlp_marking("TLP:AMBER+STRICT"),
    "TLP:RED": stix2.TLP_RED,
}

_MARKING_ID_TO_TLP: Dict[str, str] = {
    marking.id: tlp_string for tlp_string, marking in _TLP_MAP.items()
}

LAMIS_MANAGED_LABELS: Set[str] = {
    "datacenter",
    "vpn",
    "tor-exit-node",
    "public-proxy",
    "suspicious",
}

ISO_3166_1_ALPHA_2_TO_NAME: Dict[str, str] = {
    "AD": "Andorra",
    "AE": "United Arab Emirates",
    "AF": "Afghanistan",
    "AG": "Antigua and Barbuda",
    "AI": "Anguilla",
    "AL": "Albania",
    "AM": "Armenia",
    "AO": "Angola",
    "AQ": "Antarctica",
    "AR": "Argentina",
    "AS": "American Samoa",
    "AT": "Austria",
    "AU": "Australia",
    "AW": "Aruba",
    "AX": "Åland Islands",
    "AZ": "Azerbaijan",
    "BA": "Bosnia and Herzegovina",
    "BB": "Barbados",
    "BD": "Bangladesh",
    "BE": "Belgium",
    "BF": "Burkina Faso",
    "BG": "Bulgaria",
    "BH": "Bahrain",
    "BI": "Burundi",
    "BJ": "Benin",
    "BL": "Saint Barthélemy",
    "BM": "Bermuda",
    "BN": "Brunei Darussalam",
    "BO": "Bolivia",
    "BQ": "Bonaire, Sint Eustatius and Saba",
    "BR": "Brazil",
    "BS": "Bahamas",
    "BT": "Bhutan",
    "BV": "Bouvet Island",
    "BW": "Botswana",
    "BY": "Belarus",
    "BZ": "Belize",
    "CA": "Canada",
    "CC": "Cocos (Keeling) Islands",
    "CD": "Congo, Democratic Republic of the",
    "CF": "Central African Republic",
    "CG": "Congo",
    "CH": "Switzerland",
    "CI": "Côte d'Ivoire",
    "CK": "Cook Islands",
    "CL": "Chile",
    "CM": "Cameroon",
    "CN": "China",
    "CO": "Colombia",
    "CR": "Costa Rica",
    "CU": "Cuba",
    "CV": "Cabo Verde",
    "CW": "Curaçao",
    "CX": "Christmas Island",
    "CY": "Cyprus",
    "CZ": "Czechia",
    "DE": "Germany",
    "DJ": "Djibouti",
    "DK": "Denmark",
    "DM": "Dominica",
    "DO": "Dominican Republic",
    "DZ": "Algeria",
    "EC": "Ecuador",
    "EE": "Estonia",
    "EG": "Egypt",
    "EH": "Western Sahara",
    "ER": "Eritrea",
    "ES": "Spain",
    "ET": "Ethiopia",
    "FI": "Finland",
    "FJ": "Fiji",
    "FK": "Falkland Islands",
    "FM": "Micronesia",
    "FO": "Faroe Islands",
    "FR": "France",
    "GA": "Gabon",
    "GB": "United Kingdom",
    "GD": "Grenada",
    "GE": "Georgia",
    "GF": "French Guiana",
    "GG": "Guernsey",
    "GH": "Ghana",
    "GI": "Gibraltar",
    "GL": "Greenland",
    "GM": "Gambia",
    "GN": "Guinea",
    "GP": "Guadeloupe",
    "GQ": "Equatorial Guinea",
    "GR": "Greece",
    "GS": "South Georgia and the South Sandwich Islands",
    "GT": "Guatemala",
    "GU": "Guam",
    "GW": "Guinea-Bissau",
    "GY": "Guyana",
    "HK": "Hong Kong",
    "HM": "Heard Island and McDonald Islands",
    "HN": "Honduras",
    "HR": "Croatia",
    "HT": "Haiti",
    "HU": "Hungary",
    "ID": "Indonesia",
    "IE": "Ireland",
    "IL": "Israel",
    "IM": "Isle of Man",
    "IN": "India",
    "IO": "British Indian Ocean Territory",
    "IQ": "Iraq",
    "IR": "Iran",
    "IS": "Iceland",
    "IT": "Italy",
    "JE": "Jersey",
    "JM": "Jamaica",
    "JO": "Jordan",
    "JP": "Japan",
    "KE": "Kenya",
    "KG": "Kyrgyzstan",
    "KH": "Cambodia",
    "KI": "Kiribati",
    "KM": "Comoros",
    "KN": "Saint Kitts and Nevis",
    "KP": "North Korea",
    "KR": "South Korea",
    "KW": "Kuwait",
    "KY": "Cayman Islands",
    "KZ": "Kazakhstan",
    "LA": "Laos",
    "LB": "Lebanon",
    "LC": "Saint Lucia",
    "LI": "Liechtenstein",
    "LK": "Sri Lanka",
    "LR": "Liberia",
    "LS": "Lesotho",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "LV": "Latvia",
    "LY": "Libya",
    "MA": "Morocco",
    "MC": "Monaco",
    "MD": "Moldova",
    "ME": "Montenegro",
    "MF": "Saint Martin",
    "MG": "Madagascar",
    "MH": "Marshall Islands",
    "MK": "North Macedonia",
    "ML": "Mali",
    "MM": "Myanmar",
    "MN": "Mongolia",
    "MO": "Macao",
    "MP": "Northern Mariana Islands",
    "MQ": "Martinique",
    "MR": "Mauritania",
    "MS": "Montserrat",
    "MT": "Malta",
    "MU": "Mauritius",
    "MV": "Maldives",
    "MW": "Malawi",
    "MX": "Mexico",
    "MY": "Malaysia",
    "MZ": "Mozambique",
    "NA": "Namibia",
    "NC": "New Caledonia",
    "NE": "Niger",
    "NF": "Norfolk Island",
    "NG": "Nigeria",
    "NI": "Nicaragua",
    "NL": "Netherlands",
    "NO": "Norway",
    "NP": "Nepal",
    "NR": "Nauru",
    "NU": "Niue",
    "NZ": "New Zealand",
    "OM": "Oman",
    "PA": "Panama",
    "PE": "Peru",
    "PF": "French Polynesia",
    "PG": "Papua New Guinea",
    "PH": "Philippines",
    "PK": "Pakistan",
    "PL": "Poland",
    "PM": "Saint Pierre and Miquelon",
    "PN": "Pitcairn",
    "PR": "Puerto Rico",
    "PS": "Palestine",
    "PT": "Portugal",
    "PW": "Palau",
    "PY": "Paraguay",
    "QA": "Qatar",
    "RE": "Réunion",
    "RO": "Romania",
    "RS": "Serbia",
    "RU": "Russia",
    "RW": "Rwanda",
    "SA": "Saudi Arabia",
    "SB": "Solomon Islands",
    "SC": "Seychelles",
    "SD": "Sudan",
    "SE": "Sweden",
    "SG": "Singapore",
    "SH": "Saint Helena",
    "SI": "Slovenia",
    "SJ": "Svalbard and Jan Mayen",
    "SK": "Slovakia",
    "SL": "Sierra Leone",
    "SM": "San Marino",
    "SN": "Senegal",
    "SO": "Somalia",
    "SR": "Suriname",
    "SS": "South Sudan",
    "ST": "Sao Tome and Principe",
    "SV": "El Salvador",
    "SX": "Sint Maarten",
    "SY": "Syria",
    "SZ": "Eswatini",
    "TC": "Turks and Caicos Islands",
    "TD": "Chad",
    "TF": "French Southern Territories",
    "TG": "Togo",
    "TH": "Thailand",
    "TJ": "Tajikistan",
    "TK": "Tokelau",
    "TL": "Timor-Leste",
    "TM": "Turkmenistan",
    "TN": "Tunisia",
    "TO": "Tonga",
    "TR": "Türkiye",
    "TT": "Trinidad and Tobago",
    "TV": "Tuvalu",
    "TW": "Taiwan",
    "TZ": "Tanzania",
    "UA": "Ukraine",
    "UG": "Uganda",
    "UM": "United States Minor Outlying Islands",
    "US": "United States",
    "UY": "Uruguay",
    "UZ": "Uzbekistan",
    "VA": "Holy See",
    "VC": "Saint Vincent and the Grenadines",
    "VE": "Venezuela",
    "VG": "Virgin Islands (British)",
    "VI": "Virgin Islands (U.S.)",
    "VN": "Vietnam",
    "VU": "Vanuatu",
    "WF": "Wallis and Futuna",
    "WS": "Samoa",
    "XK": "Kosovo",
    "YE": "Yemen",
    "YT": "Mayotte",
    "ZA": "South Africa",
    "ZM": "Zambia",
    "ZW": "Zimbabwe",
}


class LamisNetworkBuilder:
    """Builds STIX 2.1 objects from Lamis Network API responses."""

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        author: stix2.Identity,
        observable: Dict[str, Any],
        default_marking_refs: Optional[List[str]] = None,
        stix_objects: Optional[List[Any]] = None,
        stix_entity_marking_refs: Optional[List[str]] = None,
    ) -> None:
        """Initialize the builder.

        :param helper: OpenCTIConnectorHelper instance
        :param author: Organization identity for Lamis Network
        :param observable: Observable entity being enriched
        :param default_marking_refs: Default TLP markings if observable has none
        :param stix_objects: Original STIX objects bundle from OpenCTI playbook
        :param stix_entity_marking_refs: ``object_marking_refs`` from the STIX
            entity accompanying the enrichment event.  When the enrichment
            entity carries no markings of its own, these refs are used for
            all generated objects so they inherit the observable's true TLP
            rather than the connector's configured default.
        """
        self.helper = helper
        self.author = author
        self.observable = observable
        self.default_marking_refs = list(default_marking_refs or [])
        self.stix_entity_marking_refs = list(stix_entity_marking_refs or [])
        self.bundle: List[Any] = list(stix_objects or [])
        author_id = getattr(self.author, "id", None) or (
            self.author.get("id") if isinstance(self.author, dict) else None
        )
        has_author = any(
            (
                getattr(obj, "id", None)
                or (obj.get("id") if isinstance(obj, dict) else None)
            )
            == author_id
            for obj in self.bundle
        )
        if not has_author:
            self.bundle.append(self.author)

    def get_marking_refs(self) -> List[str]:
        """Extract deduplicated marking references from the observable or fallback.

        Priority order and merge strategy:
        - Collect all marking refs from observable's ``objectMarking`` and
          flat ``object_marking_refs``, then add ``stix_entity_marking_refs``.
        - When both sources are present (e.g., enrichment_entity=TLP:GREEN and
          stix_entity=TLP:AMBER), the union is returned so generated objects
          always carry the stricter effective marking.
        - When neither source has markings, fall back to
          ``default_marking_refs``.
        """
        candidates: List[str] = []
        for raw_markings in (
            self.observable.get("objectMarking"),
            self.observable.get("object_marking_refs"),
        ):
            if not isinstance(raw_markings, list):
                continue
            for marking in raw_markings:
                if isinstance(marking, dict):
                    std_id = marking.get("standard_id")
                    if isinstance(std_id, str) and std_id:
                        candidates.append(std_id)
                elif isinstance(marking, str) and marking:
                    candidates.append(marking)

        # Always merge stix_entity markings so generated objects carry the
        # stricter of the two marking sets (not just when observable is empty).
        for ref in self.stix_entity_marking_refs:
            if isinstance(ref, str) and ref:
                candidates.append(ref)

        seen: set = set()
        deduped: List[str] = []
        for ref in candidates:
            if ref not in seen:
                seen.add(ref)
                deduped.append(ref)

        def _is_tlp_ref(ref: str) -> bool:
            if ref in _MARKING_ID_TO_TLP:
                return True
            if (
                hasattr(self.helper, "api")
                and self.helper.api
                and hasattr(self.helper.api, "marking_definition")
            ):
                try:
                    m_data = self.helper.api.marking_definition.read(id=ref)
                    if isinstance(m_data, dict):
                        return str(m_data.get("definition_type", "")).upper() == "TLP"
                except Exception:
                    pass
            return False

        has_tlp = any(_is_tlp_ref(ref) for ref in deduped)
        if not has_tlp and self.default_marking_refs:
            for def_ref in self.default_marking_refs:
                if def_ref not in seen:
                    seen.add(def_ref)
                    deduped.append(def_ref)

        return deduped if deduped else list(self.default_marking_refs)

    def enrich_observable(
        self,
        stix_entity: Dict[str, Any],
        fraud_score: int,
        labels: List[str],
        evaluated_flags: Optional[Dict[str, Optional[bool]]] = None,
    ) -> None:
        """Add score, references, and labels to a copy of the input SCO."""
        if not isinstance(stix_entity, dict) or stix_entity.get(
            "id"
        ) != self.observable.get("standard_id"):
            raise ValueError(
                "Missing or mismatched STIX observable in enrichment event"
            )
        enriched = deepcopy(stix_entity)
        # Merge marking refs so the enriched observable retains the stricter
        # marking when enrichment_entity and stix_entity differ (e.g., AMBER vs GREEN).
        # We combine markings from the STIX entity, the observable's objectMarking /
        # object_marking_refs, and stix_entity_marking_refs via get_marking_refs().
        merged_marking_refs: List[str] = []
        for ref in (
            list(enriched.get("object_marking_refs") or []) + self.get_marking_refs()
        ):
            if isinstance(ref, str) and ref and ref not in merged_marking_refs:
                merged_marking_refs.append(ref)
        if merged_marking_refs:
            enriched["object_marking_refs"] = merged_marking_refs
        OpenCTIStix2.put_attribute_in_extension(
            enriched, STIX_EXT_OCTI_SCO, "score", fraud_score
        )
        OpenCTIStix2.put_attribute_in_extension(
            enriched,
            STIX_EXT_OCTI_SCO,
            "external_references",
            {
                "source_name": "Lamis Network",
                "url": "https://lamisnetwork.com",
                "external_id": self.observable.get("value")
                or self.observable.get("observable_value"),
                "description": (
                    f"Lamis Network IP Risk Analysis (Score: {fraud_score}/100)"
                ),
            },
            True,
        )
        # Preserve analyst labels while reconciling stale risk labels added by this connector.
        # SCO labels carry no creator provenance in standard STIX extensions, so we track
        # labels added by this connector in x_lamis_network_labels.
        # Analyst labels (even if sharing names with connector labels) are preserved because
        # we only reconcile labels recorded in x_lamis_network_labels.
        ext = enriched.get("extensions", {}).get(STIX_EXT_OCTI_SCO, {})
        prev_labels = ext.get("labels") if isinstance(ext.get("labels"), list) else []

        def _get_tracked(ent: Dict[str, Any]) -> Optional[List[str]]:
            if not isinstance(ent, dict):
                return None
            if isinstance(ent.get("x_lamis_network_labels"), list):
                return ent.get("x_lamis_network_labels")
            e_ext = ent.get("extensions", {}).get(STIX_EXT_OCTI_SCO, {})
            if isinstance(e_ext, dict) and isinstance(
                e_ext.get("x_lamis_network_labels"), list
            ):
                return e_ext.get("x_lamis_network_labels")
            return None

        tracked = _get_tracked(enriched)
        if tracked is None:
            tracked = _get_tracked(stix_entity)

        # If x_lamis_network_labels is not present, this is the first run on this SCO
        # (or prior to tracking). Do NOT treat untracked labels as connector-owned.
        prev_connector_labels = set(tracked) if tracked is not None else set()
        new_connector_labels = set(labels)

        stale_labels: Set[str] = set()
        if evaluated_flags is not None:
            for lbl in prev_connector_labels:
                # Remove only if the flag was explicitly evaluated and is False
                if evaluated_flags.get(lbl) is False:
                    stale_labels.add(lbl)
                # If evaluated_flags.get(lbl) is None (omitted/partial response), retain it
        else:
            stale_labels = prev_connector_labels - new_connector_labels

        active_connector_labels = (
            prev_connector_labels - stale_labels
        ) | new_connector_labels

        # Reconcile SCO labels: keep all analyst labels, remove stale connector labels
        reconciled_labels = [lb for lb in prev_labels if lb not in stale_labels]
        for lb in sorted(active_connector_labels):
            if lb not in reconciled_labels:
                reconciled_labels.append(lb)

        sorted_active_labels = sorted(active_connector_labels)
        enriched["x_lamis_network_labels"] = sorted_active_labels

        enriched.setdefault("extensions", {}).setdefault(STIX_EXT_OCTI_SCO, {})[
            "labels"
        ] = reconciled_labels
        enriched["extensions"][STIX_EXT_OCTI_SCO][
            "x_lamis_network_labels"
        ] = sorted_active_labels

        target_id = stix_entity.get("id")
        replaced = False
        for i, obj in enumerate(self.bundle):
            obj_id = getattr(obj, "id", None) or (
                obj.get("id") if isinstance(obj, dict) else None
            )
            if obj_id == target_id:
                self.bundle[i] = enriched
                replaced = True
                break
        if not replaced:
            self.bundle.append(enriched)

    def _add_or_replace_in_bundle(self, objects: List[Any]) -> None:
        """Add objects to self.bundle, replacing any existing objects with matching IDs."""
        for new_obj in objects:
            new_id = getattr(new_obj, "id", None) or (
                new_obj.get("id") if isinstance(new_obj, dict) else None
            )
            replaced = False
            if new_id:
                for i, existing in enumerate(self.bundle):
                    ex_id = getattr(existing, "id", None) or (
                        existing.get("id") if isinstance(existing, dict) else None
                    )
                    if ex_id == new_id:
                        self.bundle[i] = new_obj
                        replaced = True
                        break
            if not replaced:
                self.bundle.append(new_obj)

    def _is_matching_retired_rel(
        self,
        obj: Any,
        relationship_type: str,
        author_id: Optional[str],
        from_ids: Set[str],
        to_ids: Set[str],
        allowed_target_ids: Optional[Set[str]],
        allowed_source_ids: Optional[Set[str]],
    ) -> bool:
        """Check if an in-memory relationship matches criteria for retirement."""
        rel_type = getattr(obj, "type", None) or (
            obj.get("type") if isinstance(obj, dict) else None
        )
        if rel_type != "relationship":
            return False
        r_type = getattr(obj, "relationship_type", None) or (
            obj.get("relationship_type") if isinstance(obj, dict) else None
        )
        if r_type != relationship_type:
            return False
        c_ref = getattr(obj, "created_by_ref", None) or (
            obj.get("created_by_ref") if isinstance(obj, dict) else None
        )
        if author_id and c_ref != author_id:
            return False
        s_ref = getattr(obj, "source_ref", None) or (
            obj.get("source_ref") if isinstance(obj, dict) else None
        )
        t_ref = getattr(obj, "target_ref", None) or (
            obj.get("target_ref") if isinstance(obj, dict) else None
        )
        if from_ids and s_ref not in from_ids:
            return False
        if to_ids and t_ref not in to_ids:
            return False
        if allowed_target_ids is not None and t_ref in allowed_target_ids:
            return False
        if allowed_source_ids is not None and s_ref in allowed_source_ids:
            return False
        return True

    def _retire_relationships(
        self,
        relationship_type: str,
        from_id: Optional[Union[str, List[str]]] = None,
        to_id: Optional[Union[str, List[str]]] = None,
        allowed_target_ids: Optional[Set[str]] = None,
        allowed_source_ids: Optional[Set[str]] = None,
    ) -> None:
        """Retire obsolete relationships by emitting STIX Relationship objects with stop_time.

        Emitting retired relationships in the STIX bundle ensures atomic ingestion
        without separate immediate API mutations that could leave an observable
        temporarily disconnected.
        """
        author_id = getattr(self.author, "id", None) or (
            self.author.get("id") if isinstance(self.author, dict) else None
        )
        from_ids = (
            {from_id}
            if isinstance(from_id, str)
            else set(from_id) if from_id else set()
        )
        to_ids = {to_id} if isinstance(to_id, str) else set(to_id) if to_id else set()
        now_utc = datetime.now(timezone.utc)
        marking_refs = self.get_marking_refs()

        # 1. Remove obsolete relationships from in-memory bundle
        self.bundle = [
            obj
            for obj in self.bundle
            if not self._is_matching_retired_rel(
                obj=obj,
                relationship_type=relationship_type,
                author_id=author_id,
                from_ids=from_ids,
                to_ids=to_ids,
                allowed_target_ids=allowed_target_ids,
                allowed_source_ids=allowed_source_ids,
            )
        ]

        # 2. Query OpenCTI platform for persisted relationships and emit retired counterparts with stop_time
        if (
            hasattr(self.helper, "api")
            and self.helper.api
            and hasattr(self.helper.api, "stix_core_relationship")
        ):
            # PyCTI's fromId and toId parameters take scalar strings, not lists.
            # Query each scalar ID combination separately and deduplicate results.
            from_id_list = (
                [i for i in from_ids if isinstance(i, str) and i]
                if from_ids
                else [None]
            )
            to_id_list = (
                [i for i in to_ids if isinstance(i, str) and i] if to_ids else [None]
            )

            seen_rel_ids: Set[str] = set()
            existing_rels: List[Dict[str, Any]] = []

            for fid in from_id_list:
                for tid in to_id_list:
                    list_kwargs: Dict[str, Any] = {
                        "relationship_type": relationship_type,
                        "getAll": True,
                    }
                    if fid is not None:
                        list_kwargs["fromId"] = fid
                    if tid is not None:
                        list_kwargs["toId"] = tid

                    max_retries = 3
                    query_rels = None
                    last_exc = None
                    for attempt in range(max_retries):
                        try:
                            query_rels = self.helper.api.stix_core_relationship.list(
                                **list_kwargs
                            )
                            break
                        except Exception as exc:
                            last_exc = exc
                            self.helper.connector_logger.warning(
                                f"[Lamis Network] Attempt {attempt + 1}/{max_retries} to query existing "
                                f"{relationship_type} relationships failed: {exc}"
                            )
                            if attempt < max_retries - 1:
                                time.sleep(0.5 * (attempt + 1))

                    if query_rels is None and last_exc is not None:
                        self.helper.connector_logger.error(
                            f"[Lamis Network] Failed to query existing {relationship_type} relationships "
                            f"after {max_retries} attempts: {last_exc}"
                        )
                        raise RuntimeError(
                            f"Failed to query existing {relationship_type} relationships from OpenCTI: {last_exc}"
                        ) from last_exc

                    if isinstance(query_rels, list):
                        for r in query_rels:
                            if isinstance(r, dict):
                                r_id = r.get("id") or r.get("standard_id")
                                if r_id and r_id in seen_rel_ids:
                                    continue
                                if r_id:
                                    seen_rel_ids.add(r_id)
                                existing_rels.append(r)

            if isinstance(existing_rels, list):
                existing_bundle_ids = {
                    getattr(o, "id", None)
                    or (o.get("id") if isinstance(o, dict) else None)
                    for o in self.bundle
                }
                for rel in existing_rels:
                    if not isinstance(rel, dict):
                        continue
                    created_by = rel.get("createdBy") or {}
                    c_id = (
                        created_by.get("standard_id")
                        or created_by.get("id")
                        or rel.get("created_by_ref")
                    )
                    if author_id and c_id != author_id:
                        continue

                    source = rel.get("from") or {}
                    s_id = (
                        source.get("standard_id")
                        or source.get("id")
                        or rel.get("source_ref")
                        or rel.get("fromId")
                    )
                    target = rel.get("to") or {}
                    t_id = (
                        target.get("standard_id")
                        or target.get("id")
                        or rel.get("target_ref")
                        or rel.get("toId")
                    )

                    if from_ids and s_id not in from_ids:
                        continue
                    if to_ids and t_id not in to_ids:
                        continue
                    if allowed_target_ids is not None and t_id in allowed_target_ids:
                        continue
                    if allowed_source_ids is not None and s_id in allowed_source_ids:
                        continue

                    rel_id = rel.get("standard_id") or rel.get("id")
                    if not rel_id or rel_id in existing_bundle_ids:
                        continue

                    start_time = rel.get("start_time") or (
                        now_utc - timedelta(seconds=1)
                    )

                    try:
                        retired_rel = Relationship(
                            id=rel_id,
                            relationship_type=relationship_type,
                            created_by_ref=author_id,
                            source_ref=s_id,
                            target_ref=t_id,
                            start_time=start_time,
                            stop_time=now_utc,
                            object_marking_refs=marking_refs,
                            allow_custom=True,
                        )
                    except Exception:
                        retired_rel = {
                            "type": "relationship",
                            "spec_version": "2.1",
                            "id": rel_id,
                            "relationship_type": relationship_type,
                            "created_by_ref": author_id,
                            "source_ref": s_id,
                            "target_ref": t_id,
                            "start_time": (
                                start_time.isoformat()
                                if hasattr(start_time, "isoformat")
                                else str(start_time)
                            ),
                            "stop_time": (
                                now_utc.isoformat()
                                if hasattr(now_utc, "isoformat")
                                else str(now_utc)
                            ),
                            "object_marking_refs": marking_refs,
                        }
                    self.bundle.append(retired_rel)
                    existing_bundle_ids.add(rel_id)

    def add_asn(self, asn_data: Dict[str, Any]) -> None:
        """Create AutonomousSystem SCO and a belongs-to relationship."""
        raw_asn = asn_data.get("asn") or asn_data.get("number")
        if raw_asn is None or isinstance(raw_asn, (bool, float)):
            return

        try:
            if isinstance(raw_asn, str) and raw_asn.upper().startswith("AS"):
                asn_number = int(raw_asn[2:])
            else:
                asn_number = int(raw_asn)
            if not 0 <= asn_number <= 4294967295:
                return
        except (ValueError, TypeError):
            self.helper.connector_logger.warning(
                f"[Lamis Network] Invalid ASN number: {raw_asn}"
            )
            return

        asn_name = str(asn_data.get("name") or asn_data.get("org") or f"AS{asn_number}")
        rir = str(asn_data.get("rir") or "Unknown")
        marking_refs = self.get_marking_refs()
        obs_id = self.observable.get("standard_id")
        obs_uuid = self.observable.get("id")
        obs_identifiers = [i for i in (obs_id, obs_uuid) if i]

        as_stix = AutonomousSystem(
            number=asn_number,
            name=asn_name,
            rir=rir,
            custom_properties={
                "x_opencti_created_by_ref": self.author.id,
            },
            object_marking_refs=marking_refs,
        )

        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "belongs-to",
                self.observable["standard_id"],
                as_stix.id,
            ),
            relationship_type="belongs-to",
            created_by_ref=self.author.id,
            source_ref=self.observable["standard_id"],
            target_ref=as_stix.id,
            object_marking_refs=marking_refs,
            allow_custom=True,
        )

        # Replace obsolete belongs-to relationships in bundle and OpenCTI platform
        self._retire_relationships(
            relationship_type="belongs-to",
            from_id=obs_identifiers,
            allowed_target_ids={as_stix.id},
        )

        self._add_or_replace_in_bundle([as_stix, relationship])
        self.helper.connector_logger.debug(
            f"[Lamis Network] Attached AutonomousSystem AS{asn_number} ({asn_name})"
        )

    def _inspect_location_target(self, target_id: str) -> Dict[str, Any]:
        """Inspect a location target from bundle, stix_objects, or OpenCTI platform."""
        # 1. Check in-memory bundle
        for obj in self.bundle:
            obj_id = getattr(obj, "id", None) or (
                obj.get("id") if isinstance(obj, dict) else None
            )
            if obj_id == target_id:
                name = getattr(obj, "name", None) or (
                    obj.get("name") if isinstance(obj, dict) else None
                )
                city = getattr(obj, "city", None) or (
                    obj.get("city") if isinstance(obj, dict) else None
                )
                country = getattr(obj, "country", None) or (
                    obj.get("country") if isinstance(obj, dict) else None
                )
                loc_type = getattr(obj, "x_opencti_location_type", None) or (
                    obj.get("x_opencti_location_type")
                    if isinstance(obj, dict)
                    else None
                )
                if (
                    not loc_type
                    and hasattr(obj, "custom_properties")
                    and isinstance(obj.custom_properties, dict)
                ):
                    loc_type = obj.custom_properties.get("x_opencti_location_type")
                if (
                    not loc_type
                    and isinstance(obj, dict)
                    and isinstance(obj.get("custom_properties"), dict)
                ):
                    loc_type = obj["custom_properties"].get("x_opencti_location_type")
                return {
                    "id": target_id,
                    "name": name,
                    "is_city": bool(loc_type == "City" or city),
                    "is_country": bool(loc_type == "Country" or (country and not city)),
                    "country": country,
                    "city": city,
                }

        # 2. Check stix_objects passed with enrichment event
        for obj in getattr(self, "stix_objects", []):
            if isinstance(obj, dict) and (
                obj.get("id") == target_id or obj.get("standard_id") == target_id
            ):
                name = obj.get("name")
                city = obj.get("city")
                country = obj.get("country")
                props = obj.get("custom_properties") or {}
                loc_type = props.get("x_opencti_location_type") or obj.get(
                    "x_opencti_location_type"
                )
                return {
                    "id": target_id,
                    "name": name,
                    "is_city": bool(loc_type == "City" or city),
                    "is_country": bool(loc_type == "Country" or (country and not city)),
                    "country": country,
                    "city": city,
                }

        # 3. Query OpenCTI API if available
        if (
            hasattr(self.helper, "api")
            and self.helper.api
            and hasattr(self.helper.api, "location")
        ):
            max_retries = 3
            loc_data = None
            last_exc = None
            for attempt in range(max_retries):
                try:
                    loc_data = self.helper.api.location.read(id=target_id)
                    break
                except Exception as exc:
                    last_exc = exc
                    if attempt < max_retries - 1:
                        time.sleep(0.5 * (attempt + 1))
            if loc_data is None and last_exc is not None:
                self.helper.connector_logger.warning(
                    f"[Lamis Network] Failed to read location {target_id} from OpenCTI: {last_exc}"
                )
                return {
                    "id": target_id,
                    "name": None,
                    "is_city": False,
                    "is_country": False,
                    "country": None,
                    "city": None,
                    "inspect_failed": True,
                }
            if isinstance(loc_data, dict):
                name = loc_data.get("name")
                city = loc_data.get("city")
                country = loc_data.get("country")
                loc_type = loc_data.get("x_opencti_location_type") or loc_data.get(
                    "entity_type"
                )
                return {
                    "id": target_id,
                    "name": name,
                    "is_city": bool(loc_type == "City" or city),
                    "is_country": bool(loc_type == "Country" or (country and not city)),
                    "country": country,
                    "city": city,
                    "inspect_failed": False,
                }

        return {
            "id": target_id,
            "name": None,
            "is_city": False,
            "is_country": False,
            "country": None,
            "city": None,
            "inspect_failed": False,
        }

    def _find_existing_located_at_targets(
        self, obs_identifiers: List[str]
    ) -> Tuple[List[str], bool]:
        """Find target IDs of existing located-at relationships originating from this observable.

        Returns (targets, discovery_failed).
        """
        targets: Set[str] = set()
        discovery_failed = False
        author_id = getattr(self.author, "id", None) or (
            self.author.get("id") if isinstance(self.author, dict) else None
        )

        for obj in self.bundle:
            rel_type = getattr(obj, "type", None) or (
                obj.get("type") if isinstance(obj, dict) else None
            )
            r_type = getattr(obj, "relationship_type", None) or (
                obj.get("relationship_type") if isinstance(obj, dict) else None
            )
            if rel_type == "relationship" and r_type == "located-at":
                c_ref = getattr(obj, "created_by_ref", None) or (
                    obj.get("created_by_ref") if isinstance(obj, dict) else None
                )
                if author_id and c_ref != author_id:
                    continue
                s_ref = getattr(obj, "source_ref", None) or (
                    obj.get("source_ref") if isinstance(obj, dict) else None
                )
                t_ref = getattr(obj, "target_ref", None) or (
                    obj.get("target_ref") if isinstance(obj, dict) else None
                )
                if s_ref in obs_identifiers and t_ref:
                    targets.add(t_ref)

        for obj in getattr(self, "stix_objects", []):
            if (
                isinstance(obj, dict)
                and obj.get("type") == "relationship"
                and obj.get("relationship_type") == "located-at"
            ):
                c_ref = obj.get("created_by_ref")
                if author_id and c_ref != author_id:
                    continue
                s_ref = obj.get("source_ref")
                t_ref = obj.get("target_ref")
                if s_ref in obs_identifiers and t_ref:
                    targets.add(t_ref)

        if (
            hasattr(self.helper, "api")
            and self.helper.api
            and hasattr(self.helper.api, "stix_core_relationship")
        ):
            max_retries = 3
            query_ids = [i for i in obs_identifiers if isinstance(i, str) and i]
            for fid in query_ids:
                rels = None
                last_exc = None
                for attempt in range(max_retries):
                    try:
                        rels = self.helper.api.stix_core_relationship.list(
                            relationship_type="located-at",
                            fromId=fid,
                            getAll=True,
                        )
                        break
                    except Exception as exc:
                        last_exc = exc
                        self.helper.connector_logger.warning(
                            f"[Lamis Network] Attempt {attempt + 1}/{max_retries} to query located-at "
                            f"relationships for target discovery with fromId={fid} failed: {exc}"
                        )
                        if attempt < max_retries - 1:
                            time.sleep(0.5 * (attempt + 1))

                if rels is None and last_exc is not None:
                    discovery_failed = True
                    self.helper.connector_logger.warning(
                        f"[Lamis Network] Target discovery failed after {max_retries} attempts: {last_exc}. "
                        "Location relationship retirement will be skipped to protect existing links."
                    )
                    break
                elif isinstance(rels, list):
                    for rel in rels:
                        if not isinstance(rel, dict):
                            continue
                        created_by = rel.get("createdBy") or {}
                        c_id = (
                            created_by.get("standard_id")
                            or created_by.get("id")
                            or rel.get("created_by_ref")
                        )
                        if author_id and c_id != author_id:
                            continue
                        target = rel.get("to") or {}
                        t_id = (
                            target.get("standard_id")
                            or target.get("id")
                            or rel.get("target_ref")
                            or rel.get("toId")
                        )
                        if t_id:
                            targets.add(t_id)

        return list(targets), discovery_failed

    def add_geolocation(self, geo_data: Dict[str, Any]) -> None:
        """Create Country and City Location SDOs with located-at relationships."""
        marking_refs = self.get_marking_refs()
        country_code = geo_data.get("country_code")
        raw_country_name = geo_data.get("country_name") or geo_data.get("country")
        city_name = geo_data.get("city")
        obs_id = self.observable.get("standard_id")
        obs_uuid = self.observable.get("id")
        obs_identifiers = [i for i in (obs_id, obs_uuid) if i]

        # Inspect existing located-at relationships to preserve valid links
        existing_targets, discovery_failed = self._find_existing_located_at_targets(
            obs_identifiers
        )
        prev_country_ids: Set[str] = set()
        prev_country_codes: Set[str] = set()
        prev_country_names: Dict[str, str] = {}
        existing_cities: List[Dict[str, Any]] = []

        for t_id in existing_targets:
            info = self._inspect_location_target(t_id)
            if info.get("inspect_failed"):
                discovery_failed = True
            if info["is_country"]:
                prev_country_ids.add(t_id)
                c_code = (info.get("country") or "").upper()
                if c_code:
                    prev_country_codes.add(c_code)
                loc_name = info.get("name")
                if loc_name and len(loc_name) > 2:
                    if c_code:
                        prev_country_names[c_code] = loc_name
            elif info["is_city"]:
                existing_cities.append(info)
                c_code = (info.get("country") or "").upper()
                if c_code:
                    prev_country_codes.add(c_code)

        # Resolve country name safely: avoid using 2-letter country code as location name
        # if a full name is available from existing target, ISO dictionary, or bundle.
        country_name = None
        if (
            raw_country_name
            and isinstance(raw_country_name, str)
            and raw_country_name.strip()
        ):
            stripped = raw_country_name.strip()
            if not (
                country_code
                and stripped.upper() == str(country_code).strip().upper()
                and len(stripped) <= 2
            ):
                country_name = stripped

        if not country_name and country_code:
            norm_code = str(country_code).strip().upper()
            # 1. Existing Country linked to this observable with matching country code
            if norm_code in prev_country_names:
                country_name = prev_country_names[norm_code]
            # 2. ISO 3166-1 alpha-2 dictionary
            if not country_name:
                country_name = ISO_3166_1_ALPHA_2_TO_NAME.get(norm_code)
            # 3. Existing Country in bundle or stix_objects
            if not country_name:
                for obj in list(self.bundle) + list(getattr(self, "stix_objects", [])):
                    c_val = getattr(obj, "country", None) or (
                        obj.get("country") if isinstance(obj, dict) else None
                    )
                    if c_val and str(c_val).upper() == norm_code:
                        n_val = getattr(obj, "name", None) or (
                            obj.get("name") if isinstance(obj, dict) else None
                        )
                        if n_val and len(n_val) > 2:
                            country_name = n_val
                            break
            # 4. Fallback to raw name or country_code
            if not country_name:
                country_name = raw_country_name or country_code

        new_objects: List[Any] = []
        new_target_ids: Set[str] = set()
        built_country_id: Optional[str] = None
        if country_code and country_name:
            country_id = PyctiLocation.generate_id(country_name, "Country")
            built_country_id = country_id
            country_location = Location(
                id=country_id,
                name=country_name,
                country=country_code,
                custom_properties={
                    "x_opencti_location_type": "Country",
                    "x_opencti_aliases": (
                        [country_code] if country_code != country_name else []
                    ),
                },
                created_by_ref=self.author.id,
                object_marking_refs=marking_refs,
            )

            rel_country = Relationship(
                id=StixCoreRelationship.generate_id(
                    "located-at",
                    self.observable["standard_id"],
                    country_location.id,
                ),
                relationship_type="located-at",
                created_by_ref=self.author.id,
                source_ref=self.observable["standard_id"],
                target_ref=country_location.id,
                object_marking_refs=marking_refs,
                allow_custom=True,
            )
            new_objects.extend([country_location, rel_country])
            new_target_ids.add(country_location.id)

        built_city_id: Optional[str] = None
        if city_name and country_code:
            city_label = f"{city_name} ({country_code})"
            city_id = PyctiLocation.generate_id(city_label, "City")
            built_city_id = city_id
            city_location = Location(
                id=city_id,
                name=city_name,
                country=country_code,
                city=city_name,
                custom_properties={
                    "x_opencti_location_type": "City",
                },
                created_by_ref=self.author.id,
                object_marking_refs=marking_refs,
            )

            rel_city = Relationship(
                id=StixCoreRelationship.generate_id(
                    "located-at",
                    self.observable["standard_id"],
                    city_location.id,
                ),
                relationship_type="located-at",
                created_by_ref=self.author.id,
                source_ref=self.observable["standard_id"],
                target_ref=city_location.id,
                object_marking_refs=marking_refs,
                allow_custom=True,
            )
            new_objects.extend([city_location, rel_city])
            new_target_ids.add(city_location.id)

        # Determine whether the country changed
        country_changed = False
        if built_country_id:
            if prev_country_ids and built_country_id not in prev_country_ids:
                if (
                    country_code
                    and prev_country_codes
                    and country_code.upper() not in prev_country_codes
                ):
                    country_changed = True
                elif not prev_country_codes:
                    country_changed = True
            elif (
                prev_country_codes
                and country_code
                and country_code.upper() not in prev_country_codes
            ):
                country_changed = True

        # If country did not change, preserve all existing Country links for this country
        if not country_changed and country_code:
            for t_id in existing_targets:
                info = self._inspect_location_target(t_id)
                if info["is_country"]:
                    c_code = (info.get("country") or "").upper()
                    if c_code == country_code.upper():
                        new_target_ids.add(t_id)

        # If this enrichment omitted the city (partial data), retain existing city
        # links unless a replacement city was built or a changed country establishes
        # that the previous city is obsolete.
        if not built_city_id and not country_changed:
            for city_info in existing_cities:
                c_code = city_info.get("country")
                if (
                    not c_code
                    or not country_code
                    or c_code.upper() == country_code.upper()
                ):
                    new_target_ids.add(city_info["id"])

        # Retain location links on partial responses: only retire old links when a usable replacement is built.
        # If target discovery failed, abort retirement to avoid removing still-valid links based on incomplete knowledge.
        if new_objects:
            if not discovery_failed:
                self._retire_relationships(
                    relationship_type="located-at",
                    from_id=obs_identifiers,
                    allowed_target_ids=new_target_ids,
                )
            else:
                self.helper.connector_logger.warning(
                    "[Lamis Network] Skipping located-at relationship retirement because "
                    "target discovery could not query OpenCTI reliably."
                )
            self._add_or_replace_in_bundle(new_objects)

    def _find_existing_indicator_valid_from(
        self,
        indicator_id: str,
        ind_data: Optional[Dict[str, Any]] = None,
    ) -> Optional[datetime]:
        """Find and parse existing valid_from for an indicator from bundle, observable, or API."""
        raw_valid_from = None

        # 1. Check in-memory bundle
        for obj in self.bundle:
            obj_id = getattr(obj, "id", None) or (
                obj.get("id") if isinstance(obj, dict) else None
            )
            if obj_id == indicator_id:
                raw_valid_from = getattr(obj, "valid_from", None) or (
                    obj.get("valid_from") if isinstance(obj, dict) else None
                )
                if raw_valid_from:
                    break

        # 2. Check observable indicators if not found in bundle
        if not raw_valid_from:
            for ind in self.observable.get("indicators", []):
                if isinstance(ind, dict) and (
                    ind.get("id") == indicator_id
                    or ind.get("standard_id") == indicator_id
                ):
                    raw_valid_from = ind.get("valid_from") or ind.get("validFrom")
                    if raw_valid_from:
                        break

        # 3. Check OpenCTI API data if provided
        if not raw_valid_from and ind_data and isinstance(ind_data, dict):
            raw_valid_from = ind_data.get("valid_from") or ind_data.get("validFrom")

        # 4. If ind_data was not provided and helper.api is available, query OpenCTI API
        if (
            not raw_valid_from
            and ind_data is None
            and hasattr(self.helper, "api")
            and self.helper.api
        ):
            try:
                fetched = self.helper.api.indicator.read(id=indicator_id)
                if isinstance(fetched, dict):
                    raw_valid_from = fetched.get("valid_from") or fetched.get(
                        "validFrom"
                    )
            except Exception:
                pass

        if raw_valid_from:
            try:
                if isinstance(raw_valid_from, str):
                    return datetime.fromisoformat(raw_valid_from.replace("Z", "+00:00"))
                elif isinstance(raw_valid_from, datetime):
                    return raw_valid_from
            except Exception:
                pass
        return None

    def revoke_indicator(self, ip_value: str, entity_type: str) -> None:
        """Revoke existing indicator when observable falls below risk threshold."""
        stix_entity_type = "ipv4-addr" if entity_type == "IPv4-Addr" else "ipv6-addr"
        pattern = f"[{stix_entity_type}:value = '{_stix_quote(ip_value)}']"
        indicator_id = PyctiIndicator.generate_id(pattern)
        author_id = getattr(self.author, "id", None) or (
            self.author.get("id") if isinstance(self.author, dict) else None
        )
        obs_id = self.observable.get("standard_id")
        obs_uuid = self.observable.get("id")
        obs_identifiers = [i for i in (obs_id, obs_uuid) if i]

        # Check if an indicator for this pattern exists in the bundle, observable metadata, or OpenCTI platform
        # Restrict retirement to indicators owned by this connector (P1)
        found_in_bundle = any(
            (
                getattr(obj, "id", None)
                or (obj.get("id") if isinstance(obj, dict) else None)
            )
            == indicator_id
            and (
                getattr(obj, "created_by_ref", None)
                or (obj.get("created_by_ref") if isinstance(obj, dict) else None)
            )
            == author_id
            for obj in self.bundle
        )
        found_in_observable = any(
            isinstance(ind, dict)
            and (
                ind.get("id") == indicator_id or ind.get("standard_id") == indicator_id
            )
            and (
                (ind.get("createdBy") or {}).get("standard_id") == author_id
                or (ind.get("createdBy") or {}).get("id") == author_id
                or ind.get("created_by_ref") == author_id
            )
            for ind in self.observable.get("indicators", [])
        )
        found_in_opencti = False
        ind_data: Optional[Dict[str, Any]] = None
        if hasattr(self.helper, "api") and self.helper.api:
            try:
                ind_data = self.helper.api.indicator.read(id=indicator_id)
                if isinstance(ind_data, dict):
                    created_by = ind_data.get("createdBy") or {}
                    c_id = (
                        created_by.get("standard_id")
                        or created_by.get("id")
                        or ind_data.get("created_by_ref")
                    )
                    if c_id == author_id:
                        found_in_opencti = True
            except Exception as e:
                self.helper.connector_logger.warning(
                    f"[Lamis Network] Failed to query existing indicator {indicator_id} in OpenCTI: {e}"
                )

        if found_in_bundle or found_in_observable or found_in_opencti:
            marking_refs = self.get_marking_refs()
            now_utc = datetime.now(timezone.utc)
            valid_from = self._find_existing_indicator_valid_from(
                indicator_id=indicator_id, ind_data=ind_data
            ) or (now_utc - timedelta(seconds=1))

            revoked_indicator = Indicator(
                id=indicator_id,
                created_by_ref=self.author.id,
                name=ip_value,
                description=f"Lamis Network: risk level decreased for {ip_value}; indicator retired.",
                pattern=pattern,
                pattern_type="stix",
                valid_from=valid_from,
                valid_until=now_utc,
                custom_properties={
                    "x_opencti_score": 0,
                    "x_opencti_main_observable_type": entity_type,
                },
                object_marking_refs=marking_refs,
                allow_custom=True,
            )
            # Remove obsolete based-on relationship from bundle and OpenCTI platform
            self._retire_relationships(
                relationship_type="based-on",
                from_id=indicator_id,
                to_id=obs_identifiers,
            )
            if found_in_bundle:
                for i, obj in enumerate(self.bundle):
                    if (
                        getattr(obj, "id", None)
                        or (obj.get("id") if isinstance(obj, dict) else None)
                    ) == indicator_id:
                        self.bundle[i] = revoked_indicator
                        break
            else:
                self.bundle.append(revoked_indicator)

    def create_indicator(
        self,
        ip_value: str,
        entity_type: str,
        fraud_score: int,
        labels: List[str],
        description: str,
        evaluated_flags: Optional[Dict[str, Optional[bool]]] = None,
    ) -> None:
        """Create a STIX Indicator and a based-on relationship to the observable."""
        stix_entity_type = "ipv4-addr" if entity_type == "IPv4-Addr" else "ipv6-addr"
        pattern = f"[{stix_entity_type}:value = '{_stix_quote(ip_value)}']"
        indicator_id = PyctiIndicator.generate_id(pattern)
        author_id = getattr(self.author, "id", None) or (
            self.author.get("id") if isinstance(self.author, dict) else None
        )

        # Preserve indicators owned by other creators (analyst or third party) or unowned indicators
        existing_bundle_indicator = None
        for obj in self.bundle:
            obj_id = getattr(obj, "id", None) or (
                obj.get("id") if isinstance(obj, dict) else None
            )
            if obj_id == indicator_id:
                c_ref = getattr(obj, "created_by_ref", None) or (
                    obj.get("created_by_ref") if isinstance(obj, dict) else None
                )
                if c_ref != author_id:
                    self.helper.connector_logger.info(
                        f"[Lamis Network] Existing indicator {indicator_id} is not confirmed to be created by this connector ({c_ref}); skipping creation."
                    )
                    return
                existing_bundle_indicator = obj

        existing_obs_indicator = None
        for ind in self.observable.get("indicators", []):
            if isinstance(ind, dict) and (
                ind.get("id") == indicator_id or ind.get("standard_id") == indicator_id
            ):
                created_by = ind.get("createdBy") or {}
                c_id = (
                    created_by.get("standard_id")
                    or created_by.get("id")
                    or ind.get("created_by_ref")
                )
                if c_id != author_id:
                    self.helper.connector_logger.info(
                        f"[Lamis Network] Existing indicator {indicator_id} in observable is not confirmed to be created by this connector ({c_id}); skipping creation."
                    )
                    return
                existing_obs_indicator = ind

        ind_data: Optional[Dict[str, Any]] = None
        if hasattr(self.helper, "api") and self.helper.api:
            try:
                ind_data = self.helper.api.indicator.read(id=indicator_id)
                if isinstance(ind_data, dict):
                    created_by = ind_data.get("createdBy") or {}
                    c_id = (
                        created_by.get("standard_id")
                        or created_by.get("id")
                        or ind_data.get("created_by_ref")
                    )
                    if c_id != author_id:
                        self.helper.connector_logger.info(
                            f"[Lamis Network] Existing indicator {indicator_id} in OpenCTI is not confirmed to be created by this connector ({c_id}); skipping creation."
                        )
                        return
            except Exception as e:
                self.helper.connector_logger.warning(
                    f"[Lamis Network] Failed to verify indicator ownership for {indicator_id}: {e}; skipping creation to fail closed."
                )
                return

        marking_refs = self.get_marking_refs()
        existing_valid_from = self._find_existing_indicator_valid_from(
            indicator_id=indicator_id, ind_data=ind_data
        )

        ext_ref = ExternalReference(
            source_name="Lamis Network",
            url="https://lamisnetwork.com",
            description=f"Lamis Network IP risk evaluation (Score: {fraud_score}/100)",
        )

        # Reconcile indicator labels: preserve analyst-added labels and retain
        # previously applied managed labels unless explicitly evaluated as False.
        existing_sources = [
            s
            for s in (existing_bundle_indicator, existing_obs_indicator, ind_data)
            if s is not None
        ]

        def _extract_labels_from_source(src: Any) -> List[str]:
            raw_labels = None
            if isinstance(src, dict):
                raw_labels = (
                    src.get("labels")
                    or src.get("x_opencti_labels")
                    or src.get("objectLabel")
                )
            else:
                raw_labels = getattr(src, "labels", None)

            extracted: List[str] = []
            if isinstance(raw_labels, (list, set, tuple)):
                for item in raw_labels:
                    if isinstance(item, str) and item:
                        extracted.append(item)
                    elif isinstance(item, dict):
                        val = item.get("value") or item.get("name")
                        if isinstance(val, str) and val:
                            extracted.append(val)
            elif isinstance(raw_labels, dict) and "edges" in raw_labels:
                for edge in raw_labels.get("edges", []):
                    if isinstance(edge, dict):
                        node = edge.get("node")
                        if isinstance(node, dict):
                            val = node.get("value") or node.get("name")
                            if isinstance(val, str) and val:
                                extracted.append(val)
                        elif isinstance(node, str) and node:
                            extracted.append(node)
            return extracted

        def _extract_tracked_from_source(src: Any) -> Optional[List[str]]:
            raw = None
            if isinstance(src, dict):
                raw = src.get("x_lamis_network_labels") or (
                    src.get("custom_properties") or {}
                ).get("x_lamis_network_labels")
            else:
                raw = getattr(src, "x_lamis_network_labels", None)
                if (
                    raw is None
                    and hasattr(src, "custom_properties")
                    and isinstance(src.custom_properties, dict)
                ):
                    raw = src.custom_properties.get("x_lamis_network_labels")
            if isinstance(raw, (list, set, tuple)):
                return [str(x) for x in raw if isinstance(x, (str, int))]
            return None

        prev_ind_labels: List[str] = []
        for src in existing_sources:
            for lbl in _extract_labels_from_source(src):
                if lbl not in prev_ind_labels:
                    prev_ind_labels.append(lbl)

        tracked_ind_labels: Optional[List[str]] = None
        for src in existing_sources:
            t = _extract_tracked_from_source(src)
            if t is not None:
                tracked_ind_labels = t
                break

        if tracked_ind_labels is not None:
            prev_connector_labels = set(tracked_ind_labels)
        else:
            # No tracking metadata — this is the first run on this indicator
            # (or prior to tracking). Do NOT treat untracked labels as
            # connector-owned, even if they share managed names. This mirrors
            # the observable path and protects analyst-added labels.
            prev_connector_labels: Set[str] = set()

        new_connector_labels = set(labels)

        stale_labels: Set[str] = set()
        if evaluated_flags is not None:
            for lbl in prev_connector_labels:
                if evaluated_flags.get(lbl) is False:
                    stale_labels.add(lbl)
        else:
            stale_labels = prev_connector_labels - new_connector_labels

        active_connector_labels = (
            prev_connector_labels - stale_labels
        ) | new_connector_labels

        reconciled_labels = [lb for lb in prev_ind_labels if lb not in stale_labels]
        for lb in sorted(active_connector_labels):
            if lb not in reconciled_labels:
                reconciled_labels.append(lb)

        sorted_active_labels = sorted(active_connector_labels)

        if existing_valid_from:
            indicator = Indicator(
                id=indicator_id,
                created_by_ref=self.author.id,
                name=ip_value,
                description=description,
                pattern=pattern,
                pattern_type="stix",
                valid_from=existing_valid_from,
                custom_properties={
                    "x_opencti_score": fraud_score,
                    "x_opencti_main_observable_type": entity_type,
                    "x_lamis_network_labels": sorted_active_labels,
                },
                labels=reconciled_labels,
                object_marking_refs=marking_refs,
                external_references=[ext_ref],
                allow_custom=True,
            )
        else:
            indicator = Indicator(
                id=indicator_id,
                created_by_ref=self.author.id,
                name=ip_value,
                description=description,
                pattern=pattern,
                pattern_type="stix",
                custom_properties={
                    "x_opencti_score": fraud_score,
                    "x_opencti_main_observable_type": entity_type,
                    "x_lamis_network_labels": sorted_active_labels,
                },
                labels=reconciled_labels,
                object_marking_refs=marking_refs,
                external_references=[ext_ref],
                allow_custom=True,
            )

        relationship = Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on",
                indicator.id,
                self.observable["standard_id"],
            ),
            relationship_type="based-on",
            created_by_ref=self.author.id,
            source_ref=indicator.id,
            target_ref=self.observable["standard_id"],
            object_marking_refs=marking_refs,
            allow_custom=True,
        )

        found = False
        for i, obj in enumerate(self.bundle):
            if (
                getattr(obj, "id", None)
                or (obj.get("id") if isinstance(obj, dict) else None)
            ) == indicator_id:
                self.bundle[i] = indicator
                found = True
                break
        if not found:
            self.bundle.append(indicator)

        # Ensure no duplicate based-on relationship in bundle
        self.bundle = [
            obj
            for obj in self.bundle
            if not (
                (
                    getattr(obj, "type", None)
                    or (obj.get("type") if isinstance(obj, dict) else None)
                )
                == "relationship"
                and (
                    getattr(obj, "relationship_type", None)
                    or (obj.get("relationship_type") if isinstance(obj, dict) else None)
                )
                == "based-on"
                and (
                    getattr(obj, "source_ref", None)
                    or (obj.get("source_ref") if isinstance(obj, dict) else None)
                )
                == indicator.id
                and (
                    getattr(obj, "target_ref", None)
                    or (obj.get("target_ref") if isinstance(obj, dict) else None)
                )
                == self.observable["standard_id"]
                and (
                    getattr(obj, "created_by_ref", None)
                    or (obj.get("created_by_ref") if isinstance(obj, dict) else None)
                )
                == self.author.id
            )
        ]
        self.bundle.append(relationship)
        self.helper.connector_logger.debug(
            f"[Lamis Network] Created Indicator {indicator_id} with labels={reconciled_labels}"
        )

    def send_bundle(self) -> str:
        """Serialize STIX objects and dispatch the bundle to OpenCTI."""
        if not self.bundle:
            return "No STIX objects generated."

        # Ensure author is in bundle
        author_id = getattr(self.author, "id", None) or (
            self.author.get("id") if isinstance(self.author, dict) else None
        )
        existing_ids = {
            getattr(obj, "id", None)
            or (obj.get("id") if isinstance(obj, dict) else None)
            for obj in self.bundle
        }
        if author_id and author_id not in existing_ids:
            self.bundle.append(self.author)
            existing_ids.add(author_id)

        # Include basic TLP marking definitions
        for marking in _TLP_MAP.values():
            if marking.id not in existing_ids:
                self.bundle.append(marking)
                existing_ids.add(marking.id)

        # Include referenced marking definitions from OpenCTI (e.g. PAP, custom markings)
        if (
            hasattr(self.helper, "api")
            and self.helper.api
            and hasattr(self.helper.api, "marking_definition")
        ):
            for ref in self.get_marking_refs():
                if ref not in existing_ids:
                    try:
                        m_data = self.helper.api.marking_definition.read(id=ref)
                        if isinstance(m_data, dict):
                            m_def = (
                                m_data.get("definition")
                                or m_data.get("name")
                                or "statement"
                            )
                            m_type = m_data.get("definition_type") or "statement"
                            try:
                                marking_obj = stix2.MarkingDefinition(
                                    id=ref,
                                    definition_type=m_type,
                                    definition=(
                                        {"statement": m_def}
                                        if m_type == "statement"
                                        else {m_type: m_def}
                                    ),
                                    allow_custom=True,
                                )
                            except Exception:
                                marking_obj = {
                                    "type": "marking-definition",
                                    "spec_version": "2.1",
                                    "id": ref,
                                    "definition_type": m_type,
                                    "definition": (
                                        {"statement": m_def}
                                        if m_type == "statement"
                                        else {m_type: m_def}
                                    ),
                                }
                            self.bundle.append(marking_obj)
                            existing_ids.add(ref)
                    except Exception:
                        pass

        # Send with cleanup_inconsistent_bundle=False so that platform markings
        # and references on newly enriched objects are never stripped by OpenCTI SDK.
        serialized_bundle = self.helper.stix2_create_bundle(self.bundle)
        self.helper.send_stix2_bundle(
            serialized_bundle, cleanup_inconsistent_bundle=False
        )
        return f"Sent STIX bundle with {len(self.bundle)} objects."
