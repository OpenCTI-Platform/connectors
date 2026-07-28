from __future__ import annotations

from datetime import datetime
from typing import Any

import models as ds
import stix2
from connector.settings import ACTOR_PROFILE_COLLECTIONS as _ACTOR_PROFILE_COLLECTIONS
from connector.settings import MALWARE_DESC_PLACEHOLDER
from connector.settings import REPORT_NOTE_COLLECTIONS as _REPORT_NOTE_COLLECTIONS
from connector.settings import THREAT_LEVEL_TO_SCORE
from support.incident_note_markdown import (
    markdown_malware,
    markdown_threat_actor,
    markdown_threat_report,
)


class SdoMixin:
    def generate_stix_domain(self, name: str) -> Any:
        self.helper.connector_logger.debug(
            f"Generating STIX domain object for name: {name}"
        )
        _type = "domain-name"

        entity_labels, _ = self._compose_observable_labels()
        domain = ds.Domain(
            name=name,
            c_type=_type,
            tlp_color=self.tlp_color,
            labels=entity_labels,
        )
        self.helper.connector_logger.info(f"STIX domain object generated for: {name}")
        return domain

    def generate_stix_url(self, name: str) -> Any:
        self.helper.connector_logger.debug(
            f"Generating STIX URL object for name: {name}"
        )
        _type = "url"

        entity_labels, _ = self._compose_observable_labels()
        url = ds.URL(
            name=name,
            c_type=_type,
            tlp_color=self.tlp_color,
            labels=entity_labels,
        )
        self.helper.connector_logger.info(f"STIX URL object generated for: {name}")
        return url

    def generate_stix_ipv4(self, name: str) -> Any:
        self.helper.connector_logger.debug(
            f"Generating STIX IPv4 object for name: {name}"
        )
        _type = "ipv4-addr"

        entity_labels, _ = self._compose_observable_labels()
        ip = ds.IPAddress(
            name=name,
            c_type=_type,
            tlp_color=self.tlp_color,
            labels=entity_labels,
        )
        self.helper.connector_logger.info(f"STIX IPv4 object generated for: {name}")
        return ip

    def generate_locations(
        self, obj_country_codes: list[Any], change_type_to: str | None = None
    ) -> list[Any]:
        self.helper.connector_logger.debug(
            f"Generating locations for country codes: {obj_country_codes}, change_type_to: {change_type_to}"
        )
        _type = "location"
        if change_type_to:
            _type = change_type_to

        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
        )
        locations = []
        for _cc in obj_country_codes:
            if not _cc:
                continue
            loc = ds.Location(
                name=_cc,
                c_type=_type,
                tlp_color=self.tlp_color,
                labels=entity_labels,
            )
            loc.generate_stix_objects()
            locations.append(loc)
        self.helper.connector_logger.info(
            f"Generated {len(locations)} location objects"
        )
        return locations

    @staticmethod
    def _region_display(raw: str) -> str:
        token = str(raw).split(":")[-1].strip()
        return token.replace("_", " ").title() if token else str(raw)

    def generate_stix_targeted_entities(
        self,
        obj: dict[str, Any],
        related_objects: list[Any] | None = None,
    ) -> list[Any]:
        """Promote threat-report victimology into searchable SDOs.

        ``sectors`` → Identity (Sector), ``targeted_companies`` /
        ``targeted_partners`` → Identity (Organization), ``regions`` →
        Location (Region). When the bundle carries a Threat-Actor /
        Intrusion-Set, each entity is linked via ``<actor> targets <entity>``.
        """
        if not obj:
            return []
        if self.collection not in _REPORT_NOTE_COLLECTIONS:
            return []
        if not self.config.get_setting_bool(
            self.collection, "targeted_entities_as_sdo", default=True
        ):
            return []

        def _str_list(value: Any) -> list[str]:
            out: list[str] = []
            seen: set[str] = set()
            for v in value if isinstance(value, list) else [value]:
                if v is None:
                    continue
                s = str(v).strip()
                if s and s not in seen:
                    seen.add(s)
                    out.append(s)
            return out

        sectors = _str_list(obj.get("sectors"))
        companies = _str_list(obj.get("targeted_companies"))
        partners = _str_list(obj.get("targeted_partners"))
        regions = _str_list(obj.get("regions"))
        if not (sectors or companies or partners or regions):
            return []

        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
        )

        actor = next(
            (
                ro
                for ro in (related_objects or [])
                if ro is not None and getattr(ro, "stix_main_object", None)
            ),
            None,
        )

        out: list[Any] = []
        for name, identity_class, desc in (
            *((s, "class", "Targeted sector (Group-IB TI).") for s in sectors),
            *(
                (c, "organization", "Targeted company (Group-IB TI).")
                for c in companies
            ),
            *(
                (p, "organization", "Targeted partner/client (Group-IB TI).")
                for p in partners
            ),
        ):
            ident = ds.Identity(
                name=name,
                c_type="identity",
                identity_class=identity_class,
                tlp_color=self._resolve_tlp_color("identity"),
                labels=entity_labels,
            )
            ident.set_description(desc)
            ident.generate_stix_objects()
            out.append(ident)

        for raw_region in regions:
            loc = ds.Location(
                name=self._region_display(raw_region),
                c_type="location",
                tlp_color=self._resolve_tlp_color("location"),
                labels=entity_labels,
                location_type="Region",
                region_value=raw_region.split(":")[-1].replace("_", "-"),
            )
            loc.generate_stix_objects()
            out.append(loc)

        if actor is not None:
            for entity in out:
                entity.generate_relationship(
                    actor.stix_main_object,
                    entity.stix_main_object,
                    relation_type="targets",
                )
                entity.add_relationships_to_stix_objects()

        self.helper.connector_logger.info(
            f"Generated {len(out)} targeted-entity objects "
            f"(sectors={len(sectors)}, companies={len(companies)}, "
            f"partners={len(partners)}, regions={len(regions)})"
        )
        return out

    def generate_stix_malware(
        self, obj: dict[str, Any], json_date_obj: dict[str, Any] | None = None
    ) -> list[Any]:
        self.helper.connector_logger.info("Starting generation of STIX malware objects")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for malware generation"
            )
            return list()

        _type = "malware"
        _events = obj.get("malware_report_list", [])

        _stix_objects: list[Any] = []
        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
        )

        # Multi-item path: actor profiles ship malware as a list of strings,
        # threat-report ships them as dicts. These are minimal Malware SDOs
        # without the full enrichment (the source payload is just a name).
        if _events:
            self.helper.connector_logger.debug(
                f"Processing {len(_events)} malware events"
            )
            for _e in _events:
                if isinstance(_e, str):
                    _e = {"name": _e}
                _name = _e.get("name")
                _malware_types = _e.get("category")
                _malware_aliases = _e.get("aliases")
                _portal_links = self._retrieve_link(_e)

                if not _name:
                    continue
                names = _name if isinstance(_name, list) else [_name]
                for n in names:
                    malware = ds.Malware(
                        name=n,
                        aliases=_malware_aliases,
                        c_type=_type,
                        malware_types=_malware_types or [],
                        tlp_color=self._resolve_tlp_color(_type),
                        labels=entity_labels,
                    )
                    malware.generate_external_references(_portal_links)
                    malware.generate_stix_objects()
                    self._log_tlp_applied(malware, _type, n)
                    _stix_objects.append(malware)

            self.helper.connector_logger.info(
                f"Generated {len(_stix_objects)} STIX malware objects"
            )
            return _stix_objects

        # Single-item path: malware/malware payload. Enrich with description,
        # threat-level score, language / platform labels, plus Threat-Actor,
        # linked-Malware, MITRE ATT&CK, source-Location relationships.
        _name = obj.get("name")
        if not _name:
            self.helper.connector_logger.info("malware payload missing 'name'")
            return _stix_objects

        _malware_types = obj.get("category")
        _malware_aliases = obj.get("aliases") or []
        _description = self.normalize_description(obj.get("description"))
        _short_description = self.normalize_description(obj.get("short_description"))

        def _is_unusable(text: str | None) -> bool:
            return not text or text.strip() == MALWARE_DESC_PLACEHOLDER

        if _is_unusable(_description) and not _is_unusable(_short_description):
            _description = _short_description
        _threat_level = obj.get("threat_level")
        _portal_links = self._retrieve_link(obj)
        _last_seen = (
            self._parse_iso_utc((json_date_obj or {}).get("date-updated"))
            if json_date_obj
            else None
        )

        score, _severity_label = self._map_threat_level_to_score(_threat_level)

        malware = ds.Malware(
            name=_name,
            aliases=_malware_aliases,
            c_type=_type,
            malware_types=_malware_types,
            last_seen=_last_seen,
            risk_score=score,
            tlp_color=self._resolve_tlp_color(_type),
            labels=entity_labels,
        )
        if _description:
            malware.set_description(_description)
        malware.generate_external_references(_portal_links)
        desc_in_ext = self.config.get_setting_bool(
            self.collection,
            "description_in_external_references",
            default=False,
        )
        if desc_in_ext:
            malware.set_description("")
            if _description:
                malware.external_references.append(
                    stix2.ExternalReference(
                        source_name="Malware description",
                        description=str(_description),
                    )
                )
        if _short_description:
            malware.external_references.append(
                stix2.ExternalReference(
                    source_name="Short description",
                    description=str(_short_description),
                )
            )
        malware.generate_stix_objects()
        self._log_tlp_applied(malware, _type, _name)
        _stix_objects.append(malware)

        # Companion SDOs and relationships built from enriched payload.
        related_sdos = self._build_malware_companions(
            malware=malware,
            obj=obj,
            entity_labels=entity_labels,
        )
        _stix_objects.extend(related_sdos)

        # Profile Note (platform / languages / threat level / arsenal /
        # description) — carries the metadata no longer flattened into labels.
        # Travels with the Malware wrapper's stix_objects.
        mal_note = self._finalize_stix_note(
            name=f"Malware profile: {_name}",
            content=markdown_malware(obj=obj, json_date_obj=json_date_obj or {}),
            object_refs=[malware.stix_main_object.id]
            + [o.stix_main_object.id for o in related_sdos],
            labels=entity_labels,
            portal_links=_portal_links or None,
            created=_last_seen,
        )
        malware.stix_objects.append(mal_note)

        self.helper.connector_logger.info(
            f"Generated {len(_stix_objects)} STIX malware objects "
            f"(1 Malware + {len(related_sdos)} related/relationship entities)"
        )
        return _stix_objects

    def _map_threat_level_to_score(
        self, threat_level: Any
    ) -> tuple[int | None, str | None]:
        """Group-IB threat-level string → (x_opencti_score, severity label)."""
        if not threat_level:
            return None, None
        key = str(threat_level).strip().lower()
        return THREAT_LEVEL_TO_SCORE.get(key, (None, None))

    def _build_malware_companions(
        self,
        *,
        malware: Any,
        obj: dict[str, Any],
        entity_labels: list[str],
    ) -> list[Any]:
        """Emit Threat-Actor / Malware / Attack-Pattern / Location SDOs that
        accompany a malware/malware payload, plus the relationships that
        connect them back to the Malware SDO.
        """
        out: list[Any] = []

        # Related threat actors (uses).
        actors: list[Any] = []
        for raw in (obj.get("ta_list") or []) + (obj.get("threat_actor_list") or []):
            ta_name = raw.get("name") if isinstance(raw, dict) else raw
            if not ta_name:
                continue
            ta = ds.ThreatActor(
                name=ta_name,
                c_type="threat-actor",
                global_label=None,
                tlp_color=self._resolve_tlp_color("threat-actor"),
                labels=entity_labels,
            )
            ta.generate_stix_objects()
            actors.append(ta)
            out.append(ta)
        if actors:
            self._generate_relations(
                main_obj=malware, related_objects=actors, helper=self.helper
            )

        # Linked malware families (variant-of).
        linked: list[Any] = []
        for raw in obj.get("linked_malware") or []:
            lm_name = raw.get("name") if isinstance(raw, dict) else raw
            if not lm_name or lm_name == obj.get("name"):
                continue
            lm = ds.Malware(
                name=lm_name,
                aliases=None,
                c_type="malware",
                malware_types=None,
                tlp_color=self._resolve_tlp_color("malware"),
                labels=entity_labels,
            )
            lm.generate_stix_objects()
            # A linked-malware name that differs as a string but normalizes to
            # the same STIX id as the parent would create a self-relationship
            # (OpenCTI: "Relation cant be created with the same source and
            # target"). Skip it.
            if lm.stix_main_object.id == malware.stix_main_object.id:
                continue
            linked.append(lm)
            out.append(lm)
        if linked:
            self._generate_relations(
                main_obj=malware, related_objects=linked, helper=self.helper
            )

        # MITRE ATT&CK techniques (uses). The malware/malware payload
        # ships these either as id/name dicts or as a bare list of strings.
        # We only emit an Attack-Pattern SDO when a MITRE technique id
        # (``T####``) is present — without it the SDO has no stable
        # identifier and would collide with similarly-named entries from
        # other reports.
        patterns: list[Any] = []
        for raw in obj.get("mitre_matrix") or []:
            if isinstance(raw, dict):
                mitre_id = raw.get("id") or raw.get("technique") or ""
                ap_name = raw.get("name") or mitre_id
            else:
                ap_name = str(raw)
                mitre_id = ap_name if str(ap_name).startswith("T") else ""
            if not ap_name or not mitre_id:
                continue
            ap = ds.AttackPattern(
                name=str(ap_name),
                c_type="attack-pattern",
                kill_chain_phases=[],
                mitre_id=str(mitre_id),
                tlp_color=self._resolve_tlp_color("attack-pattern"),
                labels=entity_labels,
            )
            ap.generate_stix_objects()
            patterns.append(ap)
            out.append(ap)
        if patterns:
            self._generate_relations(
                main_obj=malware, related_objects=patterns, helper=self.helper
            )

        # Source-country / geo-region Locations (originates-from).
        country_codes: list[str] = []
        for raw in obj.get("source_countries") or []:
            if isinstance(raw, str) and raw.strip():
                country_codes.append(raw.strip().upper())
        locations: list[Any] = []
        if country_codes:
            locations = self.generate_locations(
                country_codes, change_type_to="base-location"
            )
            out.extend(locations)
            if locations:
                self._generate_relations(
                    main_obj=malware,
                    related_objects=locations,
                    helper=self.helper,
                )

        malware.add_relationships_to_stix_objects()
        return out

    def generate_stix_vulnerability(
        self,
        obj: dict[str, Any],
        related_objects: list[Any],
        json_date_obj: dict[str, Any] | None = None,
        json_cvss_obj: dict[str, Any] | None = None,
    ) -> list[Any]:
        self.helper.connector_logger.info(
            "Starting generation of STIX vulnerability objects"
        )
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for vulnerability generation"
            )
            return list()

        _description = obj.get("__")
        _type = "vulnerability"
        if json_cvss_obj:
            _cvssv3_score = json_cvss_obj.get("score", None)
            _cvssv3_vector = json_cvss_obj.get("vector", None)
            self.helper.connector_logger.debug(
                f"CVSS score: {_cvssv3_score}, vector: {_cvssv3_vector}"
            )
        else:
            _cvssv3_score = None
            _cvssv3_vector = None
        _events = obj.get("vulnerability_list", [])

        _date_published = self._retrieve_date(json_date_obj, "date-published")

        _stix_objects = list()
        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
        )

        if _events:
            self.helper.connector_logger.debug(
                f"Processing {len(_events)} vulnerability events"
            )
            for _e in _events:
                # Actor profiles return CVE as a flat list of strings
                # (e.g. ``stat.cve`` from apt/threat_actor). Wrap each
                # string into the dict shape the rest of this loop expects.
                if isinstance(_e, str):
                    _e = {"object_id": _e}
                _name = _e.get("object_id")
                _description = self.normalize_description(_e.get("description"))

                if _name:
                    if isinstance(_name, list):
                        self.helper.connector_logger.debug(
                            f"Processing list of vulnerability names: {_name}"
                        )
                        for n in _name:
                            vulnerability = ds.Vulnerability(
                                name=n,
                                c_type=_type,
                                created=_date_published,
                                cvss_score=_cvssv3_score,
                                cvss_vector=_cvssv3_vector,
                                tlp_color=self.tlp_color,
                                labels=entity_labels,
                            )
                            vulnerability.set_description(_description)
                            vulnerability.generate_stix_objects()
                            self.helper.connector_logger.debug(
                                f"Generated STIX vulnerability object for name: {n}"
                            )

                            self._generate_relations(
                                main_obj=vulnerability,
                                related_objects=related_objects,
                                helper=self.helper,
                            )

                            vulnerability.add_relationships_to_stix_objects()

                            _stix_objects.append(vulnerability)
                    else:
                        vulnerability = ds.Vulnerability(
                            name=_name,
                            c_type=_type,
                            created=_date_published,
                            cvss_score=_cvssv3_score,
                            cvss_vector=_cvssv3_vector,
                            tlp_color=self.tlp_color,
                            labels=entity_labels,
                        )
                        vulnerability.set_description(_description)
                        vulnerability.generate_stix_objects()
                        self.helper.connector_logger.debug(
                            f"Generated STIX vulnerability object for name: {_name}"
                        )

                        self._generate_relations(
                            main_obj=vulnerability,
                            related_objects=related_objects,
                            helper=self.helper,
                        )

                        vulnerability.add_relationships_to_stix_objects()

                        _stix_objects.append(vulnerability)

        else:
            _name = obj.get("object_id")
            _description = self.normalize_description(obj.get("description"))

            if _name:
                vulnerability = ds.Vulnerability(
                    name=_name,
                    c_type=_type,
                    created=_date_published,
                    cvss_score=_cvssv3_score,
                    cvss_vector=_cvssv3_vector,
                    tlp_color=self.tlp_color,
                    labels=entity_labels,
                )
                vulnerability.set_description(_description)
                vulnerability.generate_stix_objects()
                self.helper.connector_logger.debug(
                    f"Generated STIX vulnerability object for name: {_name}"
                )

                self._generate_relations(
                    main_obj=vulnerability,
                    related_objects=related_objects,
                    helper=self.helper,
                )

                vulnerability.add_relationships_to_stix_objects()

                _stix_objects.append(vulnerability)

        self.helper.connector_logger.info(
            f"Generated {len(_stix_objects)} STIX vulnerability objects"
        )
        return _stix_objects

    def generate_stix_attack_pattern(self, obj: dict[str, Any]) -> list[Any]:
        self.helper.connector_logger.info(
            "Starting generation of STIX attack pattern objects"
        )
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for attack pattern generation"
            )
            return list()

        _description = obj.get("__")
        _type = "attack-pattern"
        _events = obj.get("mitre_matrix_list")

        _stix_objects = list()

        event_mitre_matrix = self._generate_mitre_matrix(_events)
        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
        )

        for k, v in event_mitre_matrix.items():

            kill_chain_phases = self.generate_kill_chain_phases(v["kill_chain_phases"])

            if k:
                attack_pattern = ds.AttackPattern(
                    name=self.mitre_mapper.get(k),
                    c_type=_type,
                    mitre_id=k,
                    kill_chain_phases=kill_chain_phases,
                    labels=entity_labels,
                )
                attack_pattern.set_description(_description)
                attack_pattern.generate_external_references(v["portal_links"])
                attack_pattern.generate_stix_objects()
                self.helper.connector_logger.debug(
                    f"Generated STIX attack pattern object for MITRE ID: {k}"
                )

                _stix_objects.append(attack_pattern)

        self.helper.connector_logger.info(
            f"Generated {len(_stix_objects)} STIX attack pattern objects"
        )
        return _stix_objects

    def generate_stix_threat_actor(
        self,
        obj: dict[str, Any],
        related_objects: list[Any],
        json_date_obj: dict[str, Any] | None = None,
    ) -> tuple[Any | None, list[Any] | None]:
        self.helper.connector_logger.info(
            "Starting generation of STIX threat actor objects"
        )
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for threat actor generation"
            )
            return None, None

        _type = "threat-actor"
        _global_label = self.ta_global_label
        if _global_label == "nation_state" and not self._should_include_label_type(
            "nation_state"
        ):
            _global_label = None
        elif _global_label == "cybercriminal" and not self._should_include_label_type(
            "cybercriminal"
        ):
            _global_label = None
        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            include_nation_state=(self.ta_global_label == "nation_state"),
            include_cybercriminal=(self.ta_global_label == "cybercriminal"),
        )

        _threat_actor_name = obj.get("name")
        _threat_actor_country = obj.get("country")
        _threat_actor_targeted_countries = obj.get("targeted_countries")
        _threat_actor_aliases = obj.get("aliases")
        _threat_actor_description = self.normalize_description(obj.get("description"))
        _threat_actor_goals = obj.get("goals")
        _threat_actor_roles = obj.get("roles")
        _first_seen, _last_seen = self._extract_first_last_seen(json_date_obj)

        extra_actor_labels = self._build_actor_extra_labels(obj)
        if extra_actor_labels:
            entity_labels = list(entity_labels) + [
                lbl for lbl in extra_actor_labels if lbl not in entity_labels
            ]

        _portal_link = self._retrieve_link(obj)

        threat_actor = None
        locations = None

        if _threat_actor_name and len(_threat_actor_name) > 2:
            self.helper.connector_logger.debug(
                f"Generating threat actor for name: {_threat_actor_name}"
            )
            threat_actor = ds.ThreatActor(
                name=_threat_actor_name,
                c_type=_type,
                global_label=_global_label,
                tlp_color=self._resolve_tlp_color(_type),
                labels=entity_labels,
                aliases=_threat_actor_aliases,
                first_seen=_first_seen,
                last_seen=_last_seen,
                goals=_threat_actor_goals,
                roles=_threat_actor_roles,
            )
            threat_actor.set_description(_threat_actor_description)
            threat_actor.generate_external_references(_portal_link)
            desc_in_ext = self.config.get_setting_bool(
                self.collection,
                "description_in_external_references",
                default=False,
            )
            if desc_in_ext:
                threat_actor.set_description("")
                if _threat_actor_description:
                    threat_actor.external_references.append(
                        stix2.ExternalReference(
                            source_name="Threat actor description",
                            description=str(_threat_actor_description),
                        )
                    )
            threat_actor.generate_stix_objects()
            self._log_tlp_applied(threat_actor, _type, _threat_actor_name)
            self.helper.connector_logger.debug(
                f"Generated STIX threat actor object for name: {_threat_actor_name}"
            )

            base_locations = []
            if _threat_actor_country:
                base_locations = self.generate_locations(
                    [_threat_actor_country], change_type_to="base-location"
                )
                self.helper.connector_logger.debug(
                    f"Generated {len(base_locations)} base locations"
                )
            target_locations = []
            if _threat_actor_targeted_countries:
                target_locations = self.generate_locations(
                    _threat_actor_targeted_countries,
                    change_type_to="target-location",
                )
                self.helper.connector_logger.debug(
                    f"Generated {len(target_locations)} target locations"
                )

            locations = base_locations + target_locations

            if _threat_actor_name and base_locations:
                self._generate_relations(
                    main_obj=threat_actor,
                    related_objects=base_locations,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    "Generated relations for base locations"
                )

            if _threat_actor_name and target_locations:
                self._generate_relations(
                    main_obj=threat_actor,
                    related_objects=target_locations,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    "Generated relations for target locations"
                )

            self._generate_relations(
                main_obj=threat_actor,
                related_objects=related_objects,
                helper=self.helper,
            )
            self.helper.connector_logger.debug(
                "Generated relations for related objects"
            )

            threat_actor.add_relationships_to_stix_objects()
            self.helper.connector_logger.debug(
                "Added relationships to STIX threat actor objects"
            )

            # Attach an analyst Note with the structured profile statistics
            # (targeting, expertise, activity counts) for actor-profile
            # collections. The Note travels with the actor's stix_objects so
            # the default flow emits it without extra plumbing.
            if self.collection in _ACTOR_PROFILE_COLLECTIONS:
                ta_note = self._finalize_stix_note(
                    name=f"Threat actor profile: {_threat_actor_name}",
                    content=markdown_threat_actor(
                        obj=obj, json_date_obj=json_date_obj or {}
                    ),
                    object_refs=[threat_actor.stix_main_object.id],
                    labels=entity_labels,
                    portal_links=_portal_link or None,
                    created=_first_seen,
                    modified=_last_seen,
                )
                threat_actor.stix_objects.append(ta_note)

        self.helper.connector_logger.info(
            "Completed generation of STIX threat actor objects"
        )
        return threat_actor, locations

    def generate_stix_intrusion_set(
        self,
        obj: dict[str, Any],
        related_objects: list[Any],
        json_date_obj: dict[str, Any] | None = None,
    ) -> tuple[Any | None, list[Any] | None]:
        self.helper.connector_logger.info(
            "Starting generation of STIX intrusion set objects"
        )
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for intrusion set generation"
            )
            return None, None

        _type = "intrusion-set"
        _global_label = self.ta_global_label
        if _global_label == "nation_state" and not self._should_include_label_type(
            "nation_state"
        ):
            _global_label = None
        elif _global_label == "cybercriminal" and not self._should_include_label_type(
            "cybercriminal"
        ):
            _global_label = None
        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            include_nation_state=(self.ta_global_label == "nation_state"),
            include_cybercriminal=(self.ta_global_label == "cybercriminal"),
        )

        _intrusion_set_name = obj.get("name")
        _intrusion_set_country = obj.get("country")
        _intrusion_set_targeted_countries = obj.get("targeted_countries")
        _intrusion_set_aliases = obj.get("aliases")
        _intrusion_set_description = self.normalize_description(obj.get("description"))
        _intrusion_set_goals = obj.get("goals")
        _first_seen, _last_seen = self._extract_first_last_seen(json_date_obj)

        extra_is_labels = self._build_actor_extra_labels(obj)
        if extra_is_labels:
            entity_labels = list(entity_labels) + [
                lbl for lbl in extra_is_labels if lbl not in entity_labels
            ]

        _portal_link = self._retrieve_link(obj)

        intrusion_set = None
        locations = None

        if _intrusion_set_name and len(_intrusion_set_name) > 2:
            self.helper.connector_logger.debug(
                f"Generating intrusion set for name: {_intrusion_set_name}"
            )
            intrusion_set = ds.IntrusionSet(
                name=_intrusion_set_name,
                c_type=_type,
                global_label=_global_label,
                tlp_color=self._resolve_tlp_color(_type),
                labels=entity_labels,
                aliases=_intrusion_set_aliases,
                first_seen=_first_seen,
                last_seen=_last_seen,
                goals=_intrusion_set_goals,
            )
            intrusion_set.set_description(_intrusion_set_description)
            intrusion_set.generate_external_references(_portal_link)
            desc_in_ext = self.config.get_setting_bool(
                self.collection,
                "description_in_external_references",
                default=False,
            )
            if desc_in_ext:
                intrusion_set.set_description("")
                if _intrusion_set_description:
                    intrusion_set.external_references.append(
                        stix2.ExternalReference(
                            source_name="Intrusion set description",
                            description=str(_intrusion_set_description),
                        )
                    )
            intrusion_set.generate_stix_objects()
            self._log_tlp_applied(intrusion_set, _type, _intrusion_set_name)
            self.helper.connector_logger.debug(
                f"Generated STIX intrusion set object for name: {_intrusion_set_name}"
            )

            base_locations = []
            if _intrusion_set_country:
                base_locations = self.generate_locations(
                    [_intrusion_set_country], change_type_to="base-location"
                )
                self.helper.connector_logger.debug(
                    f"Generated {len(base_locations)} base locations"
                )
            target_locations = []
            if _intrusion_set_targeted_countries:
                target_locations = self.generate_locations(
                    _intrusion_set_targeted_countries,
                    change_type_to="target-location",
                )
                self.helper.connector_logger.debug(
                    f"Generated {len(target_locations)} target locations"
                )

            locations = base_locations + target_locations

            if _intrusion_set_name and base_locations:
                self._generate_relations(
                    main_obj=intrusion_set,
                    related_objects=base_locations,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    "Generated relations for base locations"
                )

            if _intrusion_set_name and target_locations:
                self._generate_relations(
                    main_obj=intrusion_set,
                    related_objects=target_locations,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    "Generated relations for target locations"
                )

            self._generate_relations(
                main_obj=intrusion_set,
                related_objects=related_objects,
                helper=self.helper,
            )
            self.helper.connector_logger.debug(
                "Generated relations for related objects"
            )

            intrusion_set.add_relationships_to_stix_objects()
            self.helper.connector_logger.debug(
                "Added relationships to STIX intrusion set objects"
            )

            # Same profile Note as the threat-actor variant (see
            # generate_stix_threat_actor) so actor-profile collections keep the
            # structured statistics even when emitted as Intrusion-Set.
            if self.collection in _ACTOR_PROFILE_COLLECTIONS:
                is_note = self._finalize_stix_note(
                    name=f"Threat actor profile: {_intrusion_set_name}",
                    content=markdown_threat_actor(
                        obj=obj, json_date_obj=json_date_obj or {}
                    ),
                    object_refs=[intrusion_set.stix_main_object.id],
                    labels=entity_labels,
                    portal_links=_portal_link or None,
                    created=_first_seen,
                    modified=_last_seen,
                )
                intrusion_set.stix_objects.append(is_note)

        self.helper.connector_logger.info(
            "Completed generation of STIX intrusion set objects"
        )
        return intrusion_set, locations

    def generate_stix_file(
        self,
        obj: dict[str, Any],
        json_date_obj: dict[str, Any] | None = None,
        related_objects: list[Any] | None = None,
        file_is_ioc: bool = True,
    ) -> list[Any]:
        self.helper.connector_logger.info("Starting generation of STIX file objects")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for file generation"
            )
            return list()

        _description = obj.get("__")
        _type = "file"
        _events = obj.get("file_list")

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _stix_objects = list()

        if _events:
            entity_labels, _ = self._compose_observable_labels()
            self.helper.connector_logger.debug(f"Processing {len(_events)} file events")
            for _e in _events:
                _md5 = _e.get("md5", None)
                _sha1 = _e.get("sha1", None)
                _sha256 = _e.get("sha256", None)
                if _md5:
                    if not self._valid_hash(_md5, "MD5"):
                        self.helper.connector_logger.error(
                            f"Error! {_md5} is not valid MD5. Ignored."
                        )
                        _md5 = None
                if _sha1:
                    if not self._valid_hash(_sha1, "SHA1"):
                        self.helper.connector_logger.error(
                            f"Error! {_sha1} is not valid SHA1. Ignored."
                        )
                        _sha1 = None
                if _sha256:
                    if not self._valid_hash(_sha256, "SHA256"):
                        self.helper.connector_logger.error(
                            f"Error! {_sha256} is not valid SHA256. Ignored."
                        )
                        _sha256 = None
                hashes = [_md5, _sha1, _sha256]
                self.helper.connector_logger.debug(
                    f"Processing file hashes: MD5={_md5}, SHA1={_sha1}, SHA256={_sha256}"
                )

                if any(hashes):
                    file = ds.FileHash(
                        name=hashes,
                        c_type=_type,
                        tlp_color=self.tlp_color,
                        labels=entity_labels,
                    )
                    file.set_description(_description)
                    file.is_ioc = file_is_ioc
                    file.set_valid_from(valid_from)
                    file.set_valid_until(valid_until)
                    file.generate_stix_objects()
                    self.helper.connector_logger.debug("Generated STIX file object")

                    self._generate_relations(
                        main_obj=file,
                        related_objects=related_objects,
                        is_ioc=file_is_ioc,
                        helper=self.helper,
                    )
                    self.helper.connector_logger.debug(
                        "Generated relations for file object"
                    )

                    file.add_relationships_to_stix_objects()
                    self.helper.connector_logger.debug(
                        "Added relationships to STIX file object"
                    )

                    _stix_objects.append(file)

        else:
            _md5 = obj.get("md5", None)
            _sha1 = obj.get("sha1", None)
            _sha256 = obj.get("sha256", None)
            if _md5:
                if not self._valid_hash(_md5, "MD5"):
                    self.helper.connector_logger.error(
                        f"Error! {_md5} is not valid MD5. Ignored."
                    )
                    _md5 = None
            if _sha1:
                if not self._valid_hash(_sha1, "SHA1"):
                    self.helper.connector_logger.error(
                        f"Error! {_sha1} is not valid SHA1. Ignored."
                    )
                    _sha1 = None
            if _sha256:
                if not self._valid_hash(_sha256, "SHA256"):
                    self.helper.connector_logger.error(
                        f"Error! {_sha256} is not valid SHA256. Ignored."
                    )
                    _sha256 = None
            hashes = [_md5, _sha1, _sha256]
            self.helper.connector_logger.debug(
                f"Processing file hashes: MD5={_md5}, SHA1={_sha1}, SHA256={_sha256}"
            )

            if any(hashes):
                entity_labels, _ = self._compose_observable_labels()
                file = ds.FileHash(
                    name=hashes,
                    c_type=_type,
                    tlp_color=self.tlp_color,
                    labels=entity_labels,
                )
                file.set_description(_description)
                file.is_ioc = file_is_ioc
                file.set_valid_from(valid_from)
                file.set_valid_until(valid_until)
                file.generate_stix_objects()
                self.helper.connector_logger.debug("Generated STIX file object")

                self._generate_relations(
                    main_obj=file,
                    related_objects=related_objects,
                    is_ioc=file_is_ioc,
                    helper=self.helper,
                )
                self.helper.connector_logger.debug(
                    "Generated relations for file object"
                )

                file.add_relationships_to_stix_objects()
                self.helper.connector_logger.debug(
                    "Added relationships to STIX file object"
                )

                _stix_objects.append(file)

        self.helper.connector_logger.info(
            f"Generated {len(_stix_objects)} STIX file objects"
        )
        return _stix_objects

    def _process_network_entry(
        self,
        entry: dict[str, Any],
        *,
        base_desc: Any,
        ddos_geo_suffix: str,
        domain_is_ioc: bool,
        url_is_ioc: bool,
        ip_is_ioc: bool,
        valid_from: Any,
        valid_until: Any,
        related_objects: list[Any] | None,
    ) -> tuple[list[Any], list[Any], list[Any]]:
        """Process one network entry (domain / URL / IP-addresses).

        Handles both list-form entries (``network_list`` items) and the legacy
        single-object form.  Returns (domain_wrappers, url_wrappers, ip_wrappers).
        """

        def compose_desc(base: Any) -> Any:
            if ddos_geo_suffix:
                return f"{base}\n\n{ddos_geo_suffix}" if base else ddos_geo_suffix
            return base

        domain_val = entry.get("domain")
        url_val = entry.get("url")
        # Normalize scalar fields: trim whitespace; treat blanks as missing
        # so downstream validators don't see " " / "" as candidates.
        if isinstance(domain_val, str):
            domain_val = domain_val.strip() or None
        if isinstance(url_val, str):
            url_val = url_val.strip() or None
        # Normalize: list entries store a list, single-object stores a scalar.
        ip_vals_raw = entry.get("ip-address")
        ip_vals: list[Any] = (
            ip_vals_raw
            if isinstance(ip_vals_raw, list)
            else ([ip_vals_raw] if ip_vals_raw else [])
        )
        ipv6_vals_raw = entry.get("ipv6-address")
        ipv6_vals: list[Any] = (
            ipv6_vals_raw
            if isinstance(ipv6_vals_raw, list)
            else ([ipv6_vals_raw] if ipv6_vals_raw else [])
        )

        domain_obj: Any = None
        url_obj: Any = None
        domains: list[Any] = []
        urls: list[Any] = []
        ips: list[Any] = []

        if domain_val:
            if self.is_ipv4(domain_val):
                ip = self.generate_stix_ipv4(domain_val)
                ip.set_description(compose_desc(base_desc))
                ip.is_ioc = domain_is_ioc
                ip.set_valid_from(valid_from)
                ip.set_valid_until(valid_until)
                ip.generate_stix_objects()
                self._generate_relations(
                    main_obj=ip,
                    related_objects=related_objects,
                    is_ioc=domain_is_ioc,
                    helper=self.helper,
                )
                ip.add_relationships_to_stix_objects()
                ips.append(ip)
            elif self.is_valid_domain(domain_val):
                domain_obj = self.generate_stix_domain(domain_val)
                if self.collection == "attacks/ddos":
                    domain_obj.set_description(compose_desc(base_desc))
                domain_obj.is_ioc = domain_is_ioc
                domain_obj.set_valid_from(valid_from)
                domain_obj.set_valid_until(valid_until)
                domain_obj.generate_stix_objects()
                self._generate_relations(
                    main_obj=domain_obj,
                    related_objects=related_objects,
                    is_ioc=domain_is_ioc,
                    helper=self.helper,
                )
                domains.append(domain_obj)
            else:
                self.helper.connector_logger.debug(
                    f"Skip malformed domain value: {domain_val!r}"
                )

        if url_val:
            if self.is_valid_url(url_val):
                url_obj = self.generate_stix_url(url_val)
                if self.collection == "attacks/ddos":
                    url_obj.set_description(compose_desc(base_desc))
                url_obj.is_ioc = url_is_ioc
                url_obj.set_valid_from(valid_from)
                url_obj.set_valid_until(valid_until)
                url_portal_links = self._retrieve_link(entry)
                if url_portal_links:
                    url_obj.generate_external_references(url_portal_links)
                url_obj.generate_stix_objects()
                self._generate_relations(
                    main_obj=url_obj,
                    related_objects=related_objects,
                    is_ioc=url_is_ioc,
                    helper=self.helper,
                )
                url_obj.add_relationships_to_stix_objects()
                urls.append(url_obj)
            else:
                self.helper.connector_logger.debug(
                    f"Skip malformed URL value: {url_val!r}"
                )

        for ip_val in ip_vals:
            if not self.is_ipv4(str(ip_val).strip()):
                self.helper.connector_logger.debug(
                    f"Skip malformed IPv4 value: {ip_val!r}"
                )
                continue
            ip = self.generate_stix_ipv4(str(ip_val).strip())
            ip.set_description(compose_desc(base_desc))
            ip.is_ioc = ip_is_ioc
            ip.set_valid_from(valid_from)
            ip.set_valid_until(valid_until)
            ip.generate_stix_objects()
            self._generate_relations(
                main_obj=ip,
                related_objects=related_objects,
                is_ioc=ip_is_ioc,
                helper=self.helper,
            )
            if domain_obj:
                self._generate_relations(
                    main_obj=domain_obj,
                    related_objects=[ip],
                    is_ioc=False,
                    helper=self.helper,
                )
            if url_obj:
                self._generate_relations(
                    main_obj=ip,
                    related_objects=[url_obj],
                    helper=self.helper,
                )
            ip.add_relationships_to_stix_objects()
            ips.append(ip)

        # IPv6 IOC observables — historically dropped on the floor because the
        # mapping only exposed ``indicators.params.ipv4``. Now ``ipv6`` from
        # the same payload block becomes a sibling ``ipv6-addr`` observable
        # with the same is_ioc semantics and relationship topology.
        for ip6_val in ipv6_vals:
            v = str(ip6_val).strip()
            if not self.is_ipv6(v):
                self.helper.connector_logger.debug(
                    f"Skip malformed IPv6 value: {ip6_val!r}"
                )
                continue
            entity_labels, _ = self._compose_observable_labels()
            ip6 = ds.IPAddress(
                name=v,
                c_type="ipv6-addr",
                tlp_color=self.tlp_color,
                labels=entity_labels,
            )
            ip6.set_description(compose_desc(base_desc))
            ip6.is_ioc = ip_is_ioc
            ip6.set_valid_from(valid_from)
            ip6.set_valid_until(valid_until)
            ip6.generate_stix_objects()
            self._generate_relations(
                main_obj=ip6,
                related_objects=related_objects,
                is_ioc=ip_is_ioc,
                helper=self.helper,
            )
            if domain_obj:
                self._generate_relations(
                    main_obj=domain_obj,
                    related_objects=[ip6],
                    is_ioc=False,
                    helper=self.helper,
                )
            if url_obj:
                self._generate_relations(
                    main_obj=ip6,
                    related_objects=[url_obj],
                    helper=self.helper,
                )
            ip6.add_relationships_to_stix_objects()
            ips.append(ip6)

        if domain_obj is not None:
            domain_obj.add_relationships_to_stix_objects()

        return domains, urls, ips

    def generate_stix_network(
        self,
        obj: dict[str, Any],
        json_date_obj: dict[str, Any] | None = None,
        related_objects: list[Any] | None = None,
        url_is_ioc: bool = False,
        domain_is_ioc: bool = False,
        ip_is_ioc: bool = False,
    ) -> tuple[list[Any], list[Any], list[Any], list[Any]]:
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for network generation"
            )
            return [], [], [], []

        base_desc = obj.get("__")

        # Build optional DDoS geo suffix + target Location SDO. The suffix
        # used to be appended into the observable's description and that was
        # it (no STIX Location, no relationship) — meaning operators saw
        # "Target country: Romania" buried in a description string but had
        # no way to pivot on it in OpenCTI. Now the country still appears
        # in the description as a fast inline hint AND becomes a real
        # ``Location`` SDO linked to every emitted observable via
        # ``related-to`` so analysts can navigate from the country page to
        # the targets and back.
        ddos_geo_suffix = ""
        ddos_target_locations: list[Any] = []
        if self.collection == "attacks/ddos":
            country_name = obj.get("ip-country-name")
            country_code = obj.get("ip-country-code")
            if country_name and country_code:
                ddos_geo_suffix = f"Target country: {country_name} ({country_code})"
            elif country_name:
                ddos_geo_suffix = f"Target country: {country_name}"
            elif country_code:
                ddos_geo_suffix = f"Target country: {country_code}"
            if country_code:
                ddos_target_locations = self.generate_locations(
                    [country_code], change_type_to="target-location"
                )

        # ``network_list`` contains multiple entries; fall back to the object
        # itself as a single-entry list so both paths use the same loop.
        entries: list[dict[str, Any]] = obj.get("network_list") or [obj]
        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        domain_objects: list[Any] = []
        url_objects: list[Any] = []
        ip_objects: list[Any] = []

        # Caller-provided `related_objects` (typically the actor anchor) plus
        # the DDoS target Locations so observables link to both.
        combined_related = list(related_objects or []) + ddos_target_locations

        for entry in entries:
            d, u, i = self._process_network_entry(
                entry,
                base_desc=base_desc,
                ddos_geo_suffix=ddos_geo_suffix,
                domain_is_ioc=domain_is_ioc,
                url_is_ioc=url_is_ioc,
                ip_is_ioc=ip_is_ioc,
                valid_from=valid_from,
                valid_until=valid_until,
                related_objects=combined_related,
            )
            domain_objects.extend(d)
            url_objects.extend(u)
            ip_objects.extend(i)

        self.helper.connector_logger.info(
            "Generated STIX network objects",
            {
                "domains": len(domain_objects),
                "urls": len(url_objects),
                "ips": len(ip_objects),
                "target_locations": len(ddos_target_locations),
            },
        )
        return domain_objects, url_objects, ip_objects, ddos_target_locations

    def generate_stix_report(
        self,
        obj: dict[str, Any],
        json_date_obj: dict[str, Any],
        report_related_objects_ids: list[str] | None,
        json_malware_report_obj: dict[str, Any],
        json_threat_actor_obj: dict[str, Any],
        json_evaluation_obj: dict[str, Any] | None = None,
    ) -> Any | None:
        self.helper.connector_logger.info("Starting generation of STIX report object")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for report generation"
            )
            return None

        _title = obj.get("title")
        _description = self.normalize_description(obj.get("description")) or _title
        _short_description = self.normalize_description(obj.get("short_description"))
        _type = "threat_report"
        _label = "threat_report"
        _id = obj.get("id")
        _report_number = obj.get("report_number")
        normalized_related_ids = [
            rid for rid in (report_related_objects_ids or []) if rid
        ]
        if not normalized_related_ids:
            title_preview = repr((_title or "")[:240])
            self.helper.connector_logger.warning(
                "Skipping STIX Report: STIX 2.1 requires non-empty object_refs; "
                f"bundle has no related object ids (collection={self.collection!r}, "
                f"report_id={_id!r}, title={title_preview})."
            )
            return None

        _date_published = json_date_obj.get("date-published")

        if _date_published:
            try:
                _published_time = datetime.strptime(_date_published, "%Y-%m-%d")
            except (TypeError, ValueError):
                _published_time = None
        else:
            _published_time = None

        _report_portal_links = self._retrieve_link(obj)
        _threat_actor_portal_links = self._retrieve_link(json_threat_actor_obj)
        _malware_portal_links = self._retrieve_link(
            json_malware_report_obj.get("malware_report_list")
        )
        report_links = (
            _report_portal_links + _threat_actor_portal_links + _malware_portal_links
        )
        self.helper.connector_logger.debug(
            f"Retrieved {len(report_links)} portal links for report"
        )

        # Collect taxonomy labels from the enriched payload (apt/threat,
        # hi/threat). Each goes through normalization + the per-collection
        # INCLUDE_*_LABELS gate so analysts can disable noisy ones.
        def _str_list(value: Any) -> list[str]:
            if not value:
                return []
            if isinstance(value, str):
                return [value.strip()] if value.strip() else []
            if isinstance(value, list):
                out = []
                for v in value:
                    if v is None:
                        continue
                    s = str(v).strip()
                    if s:
                        out.append(s)
                return out
            return []

        raw_labels = _str_list(obj.get("raw_labels"))
        is_tailored = bool(obj.get("is_tailored"))
        is_autogen = bool(obj.get("is_autogen"))

        extra_labels: list[str] = []
        extra_labels.extend(raw_labels)
        if is_tailored:
            extra_labels.append("tailored")
        if is_autogen:
            extra_labels.append("autogen")
        if self.config.get_setting_bool(
            self.collection, "include_expertise_labels", default=True
        ):
            extra_labels.extend(_str_list(obj.get("expertise")))

        ta_label = json_threat_actor_obj.get("name")
        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            threat_actor_names=[ta_label] if ta_label else [],
            context_labels=[_label, *extra_labels],
            include_nation_state=(
                self.collection in ["apt/threat", "apt/threat_actor"]
            ),
            include_cybercriminal=(self.collection in ["hi/threat", "hi/threat_actor"]),
        )
        # When store_report_labels_in_note: labels go only into a linked Note, not on the Report.
        store_labels_in_note = self._store_report_labels_in_note()
        report_labels = [] if store_labels_in_note else entity_labels
        report = ds.Report(
            name=f"{_title}",
            c_type=_type,
            published_time=_published_time,
            related_objects_ids=normalized_related_ids,
            tlp_color=self.tlp_color,
            labels=report_labels,
        )
        # Prefer the rich HTML description from the payload; fall back to the
        # title only when description is missing entirely.
        report_desc_body = _description if _description != _title else _title
        report_desc = (
            f"Report {_id}: {report_desc_body}" if _id else (report_desc_body or "")
        )
        desc_in_ext = self.config.get_setting_bool(
            self.collection,
            "description_in_external_references",
            default=False,
        )
        if desc_in_ext:
            report.set_description("")
        else:
            report.set_description(report_desc)

        # Build the external_references list. Add Group-IB report number and
        # upstream sources (e.g. onion-mirror URLs that confirm the threat)
        # as discoverable links on the Report SDO so analysts can pivot out.
        report.generate_external_references(report_links)
        if _report_number:
            report.external_references.append(
                stix2.ExternalReference(
                    source_name="Group-IB Report Number",
                    external_id=str(_report_number),
                )
            )
        for src_url in _str_list(obj.get("sources")):
            try:
                report.external_references.append(
                    stix2.ExternalReference(
                        source_name="Upstream source",
                        url=src_url,
                    )
                )
            except Exception as exc:  # noqa: BLE001
                # stix2 rejects malformed URLs (analyst loses a pivot link).
                self.helper.connector_logger.warning(
                    "Skip malformed source URL",
                    {"url": str(src_url), "exc": str(exc)},
                )
        if _short_description:
            report.external_references.append(
                stix2.ExternalReference(
                    source_name="Short description",
                    description=str(_short_description),
                )
            )
        if desc_in_ext and report_desc:
            report.external_references.append(
                stix2.ExternalReference(
                    source_name="Report description",
                    description=report_desc,
                )
            )
        if store_labels_in_note and entity_labels:
            report._labels_note_content = entity_labels
        report.generate_stix_objects()

        if json_evaluation_obj is not None:
            reliability = json_evaluation_obj.get("reliability")
            if reliability is not None:
                author = report.author
                report.author = stix2.Identity(
                    id=author.id,
                    name=author.name,
                    identity_class=author.identity_class,
                    created=author.created,
                    modified=author.modified,
                    custom_properties={"x_opencti_reliability": str(reliability)},
                    allow_custom=True,
                )

        if self.collection in _REPORT_NOTE_COLLECTIONS and _id:
            rep_note = self._finalize_stix_note(
                name=f"Threat report details: {_id}",
                content=markdown_threat_report(
                    obj=obj, json_date_obj=json_date_obj or {}
                ),
                object_refs=[report.stix_main_object.id],
                labels=entity_labels,
                portal_links=_report_portal_links or None,
                created=self._parse_iso_utc(
                    (json_date_obj or {}).get("date-published")
                ),
            )
            report.stix_objects.append(rep_note)

        self.helper.connector_logger.debug(
            f"Generated STIX report object for ID: {_id}"
        )

        self.helper.connector_logger.info("Completed generation of STIX report object")
        return report
