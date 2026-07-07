from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import models as ds
import stix2
from support.incident_note_markdown import (
    markdown_attacks_ddos,
    markdown_attacks_deface,
    markdown_attacks_phishing_group,
    markdown_attacks_phishing_kit,
    markdown_compromised_masked_card,
    markdown_darkweb_forums,
    markdown_malware_cnc,
)
from support.note_markdown import MarkdownNote
from support.portal_external_refs import chat_portal_link_row


class StixAdapterSpecialMixin:
    def generate_stix_yara(
        self,
        obj: dict[str, Any],
        json_date_obj: dict[str, Any] | None = None,
        related_objects: list[Any] | None = None,
        yara_is_ioc: bool = True,
    ) -> Any | None:
        self.helper.connector_logger.info("Starting generation of STIX YARA object")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for YARA generation"
            )
            return None

        _yara = obj.get("yara")
        _context = obj.get("context")
        _type = "yara"
        _label = "yara"

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _date_created = self._retrieve_date(json_date_obj, "date-created")
        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            context_labels=[_label],
        )

        yara = ds.Indicator(
            name=_yara,
            c_type=_type,
            context=_context,
            created=_date_created,
            tlp_color=self.tlp_color,
            labels=entity_labels,
        )
        yara.is_ioc = yara_is_ioc
        yara.set_valid_from(valid_from)
        yara.set_valid_until(valid_until)
        yara.generate_stix_objects()
        self.helper.connector_logger.debug("Generated STIX YARA object")

        self._generate_relations(
            main_obj=yara,
            related_objects=related_objects,
            is_ioc=yara_is_ioc,
            helper=self.helper,
        )
        self.helper.connector_logger.debug("Generated relations for YARA object")

        yara.add_relationships_to_stix_objects()
        self.helper.connector_logger.debug("Added relationships to STIX YARA object")

        self.helper.connector_logger.info("Completed generation of STIX YARA object")
        return yara

    def generate_stix_suricata(
        self,
        obj: dict[str, Any],
        json_date_obj: dict[str, Any] | None = None,
        related_objects: list[Any] | None = None,
        suricata_is_ioc: bool = True,
    ) -> Any | None:
        self.helper.connector_logger.info("Starting generation of STIX Suricata object")
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for Suricata generation"
            )
            return None

        _suricata = obj.get("signature")
        _context = obj.get("context")
        _type = "suricata"
        _label = "suricata"

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _date_created = self._retrieve_date(json_date_obj, "date-created")
        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            context_labels=[_label],
        )

        suricata = ds.Indicator(
            name=_suricata,
            c_type=_type,
            context=_context,
            created=_date_created,
            tlp_color=self.tlp_color,
            labels=entity_labels,
        )
        suricata.is_ioc = suricata_is_ioc
        suricata.set_valid_from(valid_from)
        suricata.set_valid_until(valid_until)
        suricata.generate_stix_objects()
        self.helper.connector_logger.debug("Generated STIX Suricata object")

        self._generate_relations(
            main_obj=suricata,
            related_objects=related_objects,
            is_ioc=suricata_is_ioc,
            helper=self.helper,
        )
        self.helper.connector_logger.debug("Generated relations for Suricata object")

        suricata.add_relationships_to_stix_objects()
        self.helper.connector_logger.debug(
            "Added relationships to STIX Suricata object"
        )

        self.helper.connector_logger.info(
            "Completed generation of STIX Suricata object"
        )
        return suricata

    def generate_stix_ungrouped(
        self,
        obj: dict[str, Any],
        json_date_obj: dict[str, Any] | None = None,
        related_objects: list[Any] | None = None,
        email_is_ioc: bool = True,
    ) -> list[Any] | None:
        self.helper.connector_logger.info(
            "Starting generation of STIX ungrouped (email) objects"
        )
        if not obj:
            self.helper.connector_logger.warning(
                "No object provided for ungrouped generation"
            )
            return None

        _emails = obj.get("emails") or []
        _type = "email-addr"

        valid_from, valid_until = self._retrieve_ttl_dates(json_date_obj)

        _stix_objects = list()
        _seen: set[str] = set()
        _skipped_invalid = 0
        _skipped_duplicate = 0

        for _raw in _emails:
            _email = self.normalize_email(_raw)
            if _email is None:
                _skipped_invalid += 1
                self._log_skipped("email", _raw)
                continue
            if _email in _seen:
                _skipped_duplicate += 1
                continue
            _seen.add(_email)

            self.helper.connector_logger.debug(f"Processing email: {_email}")
            entity_labels, _ = self._compose_observable_labels()
            email = ds.Email(
                name=_email,
                c_type=_type,
                tlp_color=self.tlp_color,
                labels=entity_labels,
            )
            email.is_ioc = email_is_ioc
            email.set_valid_from(valid_from)
            email.set_valid_until(valid_until)
            email.generate_stix_objects()

            self._generate_relations(
                main_obj=email,
                related_objects=related_objects,
                is_ioc=email_is_ioc,
                helper=self.helper,
            )

            email.add_relationships_to_stix_objects()

            _stix_objects.append(email)

        if _skipped_invalid or _skipped_duplicate:
            self.helper.connector_logger.info(
                f"Email observables: emitted={len(_stix_objects)}, "
                f"skipped_invalid={_skipped_invalid}, "
                f"skipped_duplicate={_skipped_duplicate}"
            )

        self.helper.connector_logger.info(
            f"Generated {len(_stix_objects)} STIX email objects"
        )
        return _stix_objects

    def generate_malware_cnc(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        payload = event.get("malware_cnc") or {}
        if not payload:
            self.helper.connector_logger.warning(
                "No malware_cnc object provided for malware/cnc"
            )
            return []

        cnc_id = payload.get("id") or ""
        cnc_value = (
            (payload.get("cnc") or "").strip()
            if isinstance(payload.get("cnc"), str)
            else ""
        )
        domain_value = (
            (payload.get("domain") or "").strip()
            if isinstance(payload.get("domain"), str)
            else ""
        )
        url_value = (
            (payload.get("url") or "").strip()
            if isinstance(payload.get("url"), str)
            else ""
        )
        ipv4_rows = self._normalize_list(payload.get("ipv4_list"))
        ipv6_rows = self._normalize_list(payload.get("ipv6_list"))
        file_obj = payload.get("file") if isinstance(payload.get("file"), dict) else {}
        date_first = (json_date_obj or {}).get("date-first-seen")
        date_last = (json_date_obj or {}).get("date-last-seen")
        date_detected = (json_date_obj or {}).get("date-detected")
        valid_from = (
            self._parse_iso_utc(date_first)
            or self._parse_iso_utc(date_detected)
            or datetime.now(timezone.utc)
        )
        valid_until_explicit = self._parse_iso_utc(date_last)
        ttl_days = self._resolve_ttl_days("malware_cnc", json_date_obj, default=90)
        valid_until = (
            valid_until_explicit
            if valid_until_explicit and valid_until_explicit > valid_from
            else (valid_from + timedelta(days=ttl_days))
        )

        portal_links = self._retrieve_link(payload)

        malware_rows = [
            m
            for m in self._normalize_list(payload.get("malware_list"))
            if isinstance(m, dict) and m.get("name")
        ]
        threat_actor_rows = [
            t
            for t in self._normalize_list(payload.get("threat_actor_list"))
            if isinstance(t, dict) and t.get("name")
        ]

        malware_names = sorted({m["name"] for m in malware_rows})
        threat_actor_names = sorted({t["name"] for t in threat_actor_rows})

        include_malware = self.config.get_setting_bool(
            self.collection, "include_malware_labels", default=True
        )
        include_threat_actor = self.config.get_setting_bool(
            self.collection, "include_threat_actor_labels", default=True
        )

        # platform is shown in the Note (no `platform:` label).
        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            malware_names=malware_names if include_malware else [],
            threat_actor_names=(threat_actor_names if include_threat_actor else []),
        )

        related_objects: list[Any] = []

        malware_objects: list[Any] = []
        for name in malware_names:
            mal = ds.Malware(
                name=name,
                c_type="malware",
                malware_types=[],
                tlp_color=self._resolve_tlp_color("malware"),
                labels=entity_labels,
            )
            mal.is_ioc = False
            mal.generate_stix_objects()
            malware_objects.append(mal)
            related_objects.append(mal)

        use_intrusion = bool(
            self.config.get_extra_settings_by_name(
                "intrusion_set_instead_of_threat_actor"
            )
        )
        threat_actor_objects: list[Any] = []
        for row in threat_actor_rows:
            name = row["name"]
            if name in {m.name for m in malware_objects}:
                continue
            if use_intrusion:
                ta = ds.IntrusionSet(
                    name=name,
                    c_type="intrusion-set",
                    global_label=self.ta_global_label,
                    tlp_color=self._resolve_tlp_color("intrusion-set"),
                    labels=entity_labels,
                )
            else:
                ta = ds.ThreatActor(
                    name=name,
                    c_type="threat-actor",
                    global_label=self.ta_global_label,
                    tlp_color=self._resolve_tlp_color("threat-actor"),
                    labels=entity_labels,
                )
            ta.is_ioc = False
            ta.generate_stix_objects()
            threat_actor_objects.append(ta)
            related_objects.append(ta)

        all_ioc = self.config.get_setting_bool(
            self.collection, "all_observables_as_indicators", default=True
        )
        primary, secondaries = self._build_cnc_observable_set(
            cnc_value=cnc_value,
            domain_value=domain_value,
            url_value=url_value,
            ipv4_rows=ipv4_rows,
            ipv6_rows=ipv6_rows,
            file_obj=file_obj,
            labels=entity_labels,
            valid_from=valid_from,
            valid_until=valid_until,
            all_ioc=all_ioc,
        )
        if (
            primary is None
            and not secondaries
            and not malware_objects
            and not threat_actor_objects
        ):
            self.helper.connector_logger.warning(
                f"malware/cnc[{cnc_id}]: no observables nor SDOs to emit; skipping"
            )
            return []

        # primary becomes IoC; secondaries are non-IoC SCOs related to the Indicator.
        if primary is not None:
            primary.generate_external_references(portal_links)
            primary.generate_stix_objects()
            self._generate_relations(
                main_obj=primary,
                related_objects=secondaries + malware_objects + threat_actor_objects,
                helper=self.helper,
                is_ioc=True,
            )
            for ta in threat_actor_objects:
                for mal in malware_objects:
                    primary.generate_relationship(
                        ta.stix_main_object,
                        mal.stix_main_object,
                        relation_type="uses",
                    )
            primary.add_relationships_to_stix_objects()
            secondary_domain = next(
                (o for o in secondaries if o.c_type == "domain-name"), None
            )
            if secondary_domain is not None:
                ip_wrappers = [
                    o
                    for o in ([primary] + secondaries)
                    if o is not None and o.c_type in ("ipv4-addr", "ipv6-addr")
                ]
                for ip_w in ip_wrappers:
                    secondary_domain.generate_relationship(
                        secondary_domain.stix_main_object,
                        ip_w.stix_main_object,
                        relation_type="resolves-to",
                    )
            if all_ioc:
                for sec in secondaries:
                    self._generate_relations(
                        main_obj=sec,
                        related_objects=(malware_objects + threat_actor_objects),
                        helper=self.helper,
                        is_ioc=True,
                    )
                    sec.add_relationships_to_stix_objects()
            elif secondary_domain is not None:
                secondary_domain.add_relationships_to_stix_objects()
        elif malware_objects and threat_actor_objects:
            anchor = malware_objects[0]
            for ta in threat_actor_objects:
                for mal in malware_objects:
                    anchor.generate_relationship(
                        ta.stix_main_object,
                        mal.stix_main_object,
                        relation_type="uses",
                    )
            anchor.add_relationships_to_stix_objects()

        stix_objects: list[Any] = []
        for sec in secondaries:
            stix_objects += sec.stix_objects
        for sdo in malware_objects + threat_actor_objects:
            stix_objects += sdo.stix_objects
        if primary is not None:
            stix_objects += primary.stix_objects

        note_refs: list[str] = []
        if primary is not None:
            note_refs.append(primary.stix_main_object.id)
        note_refs += [o.stix_main_object.id for o in secondaries]
        note_refs += [
            o.stix_main_object.id for o in (malware_objects + threat_actor_objects)
        ]
        if note_refs:
            cnc_note = self._finalize_stix_note(
                name=f"Malware CnC: {cnc_value or domain_value or cnc_id or 'unknown'}",
                content=markdown_malware_cnc(
                    payload=payload, json_date_obj=json_date_obj or {}
                ),
                object_refs=note_refs,
                labels=entity_labels,
                portal_links=portal_links or None,
            )
            stix_objects.append(cnc_note)

        author_identity = self.author
        reliability = (json_eval_obj or {}).get("reliability")
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
        if primary is not None:
            stix_objects.append(primary.tlp)
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects.append(self.statement_marking)

        entities = [
            o for o in stix_objects if getattr(o, "type", None) != "relationship"
        ]
        relationships = [
            o for o in stix_objects if getattr(o, "type", None) == "relationship"
        ]
        return list(entities) + list(relationships)

    def _build_cnc_observable_set(
        self,
        cnc_value: str,
        domain_value: str,
        url_value: str,
        ipv4_rows: list[Any],
        ipv6_rows: list[Any],
        file_obj: dict[str, Any],
        labels: list[str],
        valid_from: datetime,
        valid_until: datetime,
        all_ioc: bool = False,
    ) -> tuple[Any | None, list[Any]]:
        seen_values: set[str] = set()

        def _setup_ioc_state(obj: Any, is_primary: bool) -> None:
            obj.is_ioc = is_primary or all_ioc
            if obj.is_ioc:
                obj.set_valid_from(valid_from)
                obj.set_valid_until(valid_until)
            if not is_primary:
                obj.generate_stix_objects()

        def _make_domain(value: Any, is_primary: bool) -> Any | None:
            if not value or value in seen_values:
                return None
            if self.is_ipv4(value) or self.is_ipv6(value):
                self.helper.connector_logger.info(
                    f"{self.collection}: domain field carries an IP; "
                    f"emitting as IP observable: {value!r}"
                )
                return _make_ip(value, is_primary)
            if not self.is_valid_domain(value):
                self._log_skipped("CnC domain", value)
                return None
            seen_values.add(value)
            obj = ds.Domain(
                name=value,
                c_type="domain-name",
                tlp_color=self._resolve_tlp_color("domain-name"),
                labels=labels,
            )
            _setup_ioc_state(obj, is_primary)
            return obj

        def _make_url(value: Any, is_primary: bool) -> Any | None:
            if not value or value in seen_values:
                return None
            seen_values.add(value)
            obj = ds.URL(
                name=value,
                c_type="url",
                tlp_color=self._resolve_tlp_color("url"),
                labels=labels,
            )
            _setup_ioc_state(obj, is_primary)
            return obj

        def _make_ip(value: Any, is_primary: bool) -> Any | None:
            if not value or value in seen_values:
                return None
            if self.is_ipv4(value):
                ctype = "ipv4-addr"
            elif self.is_ipv6(value):
                ctype = "ipv6-addr"
            else:
                self._log_skipped("CnC ip", value, "not a valid IPv4/IPv6 address")
                return None
            seen_values.add(value)
            obj = ds.IPAddress(
                name=value,
                c_type=ctype,
                tlp_color=self._resolve_tlp_color(ctype),
                labels=labels,
            )
            _setup_ioc_state(obj, is_primary)
            return obj

        def _make_file(file_dict: dict[str, Any], is_primary: bool) -> Any | None:
            if not isinstance(file_dict, dict):
                return None
            hashes = []
            for key, htype in (
                ("sha256", "SHA256"),
                ("sha1", "SHA1"),
                ("md5", "MD5"),
            ):
                val = file_dict.get(key)
                if not val or not isinstance(val, str):
                    continue
                if not self._valid_hash(val.strip(), htype):
                    self._log_skipped(
                        f"CnC file {key}", val, f"not a valid {htype} hash"
                    )
                    continue
                h = val.strip()
                if h not in seen_values:
                    seen_values.add(h)
                    hashes.append(h)
            if not hashes:
                return None
            obj = ds.FileHash(
                name=hashes,
                c_type="file",
                tlp_color=self._resolve_tlp_color("file"),
                labels=labels,
            )
            _setup_ioc_state(obj, is_primary)
            return obj

        # If `cnc` looks like an IP, treat it as IP candidate; else as domain candidate.
        cnc_is_ip = bool(cnc_value) and (
            self.is_ipv4(cnc_value) or self.is_ipv6(cnc_value)
        )

        primary: Any | None = None

        # Priority order: file > domain > url > first ipv4 > first ipv6
        primary = _make_file(file_obj, is_primary=True)

        if primary is None:
            chosen_domain = domain_value or (cnc_value if not cnc_is_ip else "")
            primary = _make_domain(chosen_domain, is_primary=True)

        if primary is None:
            primary = _make_url(url_value, is_primary=True)

        if primary is None:
            ipv4_first = next(
                (
                    row.get("ip")
                    for row in ipv4_rows
                    if isinstance(row, dict) and row.get("ip")
                ),
                cnc_value if cnc_is_ip and self.is_ipv4(cnc_value) else None,
            )
            primary = _make_ip(ipv4_first, is_primary=True)

        if primary is None:
            ipv6_first = next(
                (
                    row.get("ip")
                    for row in ipv6_rows
                    if isinstance(row, dict) and row.get("ip")
                ),
                cnc_value if cnc_is_ip and self.is_ipv6(cnc_value) else None,
            )
            primary = _make_ip(ipv6_first, is_primary=True)

        secondaries: list[Any] = []

        # If we picked file as primary, also publish domain/url/IPs as secondaries for context.
        # In all cases publish the rest of values that didn't make it to primary.
        for value in (domain_value, cnc_value if not cnc_is_ip else ""):
            obj = _make_domain(value, is_primary=False)
            if obj is not None:
                secondaries.append(obj)

        obj = _make_url(url_value, is_primary=False)
        if obj is not None:
            secondaries.append(obj)

        for row in ipv4_rows:
            if not isinstance(row, dict):
                continue
            obj = _make_ip(row.get("ip"), is_primary=False)
            if obj is not None:
                secondaries.append(obj)

        if cnc_is_ip and self.is_ipv4(cnc_value):
            obj = _make_ip(cnc_value, is_primary=False)
            if obj is not None:
                secondaries.append(obj)

        for row in ipv6_rows:
            if not isinstance(row, dict):
                continue
            obj = _make_ip(row.get("ip"), is_primary=False)
            if obj is not None:
                secondaries.append(obj)

        if cnc_is_ip and self.is_ipv6(cnc_value):
            obj = _make_ip(cnc_value, is_primary=False)
            if obj is not None:
                secondaries.append(obj)

        # If file wasn't primary, still emit it as secondary if hashes are present.
        if primary is None or primary.c_type != "file":
            obj = _make_file(file_obj, is_primary=False)
            if obj is not None:
                secondaries.append(obj)

        return primary, secondaries

    def _mc_build_cnc_observables(
        self,
        cnc_domain: str,
        cnc_url: str,
        cnc_ip: str,
        cnc_ipv6: str,
        cnc_country_code: str,
        client_ip: str,
        entity_labels: list[str],
        ioc_on_red: bool,
        valid_from_obs: Any,
        valid_until_obs: Any,
    ) -> list[Any]:
        """Build CnC + client-IP observable wrappers with ioc/non-ioc branching."""
        out: list[Any] = []
        seen: set[str] = set()

        def _ioc_obs(cls: type, val: str, ctype: str) -> Any:
            obs = cls(
                name=val,
                c_type=ctype,
                tlp_color=self._resolve_tlp_color(ctype),
                labels=entity_labels,
            )
            obs.is_ioc = True
            obs.set_valid_from(valid_from_obs)
            obs.set_valid_until(valid_until_obs)
            return obs

        if cnc_domain and cnc_domain not in seen:
            if self.is_ipv4(cnc_domain) or self.is_ipv6(cnc_domain):
                self.helper.connector_logger.info(
                    f"{self.collection}: domain field carries an IP; "
                    f"emitting as IP observable: {cnc_domain!r}"
                )
                seen.add(cnc_domain)
                ip_ctype = "ipv4-addr" if self.is_ipv4(cnc_domain) else "ipv6-addr"
                if ioc_on_red:
                    dom_ip = _ioc_obs(ds.IPAddress, cnc_domain, ip_ctype)
                    dom_ip.generate_stix_objects()
                    out.append(dom_ip)
                else:
                    out.append(
                        self._build_non_ioc_observable(
                            ds.IPAddress, cnc_domain, ip_ctype, entity_labels
                        )
                    )
            elif not self.is_valid_domain(cnc_domain):
                self._log_skipped("CnC domain", cnc_domain)
            else:
                seen.add(cnc_domain)
                if ioc_on_red:
                    dom = _ioc_obs(ds.Domain, cnc_domain, "domain-name")
                    dom.generate_stix_objects()
                    out.append(dom)
                else:
                    out.append(
                        self._build_non_ioc_observable(
                            ds.Domain, cnc_domain, "domain-name", entity_labels
                        )
                    )

        if cnc_url and cnc_url not in seen:
            seen.add(cnc_url)
            if ioc_on_red:
                url = _ioc_obs(ds.URL, cnc_url, "url")
                url.generate_stix_objects()
                out.append(url)
            else:
                out.append(
                    self._build_non_ioc_observable(
                        ds.URL, cnc_url, "url", entity_labels
                    )
                )

        if cnc_ip and cnc_ip not in seen and not self.is_ipv4(cnc_ip):
            self._log_skipped("CnC ip", cnc_ip, "not a valid IPv4 address")
        if cnc_ip and cnc_ip not in seen and self.is_ipv4(cnc_ip):
            seen.add(cnc_ip)
            if ioc_on_red:
                ipobj = _ioc_obs(ds.IPAddress, cnc_ip, "ipv4-addr")
                if cnc_country_code:
                    ipobj.set_description(f"CnC IP, country: {cnc_country_code}")
                ipobj.generate_stix_objects()
                out.append(ipobj)
            else:
                ipobj = self._build_non_ioc_observable(
                    ds.IPAddress, cnc_ip, "ipv4-addr", entity_labels
                )
                if cnc_country_code:
                    ipobj.set_description(f"CnC IP, country: {cnc_country_code}")
                out.append(ipobj)

        if cnc_ipv6 and cnc_ipv6 not in seen and not self.is_ipv6(cnc_ipv6):
            self._log_skipped("CnC ipv6", cnc_ipv6, "not a valid IPv6 address")
        if cnc_ipv6 and cnc_ipv6 not in seen and self.is_ipv6(cnc_ipv6):
            seen.add(cnc_ipv6)
            if ioc_on_red:
                ip6obj = _ioc_obs(ds.IPAddress, cnc_ipv6, "ipv6-addr")
                if cnc_country_code:
                    ip6obj.set_description(f"CnC IPv6, country: {cnc_country_code}")
                ip6obj.generate_stix_objects()
                out.append(ip6obj)
            else:
                out.append(
                    self._build_non_ioc_observable(
                        ds.IPAddress, cnc_ipv6, "ipv6-addr", entity_labels
                    )
                )

        if client_ip and client_ip not in seen and not self.is_ipv4(client_ip):
            self._log_skipped("client ip", client_ip, "not a valid IPv4 address")
        if client_ip and client_ip not in seen and self.is_ipv4(client_ip):
            seen.add(client_ip)
            out.append(
                self._build_non_ioc_observable(
                    ds.IPAddress, client_ip, "ipv4-addr", entity_labels
                )
            )

        return out

    def _mc_build_actors(
        self,
        threat_actor_rows: list[dict[str, Any]],
        mal_name: str | None,
        entity_labels: list[str],
    ) -> list[Any]:
        """Build Malware + ThreatActor/IntrusionSet wrappers for masked_card."""
        out: list[Any] = []
        use_intrusion = self.config.get_extra_settings_bool(
            "intrusion_set_instead_of_threat_actor"
        )
        if mal_name:
            mal = ds.Malware(
                name=mal_name,
                c_type="malware",
                malware_types=[],
                tlp_color=self._resolve_tlp_color("malware"),
                labels=entity_labels,
            )
            mal.is_ioc = False
            mal.generate_stix_objects()
            out.append(mal)

        malware_name_set = {mal_name} if mal_name else set()
        for row in threat_actor_rows:
            ta_name = row.get("name")
            if not ta_name or ta_name in malware_name_set:
                continue
            ta_cls, ta_ctype = (
                (ds.IntrusionSet, "intrusion-set")
                if use_intrusion
                else (ds.ThreatActor, "threat-actor")
            )
            ta = ta_cls(
                name=ta_name,
                c_type=ta_ctype,
                global_label=self.ta_global_label,
                tlp_color=self._resolve_tlp_color(ta_ctype),
                labels=entity_labels,
            )
            ta.is_ioc = False
            ta.generate_stix_objects()
            out.append(ta)

        return out

    def generate_compromised_masked_card(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        masked_card = event.get("masked_card") or {}
        if not masked_card:
            self.helper.connector_logger.warning(
                "No masked_card object provided for compromised/masked_card"
            )
            return []

        card_info = masked_card.get("cardInfo") or {}
        card_number = card_info.get("number") or masked_card.get("name") or "Unknown"
        card_system = card_info.get("system") or ""
        card_type = card_info.get("type") or ""
        card_issuer = card_info.get("issuer") or ""
        card_issuer_country_code = card_info.get("issuer_country_code") or ""
        card_issuer_country_name = card_info.get("issuer_country_name") or ""
        card_bins = self._normalize_list(card_info.get("bin"))
        card_cvv = card_info.get("cvv")
        card_pin = card_info.get("pin")
        card_dump = card_info.get("dump")

        def _str_field(obj: Any, key: str) -> str:
            v = (obj or {}).get(key)
            return (v or "").strip() if isinstance(v, str) else ""

        cnc_obj = masked_card.get("cnc") or {}
        cnc_domain = _str_field(cnc_obj, "domain")
        cnc_url = _str_field(cnc_obj, "url")
        cnc_ip = _str_field(cnc_obj, "ip")
        cnc_ipv6 = _str_field(cnc_obj, "ipv6")
        cnc_country_code = cnc_obj.get("country_code") or ""
        client_ip = _str_field(masked_card, "client_ipv4_ip")

        malware_obj = masked_card.get("malware") or {}
        mal_name: str | None = (
            malware_obj.get("name") if isinstance(malware_obj, dict) else None
        )
        threat_actor_rows = [
            t
            for t in self._normalize_list(masked_card.get("threat_actor_list"))
            if isinstance(t, dict) and t.get("name")
        ]
        if not threat_actor_rows:
            single_ta = masked_card.get("threat_actor")
            if isinstance(single_ta, list):
                threat_actor_rows = [
                    t for t in single_ta if isinstance(t, dict) and t.get("name")
                ]
            elif isinstance(single_ta, dict) and single_ta.get("name"):
                threat_actor_rows = [single_ta]

        owner_obj = masked_card.get("owner") or {}
        source_type = masked_card.get("source_type") or ""
        source_link = masked_card.get("source_link") or ""
        item_id = masked_card.get("id") or ""

        date_detected = (json_date_obj or {}).get("date-detected")
        date_compromised = (json_date_obj or {}).get("date-compromised")
        first_seen_dt = self._parse_iso_utc(date_compromised) or self._parse_iso_utc(
            date_detected
        )
        last_seen_dt = self._parse_iso_utc(date_detected) or self._parse_iso_utc(
            date_compromised
        )
        created_time = first_seen_dt or last_seen_dt
        if not created_time:
            self.helper.connector_logger.error(
                "compromised/masked_card: missing timestamps; skipping",
                {"item_id": item_id},
            )
            return []

        portal_links = self._retrieve_link(masked_card)
        if source_link and isinstance(source_link, str) and source_link.strip():
            portal_links.append(
                (source_link, source_link, "Compromised masked card source")
            )

        threat_actor_names = sorted({t["name"] for t in threat_actor_rows})
        malware_names = [mal_name] if mal_name else []
        source_types = [source_type] if source_type else []

        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            malware_names=(
                malware_names
                if self.config.get_setting_bool(
                    self.collection, "include_malware_labels", True
                )
                else []
            ),
            threat_actor_names=(
                list(threat_actor_names)
                if self.config.get_setting_bool(
                    self.collection, "include_threat_actor_labels", True
                )
                else []
            ),
            source_types=(
                source_types
                if self.config.get_setting_bool(
                    self.collection, "include_source_type_labels", True
                )
                else []
            ),
        )

        incident_name = f"Compromised masked card: {card_number}"
        if card_system:
            incident_name += f" ({card_system})"
        if item_id:
            incident_name += f" [{item_id}]"

        incident = ds.Incident(
            name=incident_name,
            c_type="incident",
            tlp_color=self._resolve_tlp_color("incident"),
            labels=entity_labels,
            severity=self._map_severity((json_eval_obj or {}).get("severity")),
            incident_type="data-leak",
            objective="financial-theft",
            reliability=(json_eval_obj or {}).get("reliability"),
            credibility=(json_eval_obj or {}).get("credibility"),
            admiralty_code=(json_eval_obj or {}).get("admiraltyCode"),
            first_seen=first_seen_dt or created_time,
            last_seen=last_seen_dt or created_time,
        )
        incident.set_description("")
        incident.generate_external_references(portal_links)
        incident.generate_stix_objects()

        eval_tlp = str((json_eval_obj or {}).get("tlp") or self.tlp_color or "").lower()
        ioc_on_red = "red" in eval_tlp
        ttl_days = self._resolve_ttl_days(
            "compromised_masked_card", json_date_obj, default=90
        )
        valid_from_obs = first_seen_dt or created_time
        valid_until_obs = last_seen_dt or created_time
        if valid_until_obs <= valid_from_obs:
            valid_until_obs = valid_from_obs + timedelta(days=ttl_days)

        related_objects: list[Any] = self._mc_build_cnc_observables(
            cnc_domain,
            cnc_url,
            cnc_ip,
            cnc_ipv6,
            cnc_country_code,
            client_ip,
            entity_labels,
            ioc_on_red,
            valid_from_obs,
            valid_until_obs,
        ) + self._mc_build_actors(threat_actor_rows, mal_name, entity_labels)

        location_codes = [
            cc for cc in (card_issuer_country_code, cnc_country_code) if cc
        ]
        location_codes = list(
            dict.fromkeys(location_codes)
        )  # deduplicate, preserve order
        related_objects += list(
            self.generate_locations(location_codes) if location_codes else []
        )

        # Emit the card number as a native Payment-Card observable linked to
        # the Incident (queryable / correlatable in OpenCTI).
        if card_number and card_number != "Unknown":
            card_obs = ds.PaymentCard(
                name=str(card_number),
                tlp_color=self._resolve_tlp_color("payment-card"),
                labels=entity_labels,
                expiration_date=(
                    card_info.get("validThruDate") or card_info.get("validThru")
                ),
                cvv=card_cvv,
                holder_name=owner_obj.get("name"),
            )
            card_obs.generate_stix_objects()
            related_objects.append(card_obs)

        if related_objects:
            self._generate_relations(
                main_obj=incident,
                related_objects=related_objects,
                helper=self.helper,
            )
            incident.add_relationships_to_stix_objects()

        masked_md = markdown_compromised_masked_card(
            item_id=item_id,
            masked_card=masked_card,
            card_number=card_number,
            card_bins=card_bins,
            card_system=card_system,
            card_type=card_type,
            card_issuer=card_issuer,
            card_issuer_country_name=card_issuer_country_name,
            card_issuer_country_code=card_issuer_country_code,
            card_info=card_info,
            card_cvv=card_cvv,
            card_pin=card_pin,
            card_dump=card_dump,
            cnc_domain=cnc_domain,
            cnc_url=cnc_url,
            cnc_ip=cnc_ip,
            cnc_ipv6=cnc_ipv6,
            cnc_country_code=cnc_country_code,
            ioc_domain_on_red=bool(cnc_domain) and ioc_on_red,
            ioc_url_on_red=bool(cnc_url) and ioc_on_red,
            ioc_ipv4_on_red=bool(cnc_ip) and ioc_on_red and self.is_ipv4(cnc_ip),
            eval_tlp=eval_tlp,
            mal_name=mal_name,
            malware_obj=malware_obj if isinstance(malware_obj, dict) else {},
            threat_actor_names=list(threat_actor_names),
            source_type=source_type,
            source_link=source_link,
            owner_obj=owner_obj,
            date_detected=date_detected,
            date_compromised=date_compromised,
        )

        self._apply_incident_description(incident)

        note = self._finalize_stix_note(
            name="Compromised masked card details",
            content=masked_md,
            object_refs=[incident.stix_main_object.id]
            + [o.stix_main_object.id for o in related_objects],
            labels=entity_labels,
            portal_links=portal_links,
        )

        return self._assemble_incident_bundle(
            related_objects, incident, note, json_eval_obj or {}
        )

    def _parse_message_ts(self, raw: Any) -> datetime | None:
        if raw is None:
            return None
        if isinstance(raw, datetime):
            if raw.tzinfo is None:
                return raw.replace(tzinfo=timezone.utc)
            return raw
        if isinstance(raw, (int, float)):
            try:
                return datetime.fromtimestamp(float(raw), tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                return None
        if isinstance(raw, str):
            stripped = raw.strip()
            if not stripped:
                return None
            parsed = self._parse_iso_utc(stripped)
            if parsed is not None:
                return parsed
            try:
                return datetime.fromtimestamp(float(stripped), tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                return None
        return None

    def _build_chat_message_bundle(
        self,
        platform: str,
        chat_message: dict[str, Any],
        channel_obj: dict[str, Any],
        author_obj: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
        portal_links_extra: list[tuple[str, str, str]] | None = None,
    ) -> list[Any]:
        if not chat_message:
            self.helper.connector_logger.warning(
                f"{self.collection}: empty chat_message; skipping"
            )
            return []

        msg_id = chat_message.get("id") or ""
        msg_text = chat_message.get("text") or ""
        msg_translation = chat_message.get("translation") or ""
        msg_ts = chat_message.get("ts")
        rules_raw = chat_message.get("rules")

        chan_id = channel_obj.get("id") if channel_obj else None
        chan_name = channel_obj.get("name") if channel_obj else None
        chan_title = channel_obj.get("title") if channel_obj else None  # telegram only
        chan_type = (channel_obj.get("type") or "").lower() if channel_obj else ""
        chan_server = channel_obj.get("server") if channel_obj else None  # discord only

        chan_display = (
            chan_title
            or chan_name
            or (f"{chan_server} / {chan_id}" if chan_server else None)
            or (str(chan_id) if chan_id is not None else f"unknown-{platform}-channel")
        )

        a_id = author_obj.get("id") if author_obj else None
        a_username = (
            author_obj.get("username") or author_obj.get("name") if author_obj else None
        )  # telegram=userName, discord=name
        a_first = author_obj.get("first_name") if author_obj else None
        a_last = author_obj.get("last_name") if author_obj else None
        a_disc = author_obj.get("discriminator") if author_obj else None  # discord only

        if a_id is None and not a_username:
            self.helper.connector_logger.warning(
                f"{self.collection}[{msg_id}]: author has no id/username; skipping author SCO"
            )

        account_login = str(a_id) if a_id is not None else (a_username or "")
        display_name_parts = [
            p
            for p in (
                a_username,
                a_first,
                a_last,
                f"#{a_disc}" if a_disc else None,
            )
            if p
        ]
        display_name = (
            " ".join(display_name_parts)
            if display_name_parts
            else (account_login or "unknown-author")
        )

        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
        )
        msg_portal_links = list(portal_links_extra or [])
        chat_portal_row = chat_portal_link_row(platform, chan_id, msg_id)
        if chat_portal_row:
            msg_portal_links.append(chat_portal_row)

        author_account = None
        if account_login:
            account_type = platform  # "discord" | "telegram"
            ua = ds.UserAccount(
                name=account_login,
                c_type="user-account",
                tlp_color=self._resolve_tlp_color("user-account"),
                labels=entity_labels,
                account_login=account_login,
                account_type=account_type,
                display_name=display_name,
            )
            if msg_portal_links:
                ua.generate_external_references(msg_portal_links)
            ua.generate_stix_objects()
            author_account = ua

        redact = self.config.get_setting_bool(
            self.collection, "redact_message_text", default=False
        )
        include_translation = self.config.get_setting_bool(
            self.collection, "include_translation_in_note", default=True
        )

        preview_key = self.collection.replace("/", "_")
        nb = MarkdownNote()
        nb.raw(f"## {platform.capitalize()} message [{msg_id or 'no-id'}]")
        nb.kv("Timestamp", msg_ts).kv(
            "Channel", f"{chan_display} (type={chan_type or '—'})"
        ).kv("Author", f"{display_name} (id={account_login or '—'})")
        # Surface the channel-level metadata that previously sat on the
        # channel Identity SDO. Keeps it accessible without polluting
        # Entities / Organizations with one Identity per channel.
        if channel_obj:
            nb.kv("Channel server", channel_obj.get("server"))
            nb.kv("Channel id", chan_id)
            nb.kv("Channel title", channel_obj.get("title"))
            nb.kv("First message", channel_obj.get("first_message_date"))
            nb.kv("Last message", channel_obj.get("last_message_date"))
            nb.kv("Messages", channel_obj.get("message_num"))
            nb.kv("Users", channel_obj.get("user_num"))
        if rules_raw:
            rules_list = self._normalize_list(rules_raw)
            nb.kv(
                "Hunting rules",
                ", ".join(str(r) for r in rules_list) if rules_list else None,
            )
        if redact:
            nb.gap().raw("> Message body redacted by `redact_message_text=true`.")
        else:
            if msg_text:
                nb.h2("Body").raw(self._get_text_preview(preview_key, msg_text))
            if include_translation and msg_translation:
                nb.h2("Translation").raw(
                    self._get_text_preview(preview_key, msg_translation)
                )
        note_content = nb.build()
        # Note must reference at least one entity (Note id is derived from
        # name + first object_ref). Prefer the User-Account author; fall
        # back to the Group-IB connector identity when there is no author.
        note_object_refs: list[str] = []
        if author_account is not None:
            note_object_refs.append(author_account.stix_main_object.id)
        else:
            note_object_refs.append(self.author.id)

        note_external_refs = msg_portal_links

        # Build a unique-per-message Note name so multiple messages with same body don't dedup-collide.
        note_name = f"{platform}-message:{msg_id or msg_ts or 'unknown'}"
        note_created = self._parse_message_ts(msg_ts)
        note = self._finalize_stix_note(
            name=note_name,
            content=note_content,
            object_refs=note_object_refs,
            labels=entity_labels,
            portal_links=note_external_refs or None,
            created=note_created,
            modified=note_created,
        )

        stix_objects: list[Any] = []
        if author_account is not None:
            stix_objects += author_account.stix_objects
        stix_objects.append(note)

        author_identity = self.author
        reliability = (json_eval_obj or {}).get("reliability")
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
        # Append the actual MarkingDefinition object, not the color string.
        stix_objects.append(self._tlp_marking_for("note"))
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects.append(self.statement_marking)

        entities = [
            o for o in stix_objects if getattr(o, "type", None) != "relationship"
        ]
        relationships = [
            o for o in stix_objects if getattr(o, "type", None) == "relationship"
        ]
        return list(entities) + list(relationships)

    def generate_darkweb_forums(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        post = event.get("forum_post") or event.get("threat_report") or {}
        if not post:
            self.helper.connector_logger.warning(
                "No forum_post object provided for darkweb/forums"
            )
            return []

        post_id = post.get("id") or ""
        topic = post.get("title")
        nickname = (post.get("nickname") or "").strip()
        forum = post.get("forum")
        categories = self._normalize_list(post.get("categories"))
        langs = self._normalize_list(post.get("langs"))
        forum_url = post.get("sources")

        context_labels = [str(forum)] if forum else []
        labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            context_labels=context_labels,
        )

        created = self._parse_iso_utc(
            (json_date_obj or {}).get("date-published")
        ) or self._parse_iso_utc((json_date_obj or {}).get("date-created"))

        portal_links = self._retrieve_link(post)
        if forum_url and isinstance(forum_url, str) and forum_url.strip():
            portal_links.append((None, forum_url.strip(), "Original forum post"))

        related: list[Any] = []
        author_account = None
        if nickname:
            ua = ds.UserAccount(
                name=nickname,
                c_type="user-account",
                tlp_color=self._resolve_tlp_color("user-account"),
                labels=labels,
                account_login=nickname,
                account_type="forum",
                display_name=f"{nickname} @ {forum}" if forum else nickname,
            )
            # Surface the portal/forum links on the author observable too.
            ua.generate_external_references(portal_links)
            ua.generate_stix_objects()
            author_account = ua
            related.append(ua)

        note_md = markdown_darkweb_forums(
            post=post,
            json_date_obj=json_date_obj or {},
            categories=categories,
            langs=langs,
            forum_url=forum_url,
        )
        note_refs = (
            [author_account.stix_main_object.id] if author_account else [self.author.id]
        )
        note = self._finalize_stix_note(
            name=f"Darkweb post: {topic or post_id or 'unknown'}",
            content=note_md,
            object_refs=note_refs,
            labels=labels,
            portal_links=portal_links or None,
            created=created,
            modified=created,
        )

        stix_objects: list[Any] = []
        for o in related:
            stix_objects += o.stix_objects
        stix_objects.append(note)

        author_identity = self.author
        reliability = (json_eval_obj or {}).get("reliability")
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
        stix_objects.append(self._tlp_marking_for("note"))
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects.append(self.statement_marking)

        entities = [
            o for o in stix_objects if getattr(o, "type", None) != "relationship"
        ]
        relationships = [
            o for o in stix_objects if getattr(o, "type", None) == "relationship"
        ]
        return list(entities) + list(relationships)

    def _emit_attack_observable(
        self,
        cls: type,
        value: Any,
        ctype: str,
        labels: list[str],
        *,
        is_ioc: bool,
        valid_from: Any,
        valid_until: Any,
        portal_links: list[Any] | None,
        seen: set[str],
    ) -> Any | None:
        if not isinstance(value, str):
            return None
        v = value.strip()
        if not v or v in seen:
            return None
        if ctype == "ip":
            if self.is_ipv4(v):
                ctype = "ipv4-addr"
            elif self.is_ipv6(v):
                ctype = "ipv6-addr"
            else:
                self._log_skipped("ip", v, "not a valid IPv4/IPv6 address")
                return None
        elif ctype == "domain-name":
            # Upstream domain fields regularly carry bare IP addresses;
            # OpenCTI rejects those as Domain-Name, so emit them as IPs.
            if self.is_ipv4(v) or self.is_ipv6(v):
                ctype = "ipv4-addr" if self.is_ipv4(v) else "ipv6-addr"
                cls = ds.IPAddress
                self.helper.connector_logger.info(
                    f"{self.collection}: domain field carries an IP; "
                    f"emitting as {ctype}: {v!r}"
                )
            elif not self.is_valid_domain(v):
                self._log_skipped("domain", v)
                return None
        elif ctype == "url":
            if not self.is_valid_url(v):
                self._log_skipped("url", v)
                return None
        seen.add(v)
        obj = cls(
            name=v,
            c_type=ctype,
            tlp_color=self._resolve_tlp_color(ctype),
            labels=labels,
        )
        obj.is_ioc = is_ioc
        if portal_links:
            obj.generate_external_references(portal_links)
        if is_ioc:
            obj.set_valid_from(valid_from)
            obj.set_valid_until(valid_until)
        obj.generate_stix_objects()
        return obj

    def _finalize_attack_bundle(
        self,
        related_all: list[Any],
        note: Any,
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        stix_objects: list[Any] = []
        for o in related_all:
            stix_objects += o.stix_objects
        stix_objects.append(note)

        author_identity = self.author
        reliability = (json_eval_obj or {}).get("reliability")
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
        return list(entities) + list(relationships)

    def _attack_actor_sdo(self, ta: dict[str, Any], labels: list[str]) -> Any | None:
        name = (ta or {}).get("name")
        if not name:
            return None
        use_intrusion = self.config.get_extra_settings_bool(
            "intrusion_set_instead_of_threat_actor"
        )
        ta_cls, ta_ctype = (
            (ds.IntrusionSet, "intrusion-set")
            if use_intrusion
            else (ds.ThreatActor, "threat-actor")
        )
        actor = ta_cls(
            name=name,
            c_type=ta_ctype,
            global_label=self.ta_global_label,
            tlp_color=self._resolve_tlp_color(ta_ctype),
            labels=labels,
        )
        actor.is_ioc = False
        actor.generate_stix_objects()
        return actor

    def generate_attacks_deface(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        payload = event.get("deface") or {}
        if not payload:
            self.helper.connector_logger.warning(
                "No deface object provided for attacks/deface"
            )
            return []

        deface_id = payload.get("id") or ""
        target = payload.get("target_ip") or {}
        ta = payload.get("threat_actor") or {}
        labels, _ = self._resolve_entity_labels(collection_label=self.collection)
        portal_links = self._retrieve_link(payload)

        seen: set[str] = set()
        related: list[Any] = []
        obs_by_ctype: dict[str, Any] = {}
        for cls, val, ctype in (
            (ds.Domain, payload.get("target_domain"), "domain-name"),
            (ds.URL, payload.get("site_url") or payload.get("url"), "url"),
            (ds.IPAddress, target.get("ip"), "ip"),
        ):
            obs = self._emit_attack_observable(
                cls,
                val,
                ctype,
                labels,
                is_ioc=False,
                valid_from=None,
                valid_until=None,
                portal_links=portal_links,
                seen=seen,
            )
            if obs is not None:
                related.append(obs)
                obs_by_ctype[ctype] = obs

        observable_objs = list(related)

        domain_obs = obs_by_ctype.get("domain-name")
        ip_obs = obs_by_ctype.get("ip")
        if (
            domain_obs is not None
            and ip_obs is not None
            and domain_obs.c_type == "domain-name"
        ):
            domain_obs.generate_relationship(
                domain_obs.stix_main_object,
                ip_obs.stix_main_object,
                relation_type="resolves-to",
            )

        actor = self._attack_actor_sdo(ta, labels)
        if actor is not None:
            related.append(actor)
            for obs in observable_objs:
                self._generate_relations(
                    main_obj=obs,
                    related_objects=[actor],
                    helper=self.helper,
                )
                obs.add_relationships_to_stix_objects()
        elif domain_obs is not None:
            domain_obs.add_relationships_to_stix_objects()

        cc = target.get("country_code")
        if cc:
            related += list(self.generate_locations([cc]))

        if not related:
            self.helper.connector_logger.warning(
                f"attacks/deface[{deface_id}]: nothing to emit; skipping"
            )
            return []

        if self.config.get_setting_bool(
            self.collection, "create_incident", default=True
        ):
            detected = (
                self._parse_iso_utc((json_date_obj or {}).get("detection-date"))
                or self._parse_iso_utc((json_date_obj or {}).get("date-created"))
                or datetime.now(timezone.utc)
            )
            incident = ds.Incident(
                name=(
                    f"Website defacement: "
                    f"{payload.get('target_domain') or deface_id or 'unknown'}"
                    f" [{deface_id or 'unknown'}]"
                ),
                c_type="incident",
                tlp_color=self._resolve_tlp_color("incident"),
                labels=labels,
                severity=self._map_severity((json_eval_obj or {}).get("severity")),
                incident_type="defacement",
                reliability=(json_eval_obj or {}).get("reliability"),
                credibility=(json_eval_obj or {}).get("credibility"),
                admiralty_code=(json_eval_obj or {}).get("admiraltyCode"),
                first_seen=detected,
                last_seen=detected,
            )
            incident.set_description("")
            incident.generate_external_references(portal_links)
            incident.generate_stix_objects()
            self._generate_relations(
                main_obj=incident,
                related_objects=related,
                helper=self.helper,
            )
            self._apply_incident_description(incident)
            related = [incident] + related

        note = self._finalize_stix_note(
            name=f"Website defacement: {payload.get('target_domain') or deface_id or 'unknown'}",
            content=markdown_attacks_deface(
                payload=payload, json_date_obj=json_date_obj or {}
            ),
            object_refs=[o.stix_main_object.id for o in related],
            labels=labels,
            portal_links=portal_links or None,
        )
        return self._finalize_attack_bundle(related, note, json_eval_obj or {})

    def generate_attacks_phishing_group(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        payload = event.get("phishing_group") or {}
        if not payload:
            self.helper.connector_logger.warning(
                "No phishing_group object provided for attacks/phishing_group"
            )
            return []

        pg_id = payload.get("id") or ""
        ta = payload.get("threat_actor") or {}
        brand = (
            str(payload.get("brand") or "").strip()
            if not isinstance(payload.get("brand"), (list, dict))
            else ""
        )
        brand_labels = (
            [brand]
            if brand
            and self.config.get_setting_bool(
                self.collection, "include_brand_labels", default=True
            )
            else []
        )
        labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            context_labels=brand_labels,
        )
        portal_links = self._retrieve_link(payload)

        valid_from = self._parse_iso_utc(
            (json_date_obj or {}).get("submission-time")
        ) or datetime.now(timezone.utc)
        ttl_days = self._resolve_ttl_days(
            "attacks_phishing_group", json_date_obj, default=30
        )
        valid_until = self._parse_iso_utc((json_date_obj or {}).get("takedown-time"))
        if not valid_until or valid_until <= valid_from:
            valid_until = valid_from + timedelta(days=ttl_days)

        seen: set[str] = set()
        related: list[Any] = []

        obs = self._emit_attack_observable(
            ds.Domain,
            payload.get("domain"),
            "domain-name",
            labels,
            is_ioc=True,
            valid_from=valid_from,
            valid_until=valid_until,
            portal_links=portal_links,
            seen=seen,
        )
        if obs is not None:
            related.append(obs)

        for row in payload.get("phishing_list") or []:
            if not isinstance(row, dict):
                continue
            row_obs_by_ctype: dict[str, Any] = {}
            for cls, val, ctype, ioc in (
                (ds.URL, row.get("url"), "url", True),
                (ds.Domain, row.get("domain"), "domain-name", True),
                (ds.IPAddress, row.get("ip"), "ip", False),
            ):
                obs = self._emit_attack_observable(
                    cls,
                    val,
                    ctype,
                    labels,
                    is_ioc=ioc,
                    valid_from=valid_from,
                    valid_until=valid_until,
                    portal_links=portal_links,
                    seen=seen,
                )
                if obs is not None:
                    related.append(obs)
                    row_obs_by_ctype[ctype] = obs

            row_domain = row_obs_by_ctype.get("domain-name")
            row_ip = row_obs_by_ctype.get("ip")
            if (
                row_domain is not None
                and row_ip is not None
                and row_domain.c_type == "domain-name"
            ):
                row_domain.generate_relationship(
                    row_domain.stix_main_object,
                    row_ip.stix_main_object,
                    relation_type="resolves-to",
                )
                row_domain.add_relationships_to_stix_objects()

        # Hosting IPs (non-IoC — often shared infrastructure).
        for row in payload.get("ip_list") or []:
            if not isinstance(row, dict):
                continue
            obs = self._emit_attack_observable(
                ds.IPAddress,
                row.get("ip"),
                "ip",
                labels,
                is_ioc=False,
                valid_from=valid_from,
                valid_until=valid_until,
                portal_links=portal_links,
                seen=seen,
            )
            if obs is not None:
                related.append(obs)

        observable_objs = list(related)
        actor = self._attack_actor_sdo(ta, labels)
        if actor is not None:
            related.append(actor)

        if brand and self.config.get_setting_bool(
            self.collection, "brand_as_identity", default=True
        ):
            brand_ident = ds.Identity(
                name=brand,
                c_type="identity",
                identity_class="organization",
                tlp_color=self._resolve_tlp_color("identity"),
                labels=labels,
            )
            brand_ident.set_description("Brand impersonated in phishing (Group-IB TI).")
            brand_ident.generate_external_references(portal_links)
            brand_ident.generate_stix_objects()
            for obs in observable_objs:
                brand_ident.generate_relationship(
                    obs.stix_main_object,
                    brand_ident.stix_main_object,
                    relation_type="related-to",
                )
            if actor is not None:
                brand_ident.generate_relationship(
                    actor.stix_main_object,
                    brand_ident.stix_main_object,
                    relation_type="targets",
                )
            brand_ident.add_relationships_to_stix_objects()
            related.append(brand_ident)

        country_codes = list(
            dict.fromkeys(
                cc
                for row in (payload.get("ip_list") or [])
                if isinstance(row, dict)
                for cc in [row.get("country_code")]
                if cc
            )
        )
        if country_codes:
            related += list(self.generate_locations(country_codes))

        if not related:
            self.helper.connector_logger.warning(
                f"attacks/phishing_group[{pg_id}]: nothing to emit; skipping"
            )
            return []

        note = self._finalize_stix_note(
            name=f"Phishing group: {payload.get('brand') or payload.get('domain') or pg_id or 'unknown'}",
            content=markdown_attacks_phishing_group(
                payload=payload, json_date_obj=json_date_obj or {}
            ),
            object_refs=[o.stix_main_object.id for o in related],
            labels=labels,
            portal_links=portal_links or None,
        )
        return self._finalize_attack_bundle(related, note, json_eval_obj or {})

    def generate_attacks_phishing_kit(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        payload = event.get("phishing_kit") or {}
        if not payload:
            self.helper.connector_logger.warning(
                "No phishing_kit object provided for attacks/phishing_kit"
            )
            return []

        kit_id = payload.get("id") or ""
        target_brands = list(
            dict.fromkeys(
                str(b).strip()
                for b in self._normalize_list(payload.get("target_brand"))
                if str(b).strip()
            )
        )
        brand_labels = (
            list(target_brands[:10])
            if self.config.get_setting_bool(
                self.collection, "include_brand_labels", default=True
            )
            else []
        )
        labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            context_labels=brand_labels,
        )
        portal_links = self._retrieve_link(payload)

        valid_from = (
            self._parse_iso_utc((json_date_obj or {}).get("first-seen"))
            or self._parse_iso_utc((json_date_obj or {}).get("detection-date"))
            or datetime.now(timezone.utc)
        )
        ttl_days = self._resolve_ttl_days(
            "attacks_phishing_kit", json_date_obj, default=30
        )
        valid_until = self._parse_iso_utc((json_date_obj or {}).get("last-seen"))
        if not valid_until or valid_until <= valid_from:
            valid_until = valid_from + timedelta(days=ttl_days)

        seen: set[str] = set()
        related: list[Any] = []

        # Kit file hash — IoC.
        kit_hash = payload.get("hash")
        if (
            isinstance(kit_hash, str)
            and kit_hash.strip()
            and not (
                self._valid_hash(kit_hash.strip(), "SHA256")
                or self._valid_hash(kit_hash.strip(), "SHA1")
                or self._valid_hash(kit_hash.strip(), "MD5")
            )
        ):
            self._log_skipped(
                "kit hash", kit_hash, "not a valid MD5/SHA-1/SHA-256 hash"
            )
        if (
            isinstance(kit_hash, str)
            and kit_hash.strip()
            and (
                self._valid_hash(kit_hash.strip(), "SHA256")
                or self._valid_hash(kit_hash.strip(), "SHA1")
                or self._valid_hash(kit_hash.strip(), "MD5")
            )
        ):
            fh = ds.FileHash(
                name=[kit_hash.strip()],
                c_type="file",
                tlp_color=self._resolve_tlp_color("file"),
                labels=labels,
            )
            fh.is_ioc = True
            fh.generate_external_references(portal_links)
            fh.set_valid_from(valid_from)
            fh.set_valid_until(valid_until)
            fh.generate_stix_objects()
            related.append(fh)
            seen.add(kit_hash.strip())

        # Drop emails — IoC (where stolen data is exfiltrated to).
        for raw in payload.get("emails") or []:
            email = self.normalize_email(raw)
            if email is None and raw:
                self._log_skipped("drop email", raw)
            if not email or email in seen:
                continue
            seen.add(email)
            em = ds.Email(
                name=email,
                c_type="email-addr",
                tlp_color=self._resolve_tlp_color("email-addr"),
                labels=labels,
            )
            em.is_ioc = True
            em.generate_external_references(portal_links)
            em.set_valid_from(valid_from)
            em.set_valid_until(valid_until)
            em.generate_stix_objects()
            related.append(em)

        # Where the kit was hosted/downloaded from.
        for row in payload.get("downloaded_from") or []:
            if not isinstance(row, dict):
                continue
            for cls, val, ctype in (
                (ds.URL, row.get("url"), "url"),
                (ds.Domain, row.get("domain"), "domain-name"),
            ):
                obs = self._emit_attack_observable(
                    cls,
                    val,
                    ctype,
                    labels,
                    is_ioc=True,
                    valid_from=valid_from,
                    valid_until=valid_until,
                    portal_links=portal_links,
                    seen=seen,
                )
                if obs is not None:
                    related.append(obs)

        if target_brands and self.config.get_setting_bool(
            self.collection, "brand_as_identity", default=True
        ):
            observable_objs = list(related)
            for brand_name in target_brands:
                brand_ident = ds.Identity(
                    name=brand_name,
                    c_type="identity",
                    identity_class="organization",
                    tlp_color=self._resolve_tlp_color("identity"),
                    labels=labels,
                )
                brand_ident.set_description(
                    "Brand targeted by phishing kit (Group-IB TI)."
                )
                brand_ident.generate_external_references(portal_links)
                brand_ident.generate_stix_objects()
                for obs in observable_objs:
                    brand_ident.generate_relationship(
                        obs.stix_main_object,
                        brand_ident.stix_main_object,
                        relation_type="related-to",
                    )
                brand_ident.add_relationships_to_stix_objects()
                related.append(brand_ident)

        if not related:
            self.helper.connector_logger.warning(
                f"attacks/phishing_kit[{kit_id}]: nothing to emit; skipping"
            )
            return []

        note = self._finalize_stix_note(
            name=f"Phishing kit: {payload.get('hash') or kit_id or 'unknown'}",
            content=markdown_attacks_phishing_kit(
                payload=payload, json_date_obj=json_date_obj or {}
            ),
            object_refs=[o.stix_main_object.id for o in related],
            labels=labels,
            portal_links=portal_links or None,
        )
        return self._finalize_attack_bundle(related, note, json_eval_obj or {})

    def generate_attacks_ddos(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        payload = event.get("ddos") or {}
        if not payload:
            self.helper.connector_logger.warning(
                "No ddos object provided for attacks/ddos"
            )
            return []

        ddos_id = payload.get("id") or ""
        target = payload.get("target") or {}
        cnc = payload.get("cnc") or {}
        malware = payload.get("malware") or {}
        ta = payload.get("threat_actor") or {}

        labels, _ = self._resolve_entity_labels(collection_label=self.collection)

        portal_links = self._retrieve_link(payload)

        cnc_as_indicator = self.config.get_setting_bool(
            self.collection, "cnc_as_indicator", default=True
        )
        valid_from = (
            self._parse_iso_utc((json_date_obj or {}).get("date-first-seen"))
            or self._parse_iso_utc((json_date_obj or {}).get("detection-date"))
            or datetime.now(timezone.utc)
        )
        ttl_days = self._resolve_ttl_days("attacks_ddos", json_date_obj, default=30)
        valid_until = self._parse_iso_utc((json_date_obj or {}).get("date-last-seen"))
        if not valid_until or valid_until <= valid_from:
            valid_until = valid_from + timedelta(days=ttl_days)

        observables: list[Any] = []
        seen: set[str] = set()
        by_side: dict[str, dict[str, Any]] = {"target": {}, "cnc": {}}
        for side, cls, val, ctype, is_cnc in (
            # Target (victim) infrastructure — never an IoC.
            ("target", ds.IPAddress, target.get("ip"), "ip", False),
            ("target", ds.Domain, target.get("domain"), "domain-name", False),
            ("target", ds.URL, target.get("url"), "url", False),
            # CnC (attacker) infrastructure — IoC by default.
            ("cnc", ds.Domain, cnc.get("domain"), "domain-name", True),
            ("cnc", ds.URL, cnc.get("url"), "url", True),
            ("cnc", ds.IPAddress, cnc.get("ip"), "ip", True),
        ):
            obs = self._emit_attack_observable(
                cls,
                val,
                ctype,
                labels,
                is_ioc=is_cnc and cnc_as_indicator,
                valid_from=valid_from,
                valid_until=valid_until,
                portal_links=portal_links,
                seen=seen,
            )
            if obs is not None:
                observables.append(obs)
                by_side[side][ctype] = obs

        for side_obs in by_side.values():
            side_domain = side_obs.get("domain-name")
            side_ip = side_obs.get("ip")
            if (
                side_domain is not None
                and side_ip is not None
                and side_domain.c_type == "domain-name"
            ):
                side_domain.generate_relationship(
                    side_domain.stix_main_object,
                    side_ip.stix_main_object,
                    relation_type="resolves-to",
                )

        sdo_objects: list[Any] = []
        if malware.get("name"):
            mal = ds.Malware(
                name=malware["name"],
                c_type="malware",
                malware_types=[],
                tlp_color=self._resolve_tlp_color("malware"),
                labels=labels,
            )
            mal.is_ioc = False
            mal.generate_stix_objects()
            sdo_objects.append(mal)
        if ta.get("name"):
            use_intrusion = self.config.get_extra_settings_bool(
                "intrusion_set_instead_of_threat_actor"
            )
            ta_cls, ta_ctype = (
                (ds.IntrusionSet, "intrusion-set")
                if use_intrusion
                else (ds.ThreatActor, "threat-actor")
            )
            tao = ta_cls(
                name=ta["name"],
                c_type=ta_ctype,
                global_label=self.ta_global_label,
                tlp_color=self._resolve_tlp_color(ta_ctype),
                labels=labels,
            )
            tao.is_ioc = False
            tao.generate_stix_objects()
            sdo_objects.append(tao)

        country_codes = [
            c for c in (target.get("country_code"), cnc.get("country_code")) if c
        ]
        country_codes = list(dict.fromkeys(country_codes))
        location_objects = (
            list(self.generate_locations(country_codes)) if country_codes else []
        )

        related_all = observables + sdo_objects + location_objects
        if not related_all:
            self.helper.connector_logger.warning(
                f"attacks/ddos[{ddos_id}]: no observables/SDOs to emit; skipping"
            )
            return []

        if len(sdo_objects) == 2 and malware.get("name") and ta.get("name"):
            mal_obj, ta_obj = sdo_objects[0], sdo_objects[1]
            ta_obj.generate_relationship(
                ta_obj.stix_main_object,
                mal_obj.stix_main_object,
                relation_type="uses",
            )
            ta_obj.add_relationships_to_stix_objects()

        for obs in observables:
            if obs.is_ioc or sdo_objects:
                self._generate_relations(
                    main_obj=obs,
                    related_objects=sdo_objects,
                    helper=self.helper,
                    is_ioc=obs.is_ioc,
                )
            if obs.stix_relationships:
                obs.add_relationships_to_stix_objects()

        if self.config.get_setting_bool(
            self.collection, "create_incident", default=True
        ):
            target_part = (
                target.get("domain")
                or target.get("url")
                or target.get("ip")
                or "unknown"
            )
            incident = ds.Incident(
                name=f"DDoS attack: {target_part} [{ddos_id or 'unknown'}]",
                c_type="incident",
                tlp_color=self._resolve_tlp_color("incident"),
                labels=labels,
                severity=self._map_severity((json_eval_obj or {}).get("severity")),
                incident_type="ddos",
                reliability=(json_eval_obj or {}).get("reliability"),
                credibility=(json_eval_obj or {}).get("credibility"),
                admiralty_code=(json_eval_obj or {}).get("admiraltyCode"),
                first_seen=valid_from,
                last_seen=(
                    self._parse_iso_utc((json_date_obj or {}).get("date-last-seen"))
                    or valid_from
                ),
            )
            incident.set_description("")
            incident.generate_external_references(portal_links)
            incident.generate_stix_objects()
            self._generate_relations(
                main_obj=incident,
                related_objects=related_all,
                helper=self.helper,
            )
            self._apply_incident_description(incident)
            related_all = [incident] + related_all

        note_md = markdown_attacks_ddos(
            payload=payload, json_date_obj=json_date_obj or {}
        )
        note_refs = [o.stix_main_object.id for o in related_all]
        note = self._finalize_stix_note(
            name=f"DDoS attack: {ddos_id or 'unknown'}",
            content=note_md,
            object_refs=note_refs,
            labels=labels,
            portal_links=portal_links or None,
        )

        stix_objects: list[Any] = []
        for o in related_all:
            stix_objects += o.stix_objects
        stix_objects.append(note)

        author_identity = self.author
        reliability = (json_eval_obj or {}).get("reliability")
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
        return list(entities) + list(relationships)

    def generate_compromised_discord(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        chat_message = event.get("chat_message") or {}
        channel_obj = event.get("channel") or {}
        author_obj = event.get("author") or {}
        return self._build_chat_message_bundle(
            platform="discord",
            chat_message=chat_message,
            channel_obj=channel_obj,
            author_obj=author_obj,
            json_date_obj=json_date_obj,
            json_eval_obj=json_eval_obj or {},
        )

    def generate_compromised_messenger(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        chat_message = event.get("chat_message") or {}
        channel_obj = event.get("channel") or {}
        author_obj = event.get("author") or {}
        return self._build_chat_message_bundle(
            platform="telegram",
            chat_message=chat_message,
            channel_obj=channel_obj,
            author_obj=author_obj,
            json_date_obj=json_date_obj,
            json_eval_obj=json_eval_obj or {},
        )
