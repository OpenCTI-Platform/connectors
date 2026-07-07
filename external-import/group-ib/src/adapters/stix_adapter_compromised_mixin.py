from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import models as ds
from support.incident_note_markdown import (
    markdown_compromised_access,
    markdown_compromised_account_group,
    markdown_compromised_bank_card_group,
    markdown_compromised_spd,
)


class CompromisedMixin:
    def _ag_derive_names(
        self,
        account_group: dict[str, Any],
    ) -> tuple[list[str], list[str]]:
        """Return (sorted malware names, sorted threat-actor names) from the payload."""
        events_table = self._normalize_list(account_group.get("events_table"))
        malware_names = self._extract_name_list(account_group.get("malware_list"))
        ta_names = self._extract_name_list(account_group.get("threat_actor_list"))
        for row in events_table:
            if not isinstance(row, dict):
                continue
            if row.get("malware"):
                malware_names.append(row["malware"])
            if row.get("threatActor"):
                ta_names.append(row["threatActor"])
        return (
            sorted({n for n in malware_names if n}),
            sorted({n for n in ta_names if n}),
        )

    def _ag_derive_created_time(
        self,
        json_date_obj: dict[str, Any],
        events_table: list[Any],
    ) -> tuple[
        datetime | None,
        datetime | None,
        datetime | None,
        datetime | None,
        datetime | None,
    ]:
        """Return (first_seen, last_seen, first_comp, last_comp, created_time)."""

        def _p(v: Any) -> datetime | None:
            if not v:
                return None
            try:
                return None if str(v).startswith("00") else datetime.fromisoformat(v)
            except Exception:
                return None

        fs = _p(json_date_obj.get("date-first-seen"))
        ls = _p(json_date_obj.get("date-last-seen"))
        fc = _p(json_date_obj.get("date-first-compromised"))
        lc = _p(json_date_obj.get("date-last-compromised"))
        created = fs or fc or ls or lc
        if not created:
            dates = [
                _p(r.get(k))
                for r in events_table
                if isinstance(r, dict)
                for k in ("dateDetected", "dateCompromised")
            ]
            dates = [d for d in dates if d]
            if dates:
                created = min(dates)
        return fs, ls, fc, lc, created

    def _ag_build_observables(
        self,
        account_group: dict[str, Any],
        login: str | None,
        service: dict[str, Any],
        parsed_login: dict[str, Any],
        portal_links: list[Any],
        labels: list[str],
    ) -> list[Any]:
        """Build user-account + service observables (domain/url/ip/parsed_login)."""
        out: list[Any] = []

        if login:
            ua = ds.UserAccount(
                name=login,
                c_type="user-account",
                tlp_color=self._resolve_tlp_color("user-account"),
                labels=labels,
                account_login=login,
                account_type="email" if "@" in login else "username",
                display_name=login,
            )
            ua.generate_external_references(portal_links)
            ua.generate_stix_objects()
            out.append(ua)

        def _service_obs(kind: str, val: Any, cls: type, ctype: str) -> None:
            v = str(val).strip()
            if not v:
                return
            if ctype == "domain-name":
                if self.is_ipv4(v) or self.is_ipv6(v):
                    self.helper.connector_logger.info(
                        f"{self.collection}: domain field carries an IP; "
                        f"emitting as IP observable: {v!r}"
                    )
                    cls = ds.IPAddress
                    ctype = "ipv4-addr" if self.is_ipv4(v) else "ipv6-addr"
                elif not self.is_valid_domain(v):
                    self._log_skipped(kind, v)
                    return
            elif ctype == "ipv4-addr":
                if self.is_ipv6(v):
                    ctype = "ipv6-addr"
                elif not self.is_ipv4(v):
                    self._log_skipped(kind, v, "not a valid IPv4/IPv6 address")
                    return
            out.append(self._build_non_ioc_observable(cls, v, ctype, labels))

        for field, cls, ctype in (
            ("domain", ds.Domain, "domain-name"),
            ("url", ds.URL, "url"),
            ("ip", ds.IPAddress, "ipv4-addr"),
        ):
            val = service.get(field)
            if val:
                _service_obs(f"service {field}", val, cls, ctype)

        if parsed_login.get("domain"):
            _service_obs(
                "parsed_login domain",
                parsed_login["domain"],
                ds.Domain,
                "domain-name",
            )
        if parsed_login.get("ip"):
            _service_obs(
                "parsed_login ip",
                parsed_login["ip"],
                ds.IPAddress,
                "ipv4-addr",
            )

        return out

    def _ag_build_actors(
        self,
        malware_names: list[str],
        threat_actor_names: list[str],
        labels: list[str],
    ) -> list[Any]:
        """Build Malware and ThreatActor SDO wrappers."""
        out: list[Any] = []
        for name in malware_names:
            m = ds.Malware(
                name=name,
                c_type="malware",
                malware_types=[],
                tlp_color=self._resolve_tlp_color("malware"),
                labels=labels,
            )
            m.generate_stix_objects()
            out.append(m)
        for name in threat_actor_names:
            ta = ds.ThreatActor(
                name=name,
                c_type="threat-actor",
                global_label=self.ta_global_label,
                tlp_color=self._resolve_tlp_color("threat-actor"),
                labels=labels,
            )
            ta.generate_stix_objects()
            out.append(ta)
        return out

    def generate_compromised_account_group(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        account_group = event.get("account_group") or {}
        if not account_group:
            self.helper.connector_logger.warning(
                "No account_group object provided for compromised/account_group"
            )
            return []

        login = account_group.get("login") or account_group.get("name")
        password = account_group.get("password")
        parsed_login = account_group.get("parsedLogin") or {}
        service = account_group.get("service") or {}
        source_types = self._normalize_list(account_group.get("source_type"))
        events_table = self._normalize_list(account_group.get("events_table"))

        portal_links = self._retrieve_link(account_group)
        for source in self._normalize_list(account_group.get("source")):
            if not isinstance(source, dict) or not source.get("id"):
                continue
            sid = source["id"]
            stype = source.get("type") or "Source"
            sid_type = source.get("idType") or "Unknown"
            portal_links.append(
                (sid, sid, f"{stype} ({sid_type}) - external reference")
            )

        malware_names, threat_actor_names = self._ag_derive_names(account_group)
        fs, ls, fc, lc, created_time = self._ag_derive_created_time(
            json_date_obj, events_table
        )

        if not created_time:
            self.helper.connector_logger.error(
                "Missing timestamps for compromised/account_group; skipping incident creation"
            )
            return []

        labels, _ = self._compose_account_group_labels(
            malware_names=malware_names,
            threat_actor_names=threat_actor_names,
            source_types=source_types,
            include_malware_labels=self.config.get_setting_bool(
                "compromised_account_group",
                "include_malware_labels",
                default=True,
            ),
            include_threat_actor_labels=self.config.get_setting_bool(
                "compromised_account_group",
                "include_malware_threat_actor_labels",
                default=True,
            ),
            include_source_type_labels=self.config.get_setting_bool(
                "compromised_account_group",
                "include_source_type_labels",
                default=True,
            ),
        )

        incident_name = (
            login or service.get("domain") or service.get("url") or "Unknown"
        )
        incident = ds.Incident(
            name=f"Compromised account group: {incident_name}",
            c_type="incident",
            tlp_color=self._resolve_tlp_color("incident"),
            labels=labels,
            severity=self._map_severity(json_eval_obj.get("severity")),
            incident_type="data-leak",
            objective="credential-theft",
            reliability=json_eval_obj.get("reliability"),
            credibility=json_eval_obj.get("credibility"),
            admiralty_code=json_eval_obj.get("admiraltyCode"),
            first_seen=fc or fs or created_time,
            last_seen=lc or ls or created_time,
        )
        incident.set_description("")
        incident.generate_external_references(portal_links)
        incident.generate_stix_objects()

        related_objects = self._ag_build_observables(
            account_group, login, service, parsed_login, portal_links, labels
        ) + self._ag_build_actors(malware_names, threat_actor_names, labels)

        self._generate_relations(
            main_obj=incident,
            related_objects=related_objects,
            helper=self.helper,
        )
        incident.add_relationships_to_stix_objects()

        note_md = markdown_compromised_account_group(
            login=login,
            password=password,
            include_passwords=self.config.get_setting_bool(
                "compromised_account_group", "include_passwords", default=False
            ),
            service=service,
            parsed_login=parsed_login,
            date_first_seen=json_date_obj.get("date-first-seen"),
            date_last_seen=json_date_obj.get("date-last-seen"),
            date_first_compromised=json_date_obj.get("date-first-compromised"),
            date_last_compromised=json_date_obj.get("date-last-compromised"),
            events_table=events_table,
        )

        self._apply_incident_description(incident)

        note = self._finalize_stix_note(
            name="Compromised account group details",
            content=note_md,
            object_refs=[
                obj.stix_main_object.id for obj in related_objects + [incident]
            ],
            labels=labels,
            portal_links=portal_links,
        )

        return self._assemble_incident_bundle(
            related_objects, incident, note, json_eval_obj
        )

    def generate_compromised_bank_card_group(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        card_group = event.get("bank_card_group") or {}
        if not card_group:
            self.helper.connector_logger.warning(
                "No bank_card_group object provided for compromised/bank_card_group"
            )
            return []

        card_info = card_group.get("cardInfo") or {}
        card_number = card_info.get("number") or card_group.get("name") or "Unknown"
        card_type = card_info.get("type") or ""
        card_system = card_info.get("system") or ""
        card_issuer = card_info.get("issuer") or ""
        card_issuer_country = card_info.get("issuer_country") or ""

        portal_links = self._retrieve_link(card_group)
        for source in self._normalize_list(card_group.get("source")):
            if not isinstance(source, dict) or not source.get("id"):
                continue
            src_id = source["id"]
            src_type = source.get("type") or "Source"
            src_id_type = source.get("idType") or "Unknown"
            portal_links.append(
                (
                    src_id,
                    src_id,
                    f"{src_type} ({src_id_type}) - external reference",
                )
            )

        events_table = self._normalize_list(card_group.get("events_table"))
        malware_names = self._extract_name_list(card_group.get("malware_list"))
        threat_actor_names = self._extract_name_list(
            card_group.get("threat_actor_list")
        )
        for row in events_table:
            if not isinstance(row, dict):
                continue
            if row.get("malware_name"):
                malware_names.append(row["malware_name"])
            if row.get("threatActor_name"):
                threat_actor_names.append(row["threatActor_name"])
        # OpenCTI rejects entity names shorter than 2 chars (e.g. a stray "0"
        # in events_table.threatActor_name), which then orphans the relation
        # that referenced the dropped SDO. Filter them out here.
        malware_names = sorted(
            {n for n in malware_names if n and len(str(n).strip()) >= 2}
        )
        threat_actor_names = sorted(
            {n for n in threat_actor_names if n and len(str(n).strip()) >= 2}
        )

        entity_labels, _ = self._resolve_entity_labels(collection_label=self.collection)

        date_first_seen = json_date_obj.get("date-first-seen")
        date_last_seen = json_date_obj.get("date-last-seen")
        date_first_compromised = json_date_obj.get("date-first-compromised")
        date_last_compromised = json_date_obj.get("date-last-compromised")

        date_first_seen_dt = self._parse_iso_utc(date_first_seen)
        date_last_seen_dt = self._parse_iso_utc(date_last_seen)
        date_first_compromised_dt = self._parse_iso_utc(date_first_compromised)
        date_last_compromised_dt = self._parse_iso_utc(date_last_compromised)

        created_time = (
            date_first_seen_dt
            or date_first_compromised_dt
            or date_last_seen_dt
            or date_last_compromised_dt
        )
        if not created_time and events_table:
            event_dates = [
                self._parse_iso_utc(row.get(k))
                for row in events_table
                if isinstance(row, dict)
                for k in ("dateDetected", "dateCompromised")
            ]
            event_dates = [d for d in event_dates if d]
            if event_dates:
                created_time = min(event_dates)
        if not created_time:
            self.helper.connector_logger.error(
                "Missing timestamps for compromised/bank_card_group; skipping"
            )
            return []

        severity = self._map_severity(json_eval_obj.get("severity"))
        item_id = card_group.get("id") or ""
        card_category = card_info.get("category") or ""
        card_bin = card_info.get("bin") or []

        incident_name = f"Compromised bank card: {card_number}"
        if card_system:
            incident_name += f" ({card_system})"
        if item_id:
            incident_name += f" [{item_id}]"

        incident = ds.Incident(
            name=incident_name,
            c_type="incident",
            tlp_color=self._resolve_tlp_color("incident"),
            labels=entity_labels,
            severity=severity,
            incident_type="data-leak",
            objective="financial-theft",
            reliability=json_eval_obj.get("reliability"),
            credibility=json_eval_obj.get("credibility"),
            admiralty_code=json_eval_obj.get("admiraltyCode"),
            first_seen=date_first_compromised_dt or date_first_seen_dt or created_time,
            last_seen=date_last_compromised_dt or date_last_seen_dt or created_time,
        )
        incident.set_description("")
        incident.generate_external_references(portal_links)
        incident.generate_stix_objects()

        seen_values = set()
        cnc_observables = []
        for row in events_table:
            if not isinstance(row, dict):
                continue
            for field, cls, c_type in [
                ("cnc_domain", ds.Domain, "domain-name"),
                ("cnc_url", ds.URL, "url"),
            ]:
                val = row.get(field)
                if val and val not in seen_values:
                    seen_values.add(val)
                    cnc_observables.append(
                        self._build_non_ioc_observable(cls, val, c_type, entity_labels)
                    )
            cnc_ip = row.get("cnc_ipv4_ip")
            if cnc_ip and cnc_ip not in seen_values:
                seen_values.add(cnc_ip)
                ip_ctype = "ipv4-addr" if self.is_ipv4(cnc_ip) else "ipv6-addr"
                cnc_observables.append(
                    self._build_non_ioc_observable(
                        ds.IPAddress, cnc_ip, ip_ctype, entity_labels
                    )
                )

        malware_objects = []
        for name in malware_names:
            mal = ds.Malware(
                name=name,
                c_type="malware",
                malware_types=[],
                tlp_color=self._resolve_tlp_color("malware"),
                labels=entity_labels,
            )
            mal.generate_stix_objects()
            malware_objects.append(mal)

        threat_actor_objects = []
        for name in threat_actor_names:
            ta = ds.ThreatActor(
                name=name,
                c_type="threat-actor",
                global_label=self.ta_global_label,
                tlp_color=self._resolve_tlp_color("threat-actor"),
                labels=entity_labels,
            )
            ta.generate_stix_objects()
            threat_actor_objects.append(ta)

        related_objects = cnc_observables + malware_objects + threat_actor_objects
        # Emit the (full) card number as a native Payment-Card observable
        # linked to the Incident.
        if card_number and card_number != "Unknown":
            card_obs = ds.PaymentCard(
                name=str(card_number),
                tlp_color=self._resolve_tlp_color("payment-card"),
                labels=entity_labels,
            )
            card_obs.generate_stix_objects()
            related_objects.append(card_obs)
        self._generate_relations(
            main_obj=incident,
            related_objects=related_objects,
            helper=self.helper,
        )
        incident.add_relationships_to_stix_objects()

        raw_ta_list = self._normalize_list(card_group.get("threat_actor_list"))
        raw_source_list = self._normalize_list(card_group.get("source"))

        note_md = markdown_compromised_bank_card_group(
            item_id=item_id,
            card_number=card_number,
            card_type=card_type,
            card_category=card_category,
            card_system=card_system,
            card_bin=card_bin,
            card_issuer=card_issuer,
            card_issuer_country=card_issuer_country,
            date_first_seen=date_first_seen,
            date_last_seen=date_last_seen,
            date_first_compromised=date_first_compromised,
            date_last_compromised=date_last_compromised,
            raw_ta_list=raw_ta_list,
            raw_source_list=raw_source_list,
            malware_names=malware_names,
            events_table=events_table,
            flatten_cell=self._flatten_cell,
        )

        self._apply_incident_description(incident)

        note = self._finalize_stix_note(
            name="Compromised bank card group details",
            content=note_md,
            object_refs=[incident.stix_main_object.id]
            + [o.stix_main_object.id for o in related_objects],
            labels=entity_labels,
            portal_links=portal_links,
        )

        return self._assemble_incident_bundle(
            related_objects, incident, note, json_eval_obj
        )

    def generate_compromised_access(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        payload = event.get("access") or event.get("compromised_access") or {}
        if not payload:
            self.helper.connector_logger.warning(
                "No access object provided for compromised/access"
            )
            return []

        access_id = payload.get("id")
        date_detected = payload.get("dateDetected") or (json_date_obj or {}).get(
            "date-detected"
        )
        date_compromised = payload.get("dateCompromised") or (json_date_obj or {}).get(
            "date-compromised"
        )
        created_time = self._parse_iso_utc(date_compromised) or self._parse_iso_utc(
            date_detected
        )
        if not created_time:
            created_time = datetime.now(timezone.utc)

        portal_links = self._retrieve_link(payload)
        target = payload.get("target") or {}
        cnc = payload.get("cnc") or {}
        malware_obj = payload.get("malware") or {}
        source_info = payload.get("sourceInfo") or {}
        price = payload.get("price") or {}
        labels, _ = self._resolve_entity_labels(collection_label=self.collection)
        severity = self._map_severity((json_eval_obj or {}).get("severity"))

        name_part = target.get("host") or target.get("domain") or access_id or "Unknown"
        incident_name = f"Compromised access: {name_part} [{access_id or 'unknown'}]"
        incident = ds.Incident(
            name=incident_name,
            c_type="incident",
            tlp_color=self._resolve_tlp_color("incident"),
            labels=labels,
            severity=severity,
            incident_type="data-leak",
            objective="unauthorized-access",
            reliability=(json_eval_obj or {}).get("reliability"),
            credibility=(json_eval_obj or {}).get("credibility"),
            admiralty_code=(json_eval_obj or {}).get("admiraltyCode"),
            first_seen=created_time,
            last_seen=created_time,
        )
        incident.set_description("")
        incident.generate_external_references(portal_links)
        incident.generate_stix_objects()

        related_objects = []
        cnc_as_indicator = self.config.get_setting_bool(
            self.collection, "cnc_as_indicator", default=True
        )
        ttl_days = self._resolve_ttl_days(
            "compromised_access", json_date_obj, default=90
        )
        ioc_valid_from = created_time
        ioc_valid_until = created_time + timedelta(days=ttl_days)

        cnc_observables: list[Any] = []
        cnc_domain_str = (
            (cnc.get("domain") or "").strip()
            if isinstance(cnc.get("domain"), str)
            else ""
        )

        cnc_ip_values = []
        for ip_val in (cnc.get("ip"),):
            if ip_val and isinstance(ip_val, str) and ip_val.strip():
                if not self.is_ipv4(ip_val):
                    self._log_skipped("CnC ip", ip_val, "not a valid IPv4 address")
                elif ip_val not in cnc_ip_values:
                    cnc_ip_values.append(ip_val)

        cnc_domain_obs = None
        for domain_val in (cnc.get("domain"),):
            if domain_val and isinstance(domain_val, str) and domain_val.strip():
                dv = domain_val.strip()
                if self.is_ipv4(dv):
                    self.helper.connector_logger.info(
                        f"{self.collection}: domain field carries an IP; "
                        f"emitting as IP observable: {dv!r}"
                    )
                    if dv not in cnc_ip_values:
                        cnc_ip_values.append(dv)
                    continue
                if not self.is_valid_domain(dv):
                    self._log_skipped("CnC domain", dv)
                    continue
                dom = ds.Domain(
                    name=dv,
                    c_type="domain-name",
                    tlp_color=self._resolve_tlp_color("domain-name"),
                    labels=labels,
                )
                dom.is_ioc = cnc_as_indicator
                if cnc_as_indicator:
                    dom.set_valid_from(ioc_valid_from)
                    dom.set_valid_until(ioc_valid_until)
                if dv == cnc_domain_str and cnc_domain_str:
                    desc_parts = ["darkweb marketplace"]
                    if cnc_ip_values:
                        desc_parts.append(", ".join(cnc_ip_values))
                    dom.set_description(": ".join(desc_parts))
                    cnc_domain_obs = dom
                dom.generate_stix_objects()
                related_objects.append(dom)
                cnc_observables.append(dom)
        if cnc.get("url"):
            url_val = cnc.get("url") if isinstance(cnc.get("url"), str) else None
            if url_val and url_val.strip():
                u = ds.URL(
                    name=url_val.strip(),
                    c_type="url",
                    tlp_color=self._resolve_tlp_color("url"),
                    labels=labels,
                )
                u.is_ioc = cnc_as_indicator
                if cnc_as_indicator:
                    u.set_valid_from(ioc_valid_from)
                    u.set_valid_until(ioc_valid_until)
                u.generate_stix_objects()
                related_objects.append(u)
                cnc_observables.append(u)
        darkweb_domain_for_ip = cnc_domain_str
        for ip_val in cnc_ip_values:
            ip_obs = ds.IPAddress(
                name=ip_val,
                c_type="ipv4-addr",
                tlp_color=self._resolve_tlp_color("ipv4-addr"),
                labels=labels,
            )
            ip_obs.is_ioc = cnc_as_indicator
            if cnc_as_indicator:
                ip_obs.set_valid_from(ioc_valid_from)
                ip_obs.set_valid_until(ioc_valid_until)
            if darkweb_domain_for_ip:
                ip_obs.set_description(f"darkweb marketplace: {darkweb_domain_for_ip}")
            ip_obs.generate_stix_objects()
            if cnc_domain_obs:
                ip_obs.generate_relationship(
                    cnc_domain_obs.stix_main_object,
                    ip_obs.stix_main_object,
                    relation_type="resolves-to",
                )
            related_objects.append(ip_obs)
            cnc_observables.append(ip_obs)

        if self.config.get_setting_bool(
            self.collection, "target_observables", default=True
        ):
            seen_target: set[str] = set()
            for raw_val in (target.get("domain"), target.get("host")):
                val = raw_val.strip() if isinstance(raw_val, str) else ""
                if val and val not in seen_target and not self.is_valid_domain(val):
                    self._log_skipped("target host/domain", val)
                if val and val not in seen_target and self.is_valid_domain(val):
                    seen_target.add(val)
                    t_dom = ds.Domain(
                        name=val,
                        c_type="domain-name",
                        tlp_color=self._resolve_tlp_color("domain-name"),
                        labels=labels,
                    )
                    t_dom.is_ioc = False
                    t_dom.set_description("Compromised target host (Group-IB TI).")
                    t_dom.generate_stix_objects()
                    related_objects.append(t_dom)
            t_ip_raw = target.get("ip")
            t_ip = t_ip_raw.strip() if isinstance(t_ip_raw, str) else ""
            if t_ip and t_ip not in seen_target and not self.is_ipv4(t_ip):
                self._log_skipped("target ip", t_ip, "not a valid IPv4 address")
            if t_ip and t_ip not in seen_target and self.is_ipv4(t_ip):
                seen_target.add(t_ip)
                t_ip_obs = ds.IPAddress(
                    name=t_ip,
                    c_type="ipv4-addr",
                    tlp_color=self._resolve_tlp_color("ipv4-addr"),
                    labels=labels,
                )
                t_ip_obs.is_ioc = False
                t_ip_obs.set_description("Compromised target IP (Group-IB TI).")
                t_ip_obs.generate_stix_objects()
                related_objects.append(t_ip_obs)

        malware_entity = None
        mal_name = malware_obj.get("name")
        if mal_name and isinstance(mal_name, str) and mal_name.strip():
            malware_entity = ds.Malware(
                name=mal_name.strip(),
                c_type="malware",
                malware_types=malware_obj.get("category") or [],
                tlp_color=self._resolve_tlp_color("malware"),
                labels=labels,
            )
            malware_entity.is_ioc = False
            malware_entity.generate_stix_objects()
            related_objects.append(malware_entity)

        if cnc_as_indicator:
            for obs in cnc_observables:
                self._generate_relations(
                    main_obj=obs,
                    related_objects=([malware_entity] if malware_entity else []),
                    helper=self.helper,
                    is_ioc=True,
                )
        for obs in cnc_observables:
            obs.add_relationships_to_stix_objects()

        self._generate_relations(
            main_obj=incident,
            related_objects=related_objects,
            helper=self.helper,
        )
        incident.add_relationships_to_stix_objects()

        raw_preview = payload.get("rawDataPreview")
        raw_use_full = False
        raw_max_len: int | None = 2000
        if raw_preview:
            _coll = "compromised_access"
            use_full = self.config.get_collection_settings(_coll, "full_data")
            max_len = self.config.get_collection_settings(_coll, "data_preview_max_len")
            if max_len is not None and not isinstance(max_len, int):
                try:
                    max_len = int(max_len)
                except (TypeError, ValueError):
                    max_len = None
            raw_max_len = max_len
            raw_use_full = bool(
                use_full and str(use_full).lower() in ("true", "1", "yes")
            )

        access_md = markdown_compromised_access(
            access_id=access_id,
            payload=payload,
            target=target,
            cnc=cnc,
            malware_obj=malware_obj,
            source_info=source_info,
            price=price,
            raw_preview=raw_preview,
            raw_use_full=raw_use_full,
            raw_max_len=raw_max_len,
        )
        self._apply_incident_description(incident)
        note = self._finalize_stix_note(
            name="Compromised access details",
            content=access_md,
            object_refs=[incident.stix_main_object.id]
            + [o.stix_main_object.id for o in related_objects],
            labels=labels,
        )
        stix_objects = []
        for obj in related_objects + [incident]:
            stix_objects += obj.stix_objects
        stix_objects.append(note)
        stix_objects += [self.author]
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects += [self.statement_marking]
        entities = [
            o for o in stix_objects if getattr(o, "type", None) != "relationship"
        ]
        relationships = [
            o for o in stix_objects if getattr(o, "type", None) == "relationship"
        ]
        return list(entities) + list(relationships)

    def generate_compromised_spd(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        payload = event.get("spd") or event.get("compromised_spd") or {}
        if not payload:
            self.helper.connector_logger.warning(
                "No spd object provided for compromised/spd"
            )
            return []

        spd_id = payload.get("id")
        created_at = payload.get("createdAt") or (json_date_obj or {}).get(
            "date-created"
        )
        first_seen = payload.get("firstSeenAt") or (json_date_obj or {}).get(
            "date-first-seen"
        )
        last_seen = payload.get("lastSeenAt") or (json_date_obj or {}).get(
            "date-last-seen"
        )
        created_time = (
            self._parse_iso_utc(first_seen)
            or self._parse_iso_utc(last_seen)
            or self._parse_iso_utc(created_at)
        )
        if not created_time:
            created_time = datetime.now(timezone.utc)

        portal_links = self._retrieve_link(payload)
        # SPD `tags` are short hashtag-style scalars — appropriate as labels.
        spd_tags = [
            str(t).strip()
            for t in self._normalize_list(payload.get("tags"))
            if t and str(t).strip()
        ]
        labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            context_labels=spd_tags,
        )
        severity = self._map_severity((json_eval_obj or {}).get("severity"))

        ptype = payload.get("type") or "Payment data"
        incident_name = f"Suspicious payment details: {ptype} [{spd_id or 'unknown'}]"
        incident = ds.Incident(
            name=incident_name,
            c_type="incident",
            tlp_color=self._resolve_tlp_color("incident"),
            labels=labels,
            severity=severity,
            incident_type="data-leak",
            objective="credential-theft",
            reliability=(json_eval_obj or {}).get("reliability"),
            credibility=(json_eval_obj or {}).get("credibility"),
            admiralty_code=(json_eval_obj or {}).get("admiraltyCode"),
            first_seen=created_time,
            last_seen=created_time,
        )
        incident.set_description("")
        incident.generate_external_references(portal_links)
        incident.generate_stix_objects()

        value_obj = (
            payload.get("value") if isinstance(payload.get("value"), dict) else {}
        )
        events_list = self._normalize_list(payload.get("events"))
        malware_list = self._normalize_list(payload.get("malware_list"))
        ta_list = self._normalize_list(payload.get("threat_actor_list"))

        related_objects = []
        email_val = self.normalize_email(value_obj.get("email"))
        if email_val:
            email_obs = ds.Email(
                name=email_val,
                c_type="email-addr",
                tlp_color=self._resolve_tlp_color("email-addr"),
                labels=labels,
            )
            email_obs.is_ioc = False
            email_obs.generate_stix_objects()
            related_objects.append(email_obs)
        elif value_obj.get("email"):
            self.helper.connector_logger.info(
                f"compromised/spd: skip malformed email value: "
                f"{value_obj.get('email')!r}"
            )

        bank_card_val = value_obj.get("bankCard")
        if bank_card_val and isinstance(bank_card_val, str) and bank_card_val.strip():
            card_obs = ds.PaymentCard(
                name=bank_card_val.strip(),
                tlp_color=self._resolve_tlp_color("payment-card"),
                labels=labels,
            )
            card_obs.generate_stix_objects()
            related_objects.append(card_obs)

        iban_val = value_obj.get("iban")
        if iban_val and isinstance(iban_val, str) and iban_val.strip():
            iban_obs = ds.BankAccount(
                name=iban_val.strip(),
                tlp_color=self._resolve_tlp_color("bank-account"),
                labels=labels,
            )
            iban_obs.generate_stix_objects()
            related_objects.append(iban_obs)

        primary_value = value_obj.get("value")
        already = {
            v
            for v in (
                value_obj.get("email"),
                value_obj.get("bankCard"),
                value_obj.get("iban"),
            )
            if v
        }
        if (
            primary_value
            and isinstance(primary_value, str)
            and primary_value.strip()
            and primary_value.strip() not in already
        ):
            pv = primary_value.strip()
            acct_type = (
                (payload.get("type") or "payment-data")
                .strip()
                .lower()
                .replace(" ", "-")
            )
            value_account = ds.UserAccount(
                name=pv,
                c_type="user-account",
                tlp_color=self._resolve_tlp_color("user-account"),
                labels=labels,
                account_login=pv,
                account_type=acct_type,
                display_name=f"{payload.get('type') or 'Value'}: {pv}",
            )
            value_account.generate_external_references(portal_links)
            value_account.generate_stix_objects()
            related_objects.append(value_account)

        # Country of the compromised value -> Location SDO.
        country_codes = [c for c in self._normalize_list(payload.get("country")) if c]
        if country_codes:
            related_objects += list(self.generate_locations(country_codes))

        if related_objects:
            self._generate_relations(
                main_obj=incident,
                related_objects=related_objects,
                helper=self.helper,
            )
            incident.add_relationships_to_stix_objects()

        ptype_str = payload.get("type") or "—"
        value_str = value_obj.get("value") or "—"
        spd_md = markdown_compromised_spd(
            spd_id=spd_id,
            payload=payload,
            value_obj=value_obj,
            ptype_str=ptype_str,
            value_str=value_str,
            events_list=events_list,
            malware_list=malware_list,
            ta_list=ta_list,
        )
        self._apply_incident_description(incident)
        note = self._finalize_stix_note(
            name="Suspicious payment details",
            content=spd_md,
            object_refs=[incident.stix_main_object.id]
            + [o.stix_main_object.id for o in related_objects],
            labels=labels,
        )
        stix_objects = []
        for obj in related_objects + [incident]:
            stix_objects += obj.stix_objects
        stix_objects.append(note)
        stix_objects += [self.author]
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects += [self.statement_marking]
        entities = [
            o for o in stix_objects if getattr(o, "type", None) != "relationship"
        ]
        relationships = [
            o for o in stix_objects if getattr(o, "type", None) == "relationship"
        ]
        return list(entities) + list(relationships)
