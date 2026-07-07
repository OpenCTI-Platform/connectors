from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import models as ds
import stix2
from ciaops.collections_meta.ti import TICollections
from support.incident_note_markdown import (
    markdown_hi_open_threats,
    markdown_ioc_note,
    markdown_osi_git_repository,
    markdown_osi_public_leak,
    markdown_osi_vulnerability,
)


class OsiHiMixin:
    def generate_osi_public_leak(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        payload = event.get("public_leak") or {}
        if not payload:
            self.helper.connector_logger.warning(
                "No public_leak object provided for osi/public_leak"
            )
            return []

        def _parse_iso(raw_value: Any) -> datetime | None:
            if not raw_value:
                return None
            try:
                if str(raw_value).startswith("00"):
                    return None
                return datetime.fromisoformat(str(raw_value).replace("Z", "+00:00"))
            except Exception:
                return None

        leak_id = payload.get("id")
        leak_hash = payload.get("hash") or payload.get("name")
        created_raw = payload.get("created") or (json_date_obj or {}).get(
            "date-created"
        )
        created_time = _parse_iso(created_raw)
        if not created_time:
            created_time = datetime.now(timezone.utc)
        elif getattr(created_time, "tzinfo", None) is None:
            created_time = created_time.replace(tzinfo=timezone.utc)
        portal_links = self._retrieve_link(payload)
        labels, _ = self._resolve_entity_labels(collection_label=self.collection)

        severity = self._map_severity((json_eval_obj or {}).get("severity"))

        incident_name = (
            f"Public leak: {leak_hash or leak_id or 'Unknown'} [{leak_id or 'unknown'}]"
        )
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

        related_objects = []
        if leak_hash:
            hash_type = None
            if len(str(leak_hash)) == 64:
                hash_type = "SHA-256"
            elif len(str(leak_hash)) == 40:
                hash_type = "SHA-1"
            elif len(str(leak_hash)) == 32:
                hash_type = "MD5"
            if hash_type and self._valid_hash(leak_hash, hash_type):
                file_obs = ds.FileHash(
                    name=[leak_hash],
                    c_type="file",
                    tlp_color=self._resolve_tlp_color("file"),
                    labels=labels,
                )
                file_obs.is_ioc = False
                file_obs.generate_stix_objects()
                related_objects.append(file_obs)

        link_list = self._normalize_list(payload.get("link_list"))
        for item in link_list:
            if not isinstance(item, dict):
                continue
            url_val = item.get("link")
            if url_val:
                url_obs = ds.URL(
                    name=url_val,
                    c_type="url",
                    tlp_color=self._resolve_tlp_color("url"),
                    labels=labels,
                )
                url_obs.is_ioc = False
                url_obs.generate_stix_objects()
                related_objects.append(url_obs)

        self._generate_relations(
            main_obj=incident,
            related_objects=related_objects,
            helper=self.helper,
        )
        incident.add_relationships_to_stix_objects()

        data_block = None
        if payload.get("data"):
            full_data = str(payload.get("data"))
            _coll = "osi_public_leak"
            use_full = self.config.get_collection_settings(_coll, "full_data")
            max_len = self.config.get_collection_settings(_coll, "data_preview_max_len")
            if max_len is not None and not isinstance(max_len, int):
                try:
                    max_len = int(max_len)
                except (TypeError, ValueError):
                    max_len = 2000
            if max_len is None:
                max_len = 2000
            if use_full and str(use_full).lower() in ("true", "1", "yes"):
                data_block = (True, full_data, "")
            else:
                data_preview = full_data[:max_len]
                if len(full_data) > max_len:
                    data_preview += "..."
                data_block = (
                    False,
                    data_preview,
                    f"Data (preview, max {max_len} chars)",
                )

        pl_md = markdown_osi_public_leak(
            leak_id=leak_id,
            leak_hash=leak_hash,
            created_raw=created_raw,
            payload=payload,
            link_list=link_list,
            data_full_or_preview=data_block,
            matches=payload.get("matches"),
        )

        self._apply_incident_description(incident)

        note = self._finalize_stix_note(
            name="Public leak details",
            content=pl_md,
            object_refs=[incident.stix_main_object.id]
            + [o.stix_main_object.id for o in related_objects],
            labels=labels,
            portal_links=portal_links,
        )

        stix_objects = []
        for obj in related_objects + [incident]:
            stix_objects += obj.stix_objects
        stix_objects.append(note)
        author_identity = self.author
        if (json_eval_obj or {}).get("reliability") is not None:
            author_identity = stix2.Identity(
                id=author_identity.id,
                name=author_identity.name,
                identity_class=author_identity.identity_class,
                created=author_identity.created,
                modified=author_identity.modified,
                custom_properties={
                    "x_opencti_reliability": str(
                        (json_eval_obj or {}).get("reliability")
                    )
                },
                allow_custom=True,
            )
        stix_objects += [author_identity]
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects += [self.statement_marking]
        entities = [
            o for o in stix_objects if getattr(o, "type", None) != "relationship"
        ]
        relationships = [
            o for o in stix_objects if getattr(o, "type", None) == "relationship"
        ]
        result = list(entities) + list(relationships)
        if not result:
            self.helper.connector_logger.error(
                "generate_osi_public_leak: built empty STIX list despite having public_leak payload"
            )
        return result

    def generate_osi_vulnerability(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        vuln = event.get("vulnerability") or {}
        advisory_id = vuln.get("object_id") or vuln.get("id")
        cve_list = [
            c.strip()
            for c in self._normalize_list(vuln.get("cve_list"))
            if isinstance(c, str) and c.strip()
        ]
        # Primary entity keeps the record id; each CVE links to it.
        primary_name = advisory_id or (cve_list[0] if cve_list else None)
        if not primary_name:
            self.helper.connector_logger.warning(
                "No vulnerability id/CVE provided for osi/vulnerability"
            )
            return []

        cvss = event.get("cvssv3") or event.get("cvssv2") or {}
        cpe_table = event.get("cpe_table") or {}
        cpe_list = self._normalize_list(cpe_table.get("cpe_table_list"))

        created = self._parse_iso_utc((json_date_obj or {}).get("date-published"))
        labels, _ = self._resolve_entity_labels(collection_label=self.collection)

        # External references: TI-portal + advisory link (href) + upstream
        # references (the API ships them comma-joined inside list elements).
        portal_links = self._retrieve_link(vuln)
        href = vuln.get("href")
        if href and isinstance(href, str) and href.strip():
            portal_links.append((None, href.strip(), "Upstream advisory"))
        for raw_ref in self._normalize_list(vuln.get("references")):
            if not isinstance(raw_ref, str):
                continue
            for ref in raw_ref.split(","):
                ref = ref.strip()
                if ref.startswith("http"):
                    portal_links.append((None, ref, "Reference"))

        # CVSS: prefer the merged score (cvssv3 block); fall back to the raw
        # cvss.score. Treat 0/empty as "no score".
        def _num(v: Any) -> float | None:
            try:
                f = float(v)
            except (TypeError, ValueError):
                return None
            return f if f > 0 else None

        cvss_score = _num(cvss.get("score")) or _num(vuln.get("cvss_base"))
        cvss_vector = cvss.get("vector") or vuln.get("cvss_base_vector") or None

        # Description: advisory title + description (raw description is often a
        # low-value placeholder, so the title leads).
        title = vuln.get("title")
        raw_desc = self.normalize_description(vuln.get("description"))
        desc_parts = [p for p in (title, raw_desc) if p]
        description = "\n\n".join(desc_parts) if desc_parts else None

        def _make_vuln(name: str) -> Any:
            v = ds.Vulnerability(
                name=name,
                c_type="vulnerability",
                created=created,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                tlp_color=self._resolve_tlp_color("vulnerability"),
                labels=labels,
            )
            if description:
                v.set_description(description)
            v.generate_external_references(portal_links)
            v.generate_stix_objects()
            return v

        primary = _make_vuln(primary_name)
        vuln_objects: list[Any] = [primary]
        for cve in cve_list:
            if cve == primary_name:
                continue
            cve_vuln = _make_vuln(cve)
            primary.generate_relationship(
                primary.stix_main_object,
                cve_vuln.stix_main_object,
                relation_type="related-to",
            )
            vuln_objects.append(cve_vuln)
        primary.add_relationships_to_stix_objects()

        vuln_md = markdown_osi_vulnerability(
            vuln=vuln,
            cvss={"score": cvss_score, "vector": cvss_vector},
            cpe_list=cpe_list,
            json_date_obj=json_date_obj or {},
        )
        note = self._finalize_stix_note(
            name=f"Vulnerability details: {primary_name}",
            content=vuln_md,
            object_refs=[v.stix_main_object.id for v in vuln_objects],
            labels=labels,
            portal_links=portal_links or None,
            created=created,
            modified=created,
        )

        stix_objects: list[Any] = []
        for v in vuln_objects:
            stix_objects += v.stix_objects
        stix_objects.append(note)
        author_identity = self.author
        if (json_eval_obj or {}).get("reliability") is not None:
            author_identity = stix2.Identity(
                id=author_identity.id,
                name=author_identity.name,
                identity_class=author_identity.identity_class,
                created=author_identity.created,
                modified=author_identity.modified,
                custom_properties={
                    "x_opencti_reliability": str(
                        (json_eval_obj or {}).get("reliability")
                    )
                },
                allow_custom=True,
            )
        stix_objects.append(author_identity)
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects.append(self.statement_marking)
        return stix_objects

    def generate_osi_git_repository(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        payload = event.get("git_repository") or {}
        if not payload:
            self.helper.connector_logger.warning(
                "No git_repository object provided for osi/git_repository"
            )
            return []

        def _parse_iso(raw_value: Any) -> datetime | None:
            if not raw_value:
                return None
            try:
                if str(raw_value).startswith("00"):
                    return None
                return datetime.fromisoformat(str(raw_value).replace("Z", "+00:00"))
            except Exception:
                return None

        repo_id = payload.get("id")
        name = (
            payload.get("name")
            or payload.get("leaked_file_name")
            or payload.get("source")
        )
        date_detected = payload.get("dateDetected") or (json_date_obj or {}).get(
            "date-detected"
        )
        date_created = payload.get("dateCreated") or (json_date_obj or {}).get(
            "date-created"
        )
        created_time = _parse_iso(date_created) or _parse_iso(date_detected)
        if not created_time:
            created_time = datetime.now(timezone.utc)

        portal_links = self._retrieve_link(payload)
        source_types = self._normalize_list(payload.get("source_type"))
        labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            source_types=source_types,
        )

        severity = self._map_severity((json_eval_obj or {}).get("severity"))

        incident_name = (
            f"Git repository leak: {name or 'Unknown'} [{repo_id or 'unknown'}]"
        )
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

        related_objects = []
        files_list = payload.get("files")
        if isinstance(files_list, list):
            pass
        elif isinstance(files_list, dict):
            files_list = [files_list]
        else:
            files_list = []

        author_email_observables = self.config.get_setting_bool(
            "osi_git_repository", "author_email_observables", default=True
        )
        seen_hashes = set()
        seen_urls = set()
        seen_emails = set()
        for file_row in files_list:
            if not isinstance(file_row, dict):
                continue
            hash_raw = file_row.get("hash")
            hash_list = self._normalize_list(hash_raw) if hash_raw else []
            for file_hash in hash_list:
                if not file_hash or file_hash in seen_hashes:
                    continue
                hash_type = None
                if len(str(file_hash)) == 64:
                    hash_type = "SHA-256"
                elif len(str(file_hash)) == 40:
                    hash_type = "SHA-1"
                elif len(str(file_hash)) == 32:
                    hash_type = "MD5"
                if not (hash_type and self._valid_hash(file_hash, hash_type)):
                    self._log_skipped(
                        "file hash",
                        file_hash,
                        "not a valid MD5/SHA-1/SHA-256 hash",
                    )
                if hash_type and self._valid_hash(file_hash, hash_type):
                    seen_hashes.add(file_hash)
                    file_obs = ds.FileHash(
                        name=[file_hash],
                        c_type="file",
                        tlp_color=self._resolve_tlp_color("file"),
                        labels=labels,
                    )
                    file_obs.is_ioc = False
                    file_obs.generate_stix_objects()
                    related_objects.append(file_obs)
            url_val = file_row.get("url")
            if url_val and url_val not in seen_urls:
                seen_urls.add(url_val)
                url_obs = ds.URL(
                    name=url_val,
                    c_type="url",
                    tlp_color=self._resolve_tlp_color("url"),
                    labels=labels,
                )
                url_obs.is_ioc = False
                url_obs.generate_stix_objects()
                related_objects.append(url_obs)
            if author_email_observables:
                for email_raw in self._normalize_list(file_row.get("authorEmail")):
                    email_val = self.normalize_email(email_raw)
                    if email_val is None and email_raw:
                        self._log_skipped("author email", email_raw)
                    if not email_val or email_val in seen_emails:
                        continue
                    seen_emails.add(email_val)
                    email_obs = ds.Email(
                        name=email_val,
                        c_type="email-addr",
                        tlp_color=self._resolve_tlp_color("email-addr"),
                        labels=labels,
                    )
                    email_obs.is_ioc = False
                    email_obs.set_description(
                        "Commit author of the leaked repository file."
                    )
                    email_obs.generate_stix_objects()
                    related_objects.append(email_obs)

        self._generate_relations(
            main_obj=incident,
            related_objects=related_objects,
            helper=self.helper,
        )
        incident.add_relationships_to_stix_objects()

        git_md = markdown_osi_git_repository(
            repo_id=repo_id,
            name=name,
            payload=payload,
            date_detected=date_detected,
            date_created=date_created,
            files_list=files_list,
            flatten_cell=self._flatten_cell,
        )

        self._apply_incident_description(incident)

        note = self._finalize_stix_note(
            name="Git repository leak details",
            content=git_md,
            object_refs=[incident.stix_main_object.id]
            + [o.stix_main_object.id for o in related_objects],
            labels=labels,
            portal_links=portal_links,
        )

        stix_objects = []
        for obj in related_objects + [incident]:
            stix_objects += obj.stix_objects
        stix_objects.append(note)
        author_identity = self.author
        if (json_eval_obj or {}).get("reliability") is not None:
            author_identity = stix2.Identity(
                id=author_identity.id,
                name=author_identity.name,
                identity_class=author_identity.identity_class,
                created=author_identity.created,
                modified=author_identity.modified,
                custom_properties={
                    "x_opencti_reliability": str(
                        (json_eval_obj or {}).get("reliability")
                    )
                },
                allow_custom=True,
            )
        stix_objects += [author_identity]
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects += [self.statement_marking]
        entities = [
            o for o in stix_objects if getattr(o, "type", None) != "relationship"
        ]
        relationships = [
            o for o in stix_objects if getattr(o, "type", None) == "relationship"
        ]
        result = list(entities) + list(relationships)
        if not result:
            self.helper.connector_logger.error(
                "generate_osi_git_repository: built empty STIX list despite having git_repository payload"
            )
        return result

    def _collect_hashes(self, raw_files: list[Any], raw_hashes: list[Any]) -> list[str]:
        candidates = []
        for item in raw_files:
            if isinstance(item, dict):
                for key in ("md5", "sha1", "sha256"):
                    h = item.get(key)
                    if h and isinstance(h, str) and h.strip():
                        candidates.append(h.strip())
            elif isinstance(item, str) and item.strip():
                candidates.append(item.strip())
        for item in raw_hashes:
            val = self._extract_string_value(item)
            if val:
                candidates.append(val)
        valid = []
        for h in candidates:
            if (
                self._valid_hash(h, "MD5")
                or self._valid_hash(h, "SHA1")
                or self._valid_hash(h, "SHA256")
            ):
                valid.append(h)
            else:
                self._log_skipped("file hash", h, "not a valid MD5/SHA-1/SHA-256 hash")
        return valid

    def generate_hi_open_threats(
        self,
        event: dict[str, Any],
        json_date_obj: dict[str, Any],
        json_eval_obj: dict[str, Any],
    ) -> list[Any]:
        open_threat = event.get("open_threat") or {}
        if not open_threat:
            self.helper.connector_logger.warning(
                "No open_threat object provided for hi/open_threats"
            )
            return []

        open_threat_id = open_threat.get("id") or ""
        title = open_threat.get("title") or "Open Threat Report"
        text = open_threat.get("text") or ""
        original = open_threat.get("original") or ""
        link = open_threat.get("link") or ""
        source = open_threat.get("source") or ""
        source_type = open_threat.get("sourceType") or ""

        created_time = self._parse_iso_utc(
            json_date_obj.get("date-created") or json_date_obj.get("date-detected")
        ) or datetime.now(timezone.utc)

        eval_obj = json_eval_obj or {}
        self.tlp_color = eval_obj.get("tlp") or self.tlp_color

        portal_links = self._retrieve_link(open_threat)

        raw_threat_actors = self._normalize_list(open_threat.get("threat_actor_list"))
        raw_malware = self._normalize_list(open_threat.get("malware"))
        raw_cve = self._normalize_list(open_threat.get("cve"))
        raw_domains = self._normalize_list(open_threat.get("domains"))
        raw_ips = self._normalize_list(open_threat.get("ips"))
        raw_urls = self._normalize_list(open_threat.get("urls"))
        raw_countries = self._normalize_list(open_threat.get("countries"))
        raw_tags = self._normalize_list(open_threat.get("tags"))
        raw_files = self._normalize_list(open_threat.get("files"))
        raw_hashes = self._normalize_list(open_threat.get("hashes"))

        ta_names = self._extract_name_list(raw_threat_actors)
        mal_names = self._extract_name_list(raw_malware)
        tag_labels = [str(t) for t in raw_tags if isinstance(t, str) and t]

        entity_labels, _ = self._resolve_entity_labels(
            collection_label=self.collection,
            threat_actor_names=ta_names[:5],
            malware_names=mal_names[:5],
            context_labels=tag_labels[:10],
        )

        report_name = f"{title} [{open_threat_id}]" if open_threat_id else title
        _coll = "hi_open_threats"

        report_description = TICollections.DESCRIPTIONS.get("hi/open_threats", "")

        observables_as_indicators = self.config.get_setting_bool(
            _coll, "observables_as_indicators", default=True
        )
        ioc_ttl_days = self._resolve_ttl_days(_coll, json_date_obj, default=30)
        ioc_valid_from = created_time
        ioc_valid_until = created_time + timedelta(days=ioc_ttl_days)

        def _make_open_threat_obs(cls: type, val: Any, ctype: str) -> Any:
            if ctype == "domain-name":
                if self.is_ipv4(val) or self.is_ipv6(val):
                    self.helper.connector_logger.info(
                        f"{self.collection}: domain field carries an IP; "
                        f"emitting as IP observable: {val!r}"
                    )
                    cls = ds.IPAddress
                    ctype = "ip"
                elif not self.is_valid_domain(val):
                    self._log_skipped("domain", val)
                    return None
            if ctype == "ip":
                if self.is_ipv4(val):
                    ctype = "ipv4-addr"
                elif self.is_ipv6(val):
                    ctype = "ipv6-addr"
                else:
                    self._log_skipped("ip", val, "not a valid IPv4/IPv6 address")
                    return None
            if not observables_as_indicators:
                return self._build_non_ioc_observable(cls, val, ctype, entity_labels)
            obs = cls(
                name=val,
                c_type=ctype,
                tlp_color=self._resolve_tlp_color(ctype),
                labels=entity_labels,
            )
            obs.is_ioc = True
            obs.set_valid_from(ioc_valid_from)
            obs.set_valid_until(ioc_valid_until)
            obs.generate_stix_objects()
            return obs

        related_objects = []

        for ta_item in raw_threat_actors:
            if not isinstance(ta_item, dict) or not ta_item.get("name"):
                continue
            ta_name = ta_item["name"]
            ta_labels, _ = self._resolve_entity_labels(
                collection_label=self.collection, threat_actor_names=[ta_name]
            )
            ta = ds.ThreatActor(
                name=ta_name,
                c_type="threat-actor",
                global_label=self.ta_global_label,
                tlp_color=self._resolve_tlp_color("threat-actor"),
                labels=ta_labels,
            )
            ta.generate_stix_objects()
            related_objects.append(ta)

        for mal_item in raw_malware:
            if not isinstance(mal_item, dict) or not mal_item.get("name"):
                continue
            mal_name = mal_item["name"]
            mal_labels, _ = self._resolve_entity_labels(
                collection_label=self.collection, malware_names=[mal_name]
            )
            mal = ds.Malware(
                name=mal_name,
                c_type="malware",
                malware_types=[],
                tlp_color=self._resolve_tlp_color("malware"),
                labels=mal_labels,
            )
            mal.generate_stix_objects()
            related_objects.append(mal)

        for cve_item in raw_cve:
            if not isinstance(cve_item, dict) or not cve_item.get("id"):
                continue
            vuln = ds.Vulnerability(
                name=cve_item["id"],
                c_type="vulnerability",
                tlp_color=self._resolve_tlp_color("vulnerability"),
                labels=entity_labels,
            )
            vuln.generate_stix_objects()
            related_objects.append(vuln)

        for item in raw_domains:
            val = self._extract_string_value(item)
            if val:
                obs = _make_open_threat_obs(ds.Domain, val, "domain-name")
                if obs is not None:
                    related_objects.append(obs)

        for item in raw_ips:
            val = self._extract_string_value(item)
            if val:
                ip_obs = _make_open_threat_obs(ds.IPAddress, val, "ip")
                if ip_obs is not None:
                    related_objects.append(ip_obs)

        for item in raw_urls:
            val = self._extract_string_value(item)
            if val:
                obs = _make_open_threat_obs(ds.URL, val, "url")
                if obs is not None:
                    related_objects.append(obs)

        valid_hashes = self._collect_hashes(raw_files, raw_hashes)
        if valid_hashes:
            file_obs = _make_open_threat_obs(ds.FileHash, valid_hashes, "file")
            if file_obs is not None:
                related_objects.append(file_obs)

        if observables_as_indicators:
            threat_anchors = [
                o
                for o in related_objects
                if getattr(o, "c_type", "") in ("threat-actor", "malware")
            ]
            for o in related_objects:
                if not getattr(o, "is_ioc", False):
                    continue
                self._generate_relations(
                    main_obj=o,
                    related_objects=threat_anchors,
                    helper=self.helper,
                    is_ioc=True,
                )
                o.add_relationships_to_stix_objects()

        country_codes = [
            c.get("countryCode")
            for c in raw_countries
            if isinstance(c, dict) and c.get("countryCode")
        ]
        locations = self.generate_locations(country_codes) if country_codes else []

        cve_ids = [c.get("id") for c in raw_cve if isinstance(c, dict) and c.get("id")]

        domain_vals = [v for d in raw_domains if (v := self._extract_string_value(d))]
        ip_vals = [v for i in raw_ips if (v := self._extract_string_value(i))]
        url_vals = [v for u in raw_urls if (v := self._extract_string_value(u))]

        include_text = self.config.get_setting_bool(
            _coll, "include_text_in_note", default=True
        )
        include_original = self.config.get_setting_bool(
            _coll, "include_original_in_note", default=False
        )

        hot_md = markdown_hi_open_threats(
            open_threat_id=open_threat_id,
            title=title,
            source=source,
            source_type=source_type,
            link=link,
            json_date_obj=json_date_obj,
            raw_threat_actors=raw_threat_actors,
            raw_malware=raw_malware,
            cve_ids=cve_ids,
            tag_labels=tag_labels,
            country_codes=country_codes,
            domain_vals=domain_vals,
            ip_vals=ip_vals,
            url_vals=url_vals,
            valid_hashes=valid_hashes,
            include_text=include_text,
            include_original=include_original,
            text=text,
            original=original,
            get_text_preview=lambda t: self._get_text_preview(_coll, t),
        )

        report_object_refs = [o.stix_main_object.id for o in related_objects]
        for o in related_objects:
            _ind = getattr(o, "stix_indicator", None)
            if _ind:
                report_object_refs += [
                    i.id for i in (_ind if isinstance(_ind, list) else [_ind])
                ]
        report_object_refs += [loc.stix_main_object.id for loc in locations]
        if not report_object_refs:
            report_object_refs = [self.author.id]

        if link:
            portal_links.append((link, link, f"Source: {title[:80]}"))

        report = ds.Report(
            name=report_name,
            c_type="threat_report",
            published_time=created_time,
            related_objects_ids=report_object_refs,
            tlp_color=self.tlp_color,
            labels=entity_labels,
        )
        report.set_description(report_description)
        report.generate_external_references(portal_links)
        desc_in_ext = self.config.get_setting_bool(
            _coll,
            "description_in_external_references",
            default=False,
        )
        if desc_in_ext:
            report.set_description("")
            if report_description:
                report.external_references.append(
                    stix2.ExternalReference(
                        source_name="Open threat description",
                        description=str(report_description),
                    )
                )
        report.generate_stix_objects()

        if eval_obj.get("reliability") is not None:
            author = report.author
            report.author = stix2.Identity(
                id=author.id,
                name=author.name,
                identity_class=author.identity_class,
                created=author.created,
                modified=author.modified,
                custom_properties={
                    "x_opencti_reliability": str(eval_obj["reliability"])
                },
                allow_custom=True,
            )

        note = self._finalize_stix_note(
            name=f"Open Threat: {title[:80]}",
            content=hot_md,
            object_refs=[report.stix_main_object.id]
            + [o.stix_main_object.id for o in related_objects]
            + [loc.stix_main_object.id for loc in locations],
            labels=entity_labels,
            portal_links=portal_links,
        )

        stix_objects = []
        for obj in related_objects:
            stix_objects += obj.stix_objects
        for loc in locations:
            stix_objects += loc.stix_objects
        stix_objects += report.stix_objects
        stix_objects.append(note)
        stix_objects.append(report.author)
        stix_objects.append(report.tlp)
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects.append(report.statement_marking)

        entities = [
            o for o in stix_objects if getattr(o, "type", None) != "relationship"
        ]
        relationships = [
            o for o in stix_objects if getattr(o, "type", None) == "relationship"
        ]
        return entities + relationships

    def generate_ioc_primary(
        self,
        event,
        json_date_obj,
        json_eval_obj,
    ):
        """Generate STIX for an ``ioc/primary`` event."""
        ioc_primary = event.get("ioc_primary") or {}
        if not ioc_primary:
            self.helper.connector_logger.warning(
                "No ioc_primary object provided for ioc/primary"
            )
            return []

        ioc_type = ioc_primary.get("type") or ""

        valid_from = self._parse_iso_utc(
            json_date_obj.get("date-first-seen")
        ) or datetime.now(timezone.utc)
        valid_until = self._parse_iso_utc(json_date_obj.get("date-last-seen"))
        ttl = json_date_obj.get("ttl")
        if not valid_until or valid_until <= valid_from:
            if ttl:
                try:
                    valid_until = valid_from + timedelta(days=int(ttl))
                except (ValueError, TypeError):
                    valid_until = None
            else:
                valid_until = None

        entity_labels, _ = self._resolve_entity_labels(collection_label=self.collection)

        malware_names = sorted(
            {
                m.get("name")
                for m in self._normalize_list(ioc_primary.get("malware_list"))
                if isinstance(m, dict) and m.get("name")
            }
        )
        threat_entries = [
            t
            for t in self._normalize_list(ioc_primary.get("threat_list"))
            if isinstance(t, dict) and t.get("name")
        ]

        static_desc = TICollections.DESCRIPTIONS.get("ioc/primary", "") or (
            "Consolidated Indicators of Compromise from multiple threat intelligence sources."
        )
        ioc_description = static_desc or None

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
        for t in threat_entries:
            t_name = t.get("name")
            if not t_name or t_name in malware_names:
                continue
            ta = ds.ThreatActor(
                name=t_name,
                c_type="threat-actor",
                global_label=self.ta_global_label,
                tlp_color=self._resolve_tlp_color("threat-actor"),
                labels=entity_labels,
            )
            ta.generate_stix_objects()
            threat_actor_objects.append(ta)

        indicator_labels = list(entity_labels or [])
        for name in malware_names[:5]:
            if name and name not in indicator_labels:
                indicator_labels.append(name)
        for t in threat_entries[:5]:
            t_name = t.get("name")
            if t_name and t_name not in malware_names:
                label = t_name
                if label not in indicator_labels:
                    indicator_labels.append(label)

        for tag in self._normalize_list(ioc_primary.get("tags")):
            if isinstance(tag, str):
                tag = tag.strip()
                if tag and tag not in indicator_labels:
                    indicator_labels.append(tag)

        attribution_targets = malware_objects + threat_actor_objects

        def _setup_ioc(ioc_obj):
            ioc_obj.is_ioc = True
            if ioc_description:
                ioc_obj.set_description(ioc_description)
            ioc_obj.set_valid_from(valid_from)
            ioc_obj.set_valid_until(valid_until)
            ioc_obj.generate_stix_objects()
            if ioc_obj.stix_observable and ioc_obj.stix_objects:
                ioc_obj.stix_objects = [
                    o for o in ioc_obj.stix_objects if o is not ioc_obj.stix_observable
                ]
            indicator = ioc_obj.stix_indicator
            if indicator:
                indicators = indicator if isinstance(indicator, list) else [indicator]
                for ind in indicators:
                    for target in attribution_targets:
                        ioc_obj.generate_relationship(
                            ind,
                            target.stix_main_object,
                            relation_type="indicates",
                        )
            ioc_obj.add_relationships_to_stix_objects()

        def _coerce_score(val):
            try:
                return int(val) if val is not None else None
            except (TypeError, ValueError):
                return None

        def _iter_scored(raw, field_key):
            """Yield (value, riskScore) pairs; accept bare strings as fallback."""
            out = []
            for entry in self._normalize_list(raw):
                if isinstance(entry, str):
                    v = entry.strip()
                    if v:
                        out.append((v, None))
                elif isinstance(entry, dict):
                    v = entry.get(field_key)
                    if isinstance(v, str) and v.strip():
                        out.append((v.strip(), _coerce_score(entry.get("riskScore"))))
            return out

        ioc_objects = []

        if ioc_type == "network":
            for field_key, cls, c_type in [
                ("domain", ds.Domain, "domain-name"),
                ("url", ds.URL, "url"),
            ]:
                for val, score in _iter_scored(ioc_primary.get(field_key), field_key):
                    obj_cls, obj_ctype = cls, c_type
                    if c_type == "domain-name":
                        if self.is_ipv4(val) or self.is_ipv6(val):
                            self.helper.connector_logger.info(
                                f"{self.collection}: domain field carries "
                                f"an IP; emitting as IP observable: {val!r}"
                            )
                            obj_cls = ds.IPAddress
                            obj_ctype = (
                                "ipv4-addr" if self.is_ipv4(val) else "ipv6-addr"
                            )
                        elif not self.is_valid_domain(val):
                            self._log_skipped("ioc domain", val)
                            continue
                    obj = obj_cls(
                        name=val,
                        c_type=obj_ctype,
                        tlp_color=self._resolve_tlp_color(obj_ctype),
                        labels=indicator_labels,
                        risk_score=score,
                    )
                    _setup_ioc(obj)
                    ioc_objects.append(obj)

            for ip_val, score in _iter_scored(ioc_primary.get("ip"), "ip"):
                if self.is_ipv4(ip_val):
                    ip_ctype = "ipv4-addr"
                elif self.is_ipv6(ip_val):
                    ip_ctype = "ipv6-addr"
                else:
                    self._log_skipped("ioc ip", ip_val, "not a valid IPv4/IPv6 address")
                    continue
                obj = ds.IPAddress(
                    name=ip_val,
                    c_type=ip_ctype,
                    tlp_color=self._resolve_tlp_color(ip_ctype),
                    labels=indicator_labels,
                    risk_score=score,
                )
                _setup_ioc(obj)
                ioc_objects.append(obj)

        elif ioc_type == "file":
            top_score = _coerce_score(ioc_primary.get("risk_score"))
            raw_hashes = ioc_primary.get("hash")
            if not isinstance(raw_hashes, list):
                raw_hashes = [raw_hashes] if raw_hashes else []
            valid_hashes = [
                h.strip()
                for h in raw_hashes
                if isinstance(h, str)
                and h.strip()
                and (
                    self._valid_hash(h.strip(), "MD5")
                    or self._valid_hash(h.strip(), "SHA1")
                    or self._valid_hash(h.strip(), "SHA256")
                )
            ]
            if valid_hashes:
                fh = ds.FileHash(
                    name=valid_hashes,
                    c_type="file",
                    tlp_color=self._resolve_tlp_color("file"),
                    labels=indicator_labels,
                    risk_score=top_score,
                )
                _setup_ioc(fh)
                ioc_objects.append(fh)

        if not ioc_objects:
            self.helper.connector_logger.warning(
                f"No IOC indicators produced for ioc/primary id="
                f"{ioc_primary.get('id', '')}"
            )
            return []

        ioc_id = ioc_primary.get("id") or ""
        if ioc_type == "network":
            sample_vals = []
            for field_key in ("domain", "url", "ip"):
                sample_vals.extend(
                    v for v, _ in _iter_scored(ioc_primary.get(field_key), field_key)
                )
            ioc_value = ", ".join(sample_vals)
        else:
            raw_h = ioc_primary.get("hash") or []
            ioc_value = ", ".join(
                str(h) for h in (raw_h if isinstance(raw_h, list) else [raw_h]) if h
            )

        ioc_md = markdown_ioc_note(
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value or "—",
            json_date_obj=json_date_obj,
            malware_names=malware_names,
            threat_entries=threat_entries,
            risk_score=_coerce_score(ioc_primary.get("risk_score")),
        )

        note_refs = []
        for o in ioc_objects:
            ind = o.stix_indicator
            if ind:
                indicators = ind if isinstance(ind, list) else [ind]
                note_refs += [i.id for i in indicators]
            elif o.stix_main_object:
                note_refs.append(o.stix_main_object.id)

        note = self._finalize_stix_note(
            name=f"IOC: {ioc_value[:80] if ioc_value else ioc_id[:80] or 'unknown'}",
            content=ioc_md,
            object_refs=note_refs,
            labels=indicator_labels,
        )

        stix_objects = []
        for obj in ioc_objects + malware_objects + threat_actor_objects:
            stix_objects += obj.stix_objects
        stix_objects.append(note)
        stix_objects.append(self.author)
        if self.config.get_extra_settings_by_name("enable_statement_marking"):
            stix_objects.append(self.statement_marking)

        entities = [
            o for o in stix_objects if getattr(o, "type", None) != "relationship"
        ]
        relationships = [
            o for o in stix_objects if getattr(o, "type", None) == "relationship"
        ]
        return entities + relationships
