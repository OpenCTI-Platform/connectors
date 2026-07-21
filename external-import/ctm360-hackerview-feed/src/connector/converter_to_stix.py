import re

import pycti
import stix2
from connector.utils import normalize_timestamp
from pycti import CustomObjectCaseIncident, OpenCTIConnectorHelper


class ConverterToStix:
    def __init__(self, helper: OpenCTIConnectorHelper):
        self.helper = helper
        self.author = stix2.Identity(
            id=pycti.Identity.generate_id(
                name="HackerView",
                identity_class="organization",
            ),
            name="HackerView",
            identity_class="organization",
            description="CTM360 External Attack Surface Management platform",
        )
        # Populated during issues_to_stix() for CaseIncident creation
        self.issue_case_metadata = []

    def _ext_ref(self, source_name: str, external_id: str, url: str = None):
        ref = {"source_name": source_name, "external_id": str(external_id)}
        if url:
            ref["url"] = url
        return stix2.ExternalReference(**ref)

    def _severity_to_score(self, severity: str) -> int:
        mapping = {
            "critical": 95,
            "high": 80,
            "medium": 55,
            "low": 30,
            "info": 10,
            "informational": 10,
        }
        return mapping.get(str(severity).lower(), 50)

    def _severity_to_priority(self, severity: str) -> str:
        mapping = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
        return mapping.get(str(severity).lower(), "P3")

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to OpenCTI-valid values (low, medium, high, critical)."""
        s = str(severity).lower()
        if s in ("critical", "high", "medium", "low"):
            return s
        if s in ("info", "informational"):
            return "low"
        return "medium"

    def _slugify_label(self, text: str) -> str:
        """Convert a label to lowercase kebab-case."""
        return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")

    def _flatten_issue(self, issue: dict) -> dict:
        """Flatten an issue by merging meta fields into top level.

        The HackerView API nests domain, host, resolved_ip, technologies,
        environments, first_seen, last_seen, asset, asset_type, and other
        fields inside issue["meta"]. This method merges them up so the
        converter can access them directly.
        """
        flat = dict(issue)
        meta = issue.get("meta") or {}
        # Meta fields that should be promoted (meta wins only if top-level is missing)
        meta_fields = [
            "domain",
            "host",
            "resolved_ip",
            "technologies",
            "environments",
            "first_seen",
            "last_seen",
            "asset",
            "asset_type",
            "port",
            "discovery_source",
            "host_type",
            "business_unit",
            "brand",
            "scan_id",
            "ip",
        ]
        for field in meta_fields:
            if field in meta and not flat.get(field):
                flat[field] = meta[field]
        # ticket_id: prefer top-level, fall back to meta
        if not flat.get("ticket_id") and meta.get("ticket_id"):
            flat["ticket_id"] = meta["ticket_id"]
        return flat

    def _format_list_field(self, value) -> str:
        """Convert a list field to a comma-separated string."""
        if isinstance(value, list):
            parts = []
            for item in value:
                if isinstance(item, dict):
                    # Handle CWE objects: {"cwe_id": "CWE-79", "cwe_detail": "..."}
                    cwe_id = item.get("cwe_id", "")
                    cwe_detail = item.get("cwe_detail", "")
                    parts.append(f"{cwe_id} ({cwe_detail})" if cwe_detail else cwe_id)
                else:
                    parts.append(str(item))
            return ", ".join(parts)
        return str(value) if value else ""

    def _add_list_labels(self, labels: list, value) -> None:
        """Add slugified label(s) from a string or list field."""
        if isinstance(value, list):
            for item in value:
                if item:
                    slug = self._slugify_label(str(item))
                    if slug:
                        labels.append(slug)
        elif value:
            slug = self._slugify_label(str(value))
            if slug:
                labels.append(slug)

    def _first_list_item(self, value) -> str:
        """Get the first string item from a list, or the value itself if string."""
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return str(value) if value else ""

    def issues_to_stix(self, issues: list) -> list:
        """Convert HackerView security issues to STIX objects.

        Builds, per issue, a Vulnerability (when cve_id is present), a System
        identity for the affected asset, a Note with the full details, any
        AttackPattern (CWE) / Software (technology) objects, and a
        ``CustomObjectCaseIncident`` (deterministic id) referencing them — all
        shipped in the bundle. Records the deterministic case id and current
        status in ``issue_case_metadata`` so the status tracker can follow up.
        """
        self.issue_case_metadata = []
        objects = [self.author]
        for raw_issue in issues:
            issue = self._flatten_issue(raw_issue)
            issue_id = issue.get("ticket_id", "")
            issue_name = issue.get("issue_name", "Unknown issue")
            severity = issue.get("severity", "medium")
            cve_id = issue.get("cve_id", "")
            cwe = self._format_list_field(issue.get("cwe", ""))
            issue_category = self._format_list_field(issue.get("issue_category", ""))
            potential_attack_type = self._format_list_field(
                issue.get("potential_attack_type", "")
            )
            potential_impact = self._format_list_field(
                issue.get("potential_impact", "")
            )
            status = issue.get("status", "unknown")
            progress_status = issue.get("progress_status", "")
            ticket_id = issue.get("ticket_id", "")
            domain = issue.get("domain", "")
            host = issue.get("host", "")
            asset_type = issue.get("asset_type", "")
            asset = issue.get("asset", "")
            resolved_ip = issue.get("resolved_ip", "")
            technologies = issue.get("technologies", [])
            environments = issue.get("environments", [])
            hackerview_link = issue.get("hackerview_link", "")
            first_seen = normalize_timestamp(issue.get("first_seen"))
            last_updated = normalize_timestamp(issue.get("last_updated"))

            if not issue_id:
                self.helper.connector_logger.warning(
                    "[CONVERTER] Skipping issue with no ticket_id",
                    {"issue_name": issue_name},
                )
                continue

            # STIX ids of every entity built for this issue; used as the
            # CaseIncident object_refs so the case is a complete container.
            issue_object_ids = []

            score = self._severity_to_score(severity)
            ext_ref = self._ext_ref(
                "CTM360-HackerView", str(issue_id), url=hackerview_link or None
            )

            tech_str = (
                ", ".join(technologies)
                if isinstance(technologies, list)
                else str(technologies)
            )
            env_str = (
                ", ".join(environments)
                if isinstance(environments, list)
                else str(environments)
            )
            issue_type = issue.get("issue_type", "")
            brand = issue.get("brand", "")

            # Build description with markdown formatting
            desc_lines = [f"**Issue:** {issue_name}"]
            if issue_category:
                desc_lines.append(f"**Category:** {issue_category}")
            if issue_type:
                desc_lines.append(f"**Type:** {issue_type}")
            desc_lines.append(f"**Severity:** {severity}")
            desc_lines.append(f"**Status:** {status}")
            if progress_status:
                desc_lines.append(f"**Progress:** {progress_status}")
            if asset:
                desc_lines.append(
                    f"**Asset:** {asset} ({asset_type})"
                    if asset_type
                    else f"**Asset:** {asset}"
                )
            if domain:
                desc_lines.append(f"**Domain:** {domain}")
            if host and host != domain:
                desc_lines.append(f"**Host:** {host}")
            if resolved_ip:
                desc_lines.append(f"**IP:** {resolved_ip}")
            if cve_id:
                desc_lines.append(f"**CVE:** {cve_id}")
            if cwe:
                desc_lines.append(f"**CWE:** {cwe}")
            if potential_attack_type:
                desc_lines.append(f"**Potential Attack Type:** {potential_attack_type}")
            if potential_impact:
                desc_lines.append(f"**Potential Impact:** {potential_impact}")
            if tech_str:
                desc_lines.append(f"**Technologies:** {tech_str}")
            if env_str:
                desc_lines.append(f"**Environments:** {env_str}")
            if brand:
                desc_lines.append(f"**Brand:** {brand}")
            if ticket_id:
                desc_lines.append(f"**Ticket:** {ticket_id}")
            description = "\n\n".join(desc_lines)

            # --- Vulnerability (when CVE is present) ---
            vuln_obj = None
            if cve_id:
                vuln_obj = stix2.Vulnerability(
                    id=pycti.Vulnerability.generate_id(cve_id),
                    name=cve_id,
                    description=(
                        f"Vulnerability {cve_id} detected by HackerView. "
                        f"Issue: {issue_name}. Severity: {severity}."
                    ),
                    created=first_seen,
                    modified=last_updated or first_seen,
                    created_by_ref=self.author.id,
                    external_references=[ext_ref],
                    custom_properties={
                        "x_opencti_score": score,
                        "source": "CTM360-HackerView",
                    },
                )
                objects.append(vuln_obj)
                issue_object_ids.append(vuln_obj.id)

            # --- System identity for affected asset ---
            system_name = host or domain or asset or resolved_ip
            system_id = None
            system = None
            if system_name:
                system_id = pycti.Identity.generate_id(
                    name=system_name, identity_class="system"
                )
                system = stix2.Identity(
                    id=system_id,
                    name=system_name,
                    identity_class="system",
                    description=f"HackerView asset: {system_name}"
                    + (f" ({asset_type})" if asset_type else ""),
                    created_by_ref=self.author.id,
                )
                objects.append(system)
                issue_object_ids.append(system_id)

                # System --has--> Vulnerability
                if vuln_obj:
                    objects.append(
                        stix2.Relationship(
                            id=pycti.StixCoreRelationship.generate_id(
                                relationship_type="has",
                                source_ref=system_id,
                                target_ref=vuln_obj.id,
                            ),
                            relationship_type="has",
                            source_ref=system_id,
                            target_ref=vuln_obj.id,
                            created_by_ref=self.author.id,
                        )
                    )

            # --- Note with full issue details ---
            note_refs = [self.author.id]
            if vuln_obj:
                note_refs.append(vuln_obj.id)
            if system_id:
                note_refs.append(system_id)

            # Seed the Note id from the stable ticket id (not the mutable
            # description, which changes with status/progress) so re-imports
            # update the same Note instead of creating duplicates.
            note_id = pycti.Note.generate_id(
                created=None, content=f"ctm360-hackerview-issue-note-{issue_id}"
            )
            note = stix2.Note(
                id=note_id,
                content=description,
                created=first_seen,
                modified=last_updated or first_seen,
                created_by_ref=self.author.id,
                external_references=[ext_ref],
                object_refs=note_refs,
                custom_properties={
                    "x_opencti_score": score,
                },
            )
            objects.append(note)
            issue_object_ids.append(note.id)

            # --- AttackPattern from CWE IDs ---
            cwe_raw_list = issue.get("cwe", [])
            if isinstance(cwe_raw_list, list):
                for cwe_item in cwe_raw_list:
                    cwe_id_val = (
                        cwe_item.get("cwe_id", "")
                        if isinstance(cwe_item, dict)
                        else str(cwe_item)
                    )
                    cwe_detail = (
                        cwe_item.get("cwe_detail", "")
                        if isinstance(cwe_item, dict)
                        else ""
                    )
                    if not cwe_id_val:
                        continue

                    attack_id = pycti.AttackPattern.generate_id(
                        name=cwe_id_val, x_mitre_id=cwe_id_val
                    )
                    attack_pattern = stix2.AttackPattern(
                        id=attack_id,
                        name=cwe_id_val,
                        description=cwe_detail or f"Weakness {cwe_id_val}",
                        created_by_ref=self.author.id,
                        external_references=[
                            stix2.ExternalReference(
                                source_name="cwe",
                                external_id=cwe_id_val,
                                url=f"https://cwe.mitre.org/data/definitions/{cwe_id_val.replace('CWE-', '')}.html",
                            )
                        ],
                    )
                    objects.append(attack_pattern)
                    issue_object_ids.append(attack_id)

                    # Vulnerability --related-to--> AttackPattern
                    if vuln_obj:
                        objects.append(
                            stix2.Relationship(
                                id=pycti.StixCoreRelationship.generate_id(
                                    relationship_type="related-to",
                                    source_ref=vuln_obj.id,
                                    target_ref=attack_id,
                                ),
                                relationship_type="related-to",
                                source_ref=vuln_obj.id,
                                target_ref=attack_id,
                                created_by_ref=self.author.id,
                            )
                        )

            # --- Software from technologies ---
            if isinstance(technologies, list):
                for tech in technologies:
                    if not tech:
                        continue
                    tech_name = str(tech).strip()
                    # stix2 derives a deterministic SCO id from `name`, so the
                    # same technology reuses the same Software id across runs.
                    software = stix2.Software(name=tech_name)
                    objects.append(software)
                    issue_object_ids.append(software.id)

                    # System --related-to--> Software
                    if system_name and system_id:
                        objects.append(
                            stix2.Relationship(
                                id=pycti.StixCoreRelationship.generate_id(
                                    relationship_type="related-to",
                                    source_ref=system_id,
                                    target_ref=software.id,
                                ),
                                relationship_type="related-to",
                                source_ref=system_id,
                                target_ref=software.id,
                                created_by_ref=self.author.id,
                            )
                        )

            # Build case name: issue_name - asset [ticket_id]
            case_name = (
                f"{issue_name} - {asset} [{issue_id}]"
                if asset
                else f"{issue_name} [{issue_id}]"
            )

            # Build labels (no severity)
            discovery_source = issue.get("discovery_source", "")
            # Combine status + progress_status into a single value used both for
            # the case's `status:` label and for the status tracker's seed, so the
            # bundle label and the tracker stay in sync. If they diverged, the
            # tracker would try to remove a `status:` label that never existed on
            # the case (the tracker maintains the combined form) and leak the
            # original `status:` label on the first detected change.
            effective_status = (
                f"{str(status).lower()}:{str(progress_status).lower()}"
                if progress_status
                else str(status).lower()
            )
            case_labels = ["ctm360-hackerview"]
            if status and str(status).lower() != "unknown":
                case_labels.append(f"status:{effective_status}")
            self._add_list_labels(case_labels, issue_type)
            self._add_list_labels(case_labels, issue.get("issue_category", []))
            self._add_list_labels(case_labels, technologies)
            if brand:
                case_labels.append(f"Brand:{brand}")
            if discovery_source:
                case_labels.append(f"Source:{discovery_source}")
            # CWE labels
            cwe_raw = issue.get("cwe", [])
            if isinstance(cwe_raw, list):
                for cwe_item in cwe_raw:
                    if isinstance(cwe_item, dict):
                        cwe_id_val = cwe_item.get("cwe_id", "")
                        if cwe_id_val:
                            case_labels.append(cwe_id_val.lower())
                    elif cwe_item:
                        case_labels.append(str(cwe_item).lower())
            elif cwe_raw:
                case_labels.append(str(cwe_raw).lower())
            if cve_id:
                case_labels.append(cve_id.lower())
            self._add_list_labels(case_labels, issue.get("potential_attack_type", []))
            self._add_list_labels(case_labels, issue.get("potential_impact", []))

            # --- CaseIncident (shipped in the bundle, never via the API) ---
            case_id = pycti.CaseIncident.generate_id(name=case_name, created=first_seen)
            case_kwargs = {
                "id": case_id,
                "name": case_name,
                "description": description,
                "severity": self._normalize_severity(severity),
                "priority": self._severity_to_priority(severity),
                "created": first_seen,
                "created_by_ref": self.author.id,
                "labels": case_labels,
                "external_references": [ext_ref],
                "object_refs": issue_object_ids,
            }
            response_types = [self._format_list_field(issue_type)] if issue_type else []
            if response_types:
                case_kwargs["response_types"] = response_types
            objects.append(CustomObjectCaseIncident(**case_kwargs))

            # The deterministic case id and the issue's current status are kept
            # so the background status tracker can reflect later status changes
            # onto the case shipped in the bundle (no API creation needed). The
            # tracker is seeded with the exact same `effective_status` value that
            # backs the `status:` label above, so the first poll cycle treats an
            # unchanged status as a no-op and a change targets the real label.
            self.issue_case_metadata.append(
                {
                    "ticket_id": str(issue_id),
                    "case_incident_id": case_id,
                    "initial_status": effective_status,
                }
            )

        return objects

    def resolved_issues_to_stix(self, issues: list) -> list:
        """Convert resolved issues to STIX objects.

        Resolved issues follow the same structure as active issues but are
        marked with resolved labels.
        """
        objects = [self.author]
        for raw_issue in issues:
            issue = self._flatten_issue(raw_issue)
            issue_id = issue.get("ticket_id", "")
            issue_name = issue.get("issue_name", "Unknown resolved issue")
            severity = issue.get("severity", "medium")
            cve_id = issue.get("cve_id", "")
            domain = issue.get("domain", "")
            host = issue.get("host", "")
            resolved_ip = issue.get("resolved_ip", "")
            hackerview_link = issue.get("hackerview_link", "")
            first_seen = normalize_timestamp(issue.get("first_seen"))
            last_updated = normalize_timestamp(issue.get("last_updated"))

            if not issue_id:
                self.helper.connector_logger.warning(
                    "[CONVERTER] Skipping resolved issue with no ticket_id",
                    {"issue_name": issue_name},
                )
                continue

            score = self._severity_to_score(severity)
            ext_ref = self._ext_ref(
                "CTM360-HackerView", str(issue_id), url=hackerview_link or None
            )

            # --- Vulnerability (when CVE is present) ---
            vuln_obj = None
            if cve_id:
                vuln_obj = stix2.Vulnerability(
                    id=pycti.Vulnerability.generate_id(cve_id),
                    name=cve_id,
                    description=(
                        f"Resolved vulnerability {cve_id} from CTM360 HackerView. "
                        f"Issue: {issue_name}. Severity: {severity}."
                    ),
                    created=first_seen,
                    modified=last_updated or first_seen,
                    created_by_ref=self.author.id,
                    external_references=[ext_ref],
                    labels=["resolved"],
                    custom_properties={
                        "x_opencti_score": max(score - 20, 0),
                        "source": "CTM360-HackerView",
                    },
                )
                objects.append(vuln_obj)

            # --- System identity for affected asset ---
            # Include resolved_ip in the name fallback so an IP-only resolved
            # issue keeps a unique identity; generating the id from an empty
            # name would collapse all such assets into one System.
            system_name = host or domain or resolved_ip
            if system_name:
                system_id = pycti.Identity.generate_id(
                    name=system_name, identity_class="system"
                )
                system_desc = f"HackerView asset: {system_name}"
                if resolved_ip and resolved_ip != system_name:
                    system_desc += f" ({resolved_ip})"
                system = stix2.Identity(
                    id=system_id,
                    name=system_name,
                    identity_class="system",
                    description=system_desc,
                    created_by_ref=self.author.id,
                )
                objects.append(system)
                if vuln_obj:
                    objects.append(
                        stix2.Relationship(
                            id=pycti.StixCoreRelationship.generate_id(
                                relationship_type="has",
                                source_ref=system_id,
                                target_ref=vuln_obj.id,
                            ),
                            relationship_type="has",
                            source_ref=system_id,
                            target_ref=vuln_obj.id,
                            created_by_ref=self.author.id,
                        )
                    )

            # --- Note for resolved issue ---
            note_content = (
                f"Resolved HackerView issue: {issue_name}. "
                f"Severity: {severity}. CVE: {cve_id or 'N/A'}."
            )
            # Stable Note id keyed on the ticket id (not the mutable content)
            # so re-imports don't create duplicate resolved-issue notes.
            note_id = pycti.Note.generate_id(
                created=None, content=f"ctm360-hackerview-resolved-note-{issue_id}"
            )
            note = stix2.Note(
                id=note_id,
                content=note_content,
                created=first_seen,
                modified=last_updated or first_seen,
                created_by_ref=self.author.id,
                external_references=[ext_ref],
                object_refs=[self.author.id],
                labels=["resolved"],
                custom_properties={
                    "x_opencti_score": max(score - 20, 0),
                },
            )
            objects.append(note)

        return objects

    def domain_assets_to_stix(self, assets: list) -> list:
        """Convert domain assets to System identities."""
        objects = [self.author]
        for asset in assets:
            domain = asset.get("domain", "") if isinstance(asset, dict) else str(asset)
            if not domain:
                continue
            system_id = pycti.Identity.generate_id(name=domain, identity_class="system")
            system = stix2.Identity(
                id=system_id,
                name=domain,
                identity_class="system",
                description=f"CTM360 HackerView genuine domain asset: {domain}",
                created_by_ref=self.author.id,
            )
            objects.append(system)
        return objects

    def host_assets_to_stix(self, assets: list) -> list:
        """Convert hostname assets to System identities."""
        objects = [self.author]
        for asset in assets:
            host = asset.get("host", "") if isinstance(asset, dict) else str(asset)
            if not host:
                continue
            system_id = pycti.Identity.generate_id(name=host, identity_class="system")
            system = stix2.Identity(
                id=system_id,
                name=host,
                identity_class="system",
                description=f"CTM360 HackerView genuine hostname asset: {host}",
                created_by_ref=self.author.id,
            )
            objects.append(system)
        return objects

    def ip_assets_to_stix(self, assets: list) -> list:
        """Convert IP address assets to System identities."""
        objects = [self.author]
        for asset in assets:
            ip_val = (
                asset.get("ip_address", "") if isinstance(asset, dict) else str(asset)
            )
            if not ip_val:
                continue
            system_id = pycti.Identity.generate_id(name=ip_val, identity_class="system")
            system = stix2.Identity(
                id=system_id,
                name=ip_val,
                identity_class="system",
                description=f"CTM360 HackerView IP address asset: {ip_val}",
                created_by_ref=self.author.id,
            )
            objects.append(system)
        return objects
