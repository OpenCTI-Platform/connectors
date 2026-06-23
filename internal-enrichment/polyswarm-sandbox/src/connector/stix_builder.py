"""
STIX Builder for PolySwarm Connector
Complete implementation with malware profile mapping and separate notes
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import requests
from connectors_sdk.models import OrganizationAuthor
from pycti import (
    AttackPattern,
    Identity,
    Indicator,
    Location,
    Malware,
    Note,
    StixCoreRelationship,
    ThreatActor,
    Vulnerability,
)

if TYPE_CHECKING:
    from pycti import OpenCTIConnectorHelper

try:
    from connector.ttp_mapping import MITRE_KILL_CHAIN, get_ttp_info
except ImportError:
    TTP_DATABASE = {}
    MITRE_KILL_CHAIN = "mitre-attack"

    def get_ttp_info(ttp_id: str) -> dict:  # type: ignore[misc]
        return {
            "name": f"ATT&CK Technique {ttp_id}",
            "tactic": "unknown",
            "description": "",
        }


# PROD-17: Import SandboxProcessor's benign-domain filter to avoid duplicate lists
try:
    from connector.sandbox_processor import SandboxProcessor as _Sp

    _is_benign_domain = _Sp._is_benign_domain
except ImportError:

    def _is_benign_domain(domain: str) -> bool:
        if not domain:
            return True
        benign = {
            "microsoft.com",
            "windowsupdate.com",
            "windows.com",
            "digicert.com",
            "verisign.com",
            "symantec.com",
            "akamai",
            ".arpa",
            "live.com",
            "office.com",
        }
        return any(b in domain.lower() for b in benign)


SOFTWARE_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


class StixBuilder:
    """Builds STIX 2.1 bundles from PolySwarm scan and sandbox results with full profile enrichment."""

    OBSERVABLE_DESCRIPTION = (
        "Communication was observed. The Entity may or may NOT be malicious."
    )

    # polykg circuit breaker — cool down 5 min after a connection failure
    _POLYKG_CIRCUIT_OPEN: bool = False
    _POLYKG_CIRCUIT_OPENED_AT: float | None = None
    _POLYKG_CIRCUIT_COOLDOWN: float = 300.0

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        polykg_api_url: str | None = None,
        polyswarm_api_key: str | None = None,
    ) -> None:
        self.helper = helper
        self._polykg_api_url = polykg_api_url
        self._polyswarm_api_key = polyswarm_api_key
        self._now = (
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        )
        self.author = self._create_author()
        self.author_id = self.author["id"]

        # Statement marking
        self.statement_marking = self._create_statement_marking()

        # Profile cache (polykg results)
        self._profile_cache: dict = {}

        # Caches
        self._actor_cache: dict[str, dict] = {}
        self._location_cache: dict[str, dict] = {}
        self._sector_cache: dict[str, dict] = {}
        self._vulnerability_cache: dict[str, dict] = {}
        self._malware_cache: dict[str, dict] = {}
        self._software_cache: dict[str, dict] = {}
        self._intrusion_set_cache: dict[str, dict] = {}
        self._enrichment_depth = 0
        self._max_enrichment_depth = 2

    @staticmethod
    def _cfg(config, key: str, default=None) -> object:
        """Access config value — works with both Pydantic ConnectorSettings and plain dicts."""
        if hasattr(config, "polyswarm"):
            return getattr(config.polyswarm, key, default)
        if isinstance(config, dict):
            return config.get(key, default)
        return default

    def _create_author(self) -> dict:
        """Create Author (Organization Identity) as plain dict."""
        sdk_author = OrganizationAuthor(
            name="PolySwarm_Malware_Threat_Intelligence",
            description="PolySwarm is a next-generation Malware Intelligence Platform combining "
            "the speed of crowdsourced detection with the rigor of enterprise security.",
        )
        return json.loads(sdk_author.to_stix2_object().serialize())

    def _author_props(self) -> dict:
        """Return author reference dict for use in STIX object creation."""
        return dict(created_by_ref=self.author_id)

    @staticmethod
    def _create_statement_marking() -> dict:
        """TLP:CLEAR-equivalent statement marking for PolySwarm content."""
        return {
            "type": "marking-definition",
            "spec_version": "2.1",
            "id": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
            "created": "2017-01-20T00:00:00.000Z",
            "definition_type": "statement",
            "definition": {
                "statement": "Copyright 2024, PolySwarm. All rights reserved."
            },
        }

    def _fetch_polykg_profile(self, family_name: str) -> dict | None:
        """Fetch a malware family profile from the polykg REST API.

        Replaces the old disk-based MalwareProfileLoader with a live API call.
        Includes circuit breaker to avoid hammering polykg on connection failures.
        Results are cached per-enrichment via _profile_cache.
        """
        import time as _time  # local import to keep module-level imports clean

        if not self._polykg_api_url or not family_name:
            return None

        # Check cache first
        cache_key = family_name.lower().strip()
        if cache_key in self._profile_cache:
            return self._profile_cache[cache_key]

        # Circuit breaker — skip if recently failed
        if self._POLYKG_CIRCUIT_OPEN:
            elapsed = _time.time() - (self._POLYKG_CIRCUIT_OPENED_AT or 0)
            if elapsed < self._POLYKG_CIRCUIT_COOLDOWN:
                return None
            StixBuilder._POLYKG_CIRCUIT_OPEN = False
            StixBuilder._POLYKG_CIRCUIT_OPENED_AT = None

        try:
            headers: dict = {}
            if self._polyswarm_api_key:
                headers["Authorization"] = f"Bearer {self._polyswarm_api_key}"

            resp = requests.post(
                f"{self._polykg_api_url.rstrip('/')}/v3/kg/profile",
                json={"family_name": family_name},
                headers=headers,
                timeout=10,
            )
            if resp.status_code == 200:
                profile = resp.json()
                self._profile_cache[cache_key] = profile
                return profile
            if resp.status_code in (401, 403):
                self.helper.connector_logger.warning(
                    f"[STIX] polykg auth error {resp.status_code} for {family_name}"
                )
                return None
            self.helper.connector_logger.warning(
                f"[STIX] polykg returned {resp.status_code} for {family_name}"
            )
            return None

        except requests.ConnectionError as exc:
            self.helper.connector_logger.warning(
                f"[STIX] polykg connection failed, opening circuit: {exc}"
            )
            StixBuilder._POLYKG_CIRCUIT_OPEN = True
            StixBuilder._POLYKG_CIRCUIT_OPENED_AT = _time.time()
            return None
        except requests.RequestException as exc:
            self.helper.connector_logger.warning(
                f"[STIX] polykg profile fetch failed for {family_name}: {exc}"
            )
            return None

    @staticmethod
    def _to_bool(value) -> bool:
        """Parse boolean from env var string or Python bool."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() not in ("false", "0", "no", "off", "")
        return bool(value)

    @staticmethod
    def _note_id(entity_id: str, note_type: str) -> str:
        """Deterministic Note ID keyed to entity + note type.

        Fixes issue #37 — uuid4() created duplicate Notes on re-enrichment.
        Using Note.generate_id() ensures OpenCTI upserts instead of inserting.
        """
        stable = f"polyswarm-sandbox:{entity_id}:{note_type}"
        return Note.generate_id(created=None, content=stable)

    def build_bundle(
        self,
        entity: dict,
        scan_data: dict | None = None,
        sandbox_data: dict | None = None,
        sandbox_results: dict | None = None,
        sandbox_failures: dict | None = None,
        llm_reports: dict | None = None,
        config: dict | None = None,
    ) -> list[dict]:
        """
        Build complete STIX bundle from scan and sandbox results.

        Args:
            entity: The file entity being enriched
            scan_data: Processed scan results from ScanProcessor
            sandbox_data: Merged sandbox results (for backward compatibility)
            sandbox_results: Dict of individual sandbox results keyed by provider (triage, cape)
            sandbox_failures: Dict of failed sandbox results keyed by provider
            llm_reports: Dict of LLM report texts keyed by source ('scan', 'triage', 'cape')
            config: Configuration options
        """
        objects = []
        config = config or {}
        sandbox_results = sandbox_results or {}

        sandbox_failures = sandbox_failures or {}
        llm_reports = llm_reports or {}

        # Backward compat: if sandbox_data passed but sandbox_results empty,
        # auto-detect provider and populate sandbox_results
        if sandbox_data and not sandbox_results:
            provider = sandbox_data.get("provider", "").lower()
            if provider in ("triage", "cape"):
                sandbox_results = {provider: sandbox_data}
            elif sandbox_data.get("triage_behavioral_score") is not None:
                sandbox_results = {"triage": sandbox_data}
            elif sandbox_data.get("cape_malscore") is not None:
                sandbox_results = {"cape": sandbox_data}
            else:
                sandbox_results = {"sandbox": sandbox_data}

        self._clear_caches()
        entity = self._normalize_entity(entity)

        objects.append(self.author)

        # Calculate scores — from scan + best per-provider sandbox score
        s_score = (scan_data or {}).get("score", 0)
        b_score = max(
            (r.get("score", 0) for r in sandbox_results.values() if r),
            default=0,
        )
        score = max(s_score, b_score)

        # Get family — prefer highest-scoring sandbox provider, fallback to scan
        family = None
        best_sb_score = 0
        for _prov, result in sandbox_results.items():
            if result:
                prov_family = result.get("family")
                prov_score = result.get("score", 0)
                if (
                    prov_family
                    and str(prov_family).lower() not in ("unknown", "none", "")
                    and prov_score >= best_sb_score
                ):
                    family = prov_family
                    best_sb_score = prov_score
        if not family:
            family = (scan_data or {}).get("family")
        if family and str(family).lower() in ("unknown", "none"):
            family = None

        # Load profile
        profile = None
        if family:
            profile = self._fetch_polykg_profile(family)
            if profile:
                self.helper.connector_logger.info(f"[STIX] Loaded profile for {family}")

        # Build external refs
        external_refs = self._build_external_refs(
            scan_data, None, sandbox_results=sandbox_results
        )
        basic_labels = self._collect_labels(
            scan_data, None, profile, sandbox_results=sandbox_results
        )
        comprehensive_labels = self._collect_labels(
            scan_data,
            None,
            profile,
            comprehensive=True,
            sandbox_results=sandbox_results,
        )

        # === CREATE MALWARE WITH FULL ENRICHMENT ===
        malware_id = None
        if family:
            malware_obj, additional_objs, relationships = (
                self._create_malware_with_enrichment(
                    family,
                    score,
                    external_refs,
                    basic_labels,
                    scan_data,
                    sandbox_data,
                    profile,
                )
            )
            if malware_obj:
                objects.append(malware_obj)
                objects.extend(additional_objs)
                objects.extend(relationships)
                malware_id = malware_obj["id"]
                self._malware_cache[family.lower()] = malware_obj
                objects.append(self._create_rel(entity["id"], "related-to", malware_id))

        # === CREATE SEPARATE NOTES (to get IDs for indicator) ===
        # NOTE: OpenCTI displays notes in reverse insertion order (last-in appears first).
        # We add notes in REVERSE of desired display order so they render correctly.
        # Desired display: Scan → Triage → Cape → Threat Intel → Failures
        # Bundle order:    Failures → Threat Intel → Cape → Triage → Scan
        note_ids = []
        scan_note_id = None  # tracked separately — only this goes on the indicator

        # Resolve sandbox results for note creation (per-provider, no merge)
        triage_result = sandbox_results.get("triage")
        cape_result = sandbox_results.get("cape")

        # 5. Sandbox Failure Notes (added first → displayed last)
        for provider, failure_info in sandbox_failures.items():
            failure_note = self._create_sandbox_failure_note(
                entity, provider, failure_info
            )
            if failure_note:
                objects.append(failure_note)
                note_ids.append(failure_note["id"])

        # 4. Extended Threat Intelligence Note (from profile)
        if profile:
            intel_note = self._create_threat_intel_note(entity, profile, family)
            if intel_note:
                objects.append(intel_note)
                note_ids.append(intel_note["id"])

        # 3. Cape Sandbox Note (with AI summary if available)
        if cape_result:
            cape_note = self._create_cape_sandbox_note(
                entity, cape_result, llm_report=llm_reports.get("cape")
            )
            if cape_note:
                objects.append(cape_note)
                note_ids.append(cape_note["id"])

        # 2. Triage Sandbox Note (with AI summary if available)
        if triage_result:
            triage_note = self._create_triage_sandbox_note(
                entity, triage_result, llm_report=llm_reports.get("triage")
            )
            if triage_note:
                objects.append(triage_note)
                note_ids.append(triage_note["id"])

        # 1. Scan Summary Note (added last → displayed first)
        scan_note = self._create_scan_summary_note(
            entity, scan_data, score, llm_report=llm_reports.get("scan")
        )
        if scan_note:
            objects.append(scan_note)
            note_ids.append(scan_note["id"])
            scan_note_id = scan_note["id"]

        # === CREATE INDICATOR (with note references) ===
        indicator_obj = None
        related_malware_objs = []
        min_score = self._cfg(config, "min_polyscore", 50)
        create_indicators = self._cfg(config, "create_indicators", True)
        if create_indicators and score >= min_score:
            indicator_obj, indicator_rels = self._create_indicator_enhanced(
                entity,
                score,
                external_refs,
                comprehensive_labels,
                malware_id,
                profile,
                scan_data,
                sandbox_data,
                note_ids=[scan_note_id] if scan_note_id else [],
            )
            if indicator_obj:
                objects.append(indicator_obj)
                objects.extend(indicator_rels)

                # Update all notes to also reference the indicator
                # This copies the notes to the indicator
                indicator_id = indicator_obj["id"]
                for obj in objects:
                    if obj.get("type") == "note" and obj.get("id") in note_ids:
                        current_refs = obj.get("object_refs", [])
                        if indicator_id not in current_refs:
                            obj["object_refs"] = current_refs + [indicator_id]

                # Add related malware objects created during indicator creation
                if profile and profile.get("related_malware"):
                    for related_name in profile["related_malware"]:
                        related_obj = self._malware_cache.get(related_name.lower())
                        if related_obj and related_obj not in objects:
                            objects.append(related_obj)
                            related_malware_objs.append(related_obj)

        # === CREATE THREAT ACTOR RELATIONSHIPS TO RELATED MALWARE ===
        if profile and profile.get("actors") and related_malware_objs:
            for actor_name in profile["actors"]:
                actor_obj = self._actor_cache.get(actor_name.lower())
                if actor_obj:
                    for related_obj in related_malware_objs:
                        objects.append(
                            self._create_rel(
                                actor_obj["id"],
                                "uses",
                                related_obj["id"],
                                f"Threat actor {actor_name} may use related malware",
                            )
                        )

        # === UPDATE ARTIFACT ===
        # Collect individual raw scores for the description breakdown
        score_details = {}
        if scan_data:
            raw_ps = scan_data.get("raw_polyscore", 0)
            score_details["polyscore"] = {"raw": raw_ps, "converted": s_score}
        for prov, result in sandbox_results.items():
            if result:
                if prov == "triage":
                    raw = max(
                        result.get("triage_behavioral_score", 0),
                        result.get("triage_static_score", 0),
                        result.get("triage_sandbox_score", 0),
                    )
                    score_details["triage"] = {
                        "raw": raw,
                        "converted": result.get("score", 0),
                    }
                elif prov == "cape":
                    raw = result.get("cape_malscore", 0)
                    score_details["cape"] = {
                        "raw": raw,
                        "converted": result.get("score", 0),
                    }

        artifact_update = self._create_entity_update_enhanced(
            entity,
            score,
            external_refs,
            comprehensive_labels,
            config=config,
            score_details=score_details,
        )
        objects.append(artifact_update)

        # === ATTACK PATTERNS (deduped across all sandbox providers) ===
        all_ttps = set()
        for _prov, result in sandbox_results.items():
            if result and result.get("ttps"):
                all_ttps.update(result["ttps"])

        if all_ttps:
            indicator_id = indicator_obj["id"] if indicator_obj else None
            ttp_objs = self._create_attack_patterns_enhanced(
                list(all_ttps), malware_id, indicator_id, entity["id"]
            )
            objects.extend(ttp_objs)

        # === NETWORK OBSERVABLES (deduped across all sandbox providers) ===
        create_observables = self._cfg(config, "create_observables", True)
        if create_observables:
            # Collect and dedup IOCs from all providers before creating STIX objects
            deduped_domains: list = []
            deduped_ips: list = []
            deduped_c2: list = []
            seen_domains: set = set()
            seen_ips: set = set()

            for _prov, result in sandbox_results.items():
                if not result:
                    continue
                for d in result.get("domains", []):
                    key = d.get("domain", "") if isinstance(d, dict) else str(d)
                    if key and key not in seen_domains:
                        seen_domains.add(key)
                        deduped_domains.append(d)
                for ip in result.get("ips", []):
                    ip_str = ip if isinstance(ip, str) else str(ip)
                    if ip_str and ip_str not in seen_ips:
                        seen_ips.add(ip_str)
                        deduped_ips.append(ip)
                for c2 in result.get("c2_candidates", []):
                    c2_key = f"{c2.get('ip', '')}:{c2.get('port', '')}"
                    if c2_key and c2_key not in seen_ips:
                        seen_ips.add(c2_key)
                        deduped_c2.append(c2)

            # Build a single deduped IOC dict and create observables in one pass
            if deduped_domains or deduped_ips or deduped_c2:
                deduped_ioc_data = {
                    "domains": deduped_domains,
                    "ips": deduped_ips,
                    "c2_candidates": deduped_c2,
                }
                ioc_objs = self._create_network_observables(
                    deduped_ioc_data, entity, malware_id
                )
                objects.extend(ioc_objs)

        # Deduplicate
        seen_ids = set()
        unique_objects = []
        for obj in objects:
            if obj.get("id") not in seen_ids:
                seen_ids.add(obj["id"])
                unique_objects.append(obj)

        # Sort: all entities/observables first, then relationships last.
        # OpenCTI worker imports in order — relationships fail with
        # MISSING_REFERENCE_ERROR if the referenced objects don't exist yet.
        # Fine-grained ordering ensures proper dependency resolution,
        # especially when send_stix2_bundle splits into multiple sub-bundles.
        _type_order = {
            "identity": 0,
            "location": 1,
            "marking-definition": 1,
            "malware": 2,
            "intrusion-set": 2,
            "threat-actor": 2,
            "tool": 2,
            "vulnerability": 2,
            "campaign": 2,
            "attack-pattern": 3,
            "domain-name": 4,
            "ipv4-addr": 4,
            "ipv6-addr": 4,
            "url": 4,
            "email-addr": 4,
            "artifact": 5,
            "file": 5,
            "indicator": 5,
            "note": 6,
            "report": 6,
            "opinion": 6,
            "relationship": 7,
            "sighting": 7,
        }
        unique_objects.sort(key=lambda o: _type_order.get(o.get("type", ""), 5))
        return unique_objects

    def _clear_caches(self) -> None:
        self._actor_cache = {}
        self._location_cache = {}
        self._sector_cache = {}
        self._vulnerability_cache = {}
        self._malware_cache = {}
        self._software_cache = {}
        self._intrusion_set_cache = {}
        self._enrichment_depth = 0
        # BUG-1 fix: refresh timestamp each enrichment run (connector is long-lived daemon)
        self._now = (
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        )

    def _normalize_entity(self, entity: dict) -> dict:
        normalized = dict(entity)
        if not normalized.get("hashes") and normalized.get("observable_value"):
            obs_val = normalized["observable_value"]
            hashes = {}
            if len(obs_val) == 32 and all(
                c in "0123456789abcdefABCDEF" for c in obs_val
            ):
                hashes["MD5"] = obs_val
            elif len(obs_val) == 40 and all(
                c in "0123456789abcdefABCDEF" for c in obs_val
            ):
                hashes["SHA-1"] = obs_val
            elif len(obs_val) == 64 and all(
                c in "0123456789abcdefABCDEF" for c in obs_val
            ):
                hashes["SHA-256"] = obs_val
            if hashes:
                normalized["hashes"] = hashes
        return normalized

    def _build_external_refs(
        self,
        scan_data: dict | None,
        sandbox_data: dict | None,
        sandbox_results: dict | None = None,
    ) -> list[dict]:
        refs = []
        if scan_data and scan_data.get("permalink"):
            refs.append(
                {
                    "source_name": "PolySwarm Scan Report",
                    "url": scan_data["permalink"],
                    "description": "View detailed PolySwarm scan analysis",
                }
            )
        # Per-provider sandbox permalinks
        if sandbox_results:
            for provider, result in sandbox_results.items():
                if result and result.get("permalink"):
                    refs.append(
                        {
                            "source_name": f"PolySwarm {provider.capitalize()} Sandbox Report",
                            "url": result["permalink"],
                            "description": f"View detailed {provider.capitalize()} sandbox analysis",
                        }
                    )
        elif sandbox_data and sandbox_data.get("permalink"):
            refs.append(
                {
                    "source_name": "PolySwarm Sandbox Report",
                    "url": sandbox_data["permalink"],
                    "description": "View detailed PolySwarm sandbox analysis",
                }
            )
        return refs

    def _collect_labels(
        self,
        scan_data: dict | None,
        sandbox_data: dict | None,
        profile: dict | None = None,
        comprehensive: bool = False,
        sandbox_results: dict | None = None,
    ) -> list[str]:
        """
        Collect labels for STIX objects.
        When comprehensive=True, includes extended profile labels
        (threat actors, target countries, CVEs).

        Label policy:
        - No MITRE labels (TTPs are represented as AttackPattern STIX objects)
        - No signature labels (vendor-specific noise, included in Note content)
        - No behavior labels (generic sandbox tags, details in Notes)
        - Family labels prefixed with provider name (e.g. cape_malware_family:WannaCry)
        """
        labels = set()
        if scan_data:
            family = scan_data.get("family")
            if family and family != "Unknown":
                labels.add(f"PolyUnite:{family}")
            for lbl in scan_data.get("labels", []):
                labels.add(f"malware_type:{lbl.lower()}")
            for os_name in scan_data.get("operating_systems", []):
                labels.add(f"os_type:{os_name.lower()}")
            labels.add(f"polyscore:{scan_data.get('score', 0)}")

        # Provider-specific family labels from individual sandbox results
        # e.g. cape_malware_family:WannaCry, triage_malware_family:Emotet
        if sandbox_results:
            for provider, result in sandbox_results.items():
                if result:
                    sb_family = result.get("family")
                    if sb_family and str(sb_family).lower() not in (
                        "unknown",
                        "none",
                        "",
                    ):
                        labels.add(f"{provider}_malware_family:{sb_family}")
        if profile:
            for lang in profile.get("programming_languages", []):
                labels.add(f"language:{lang.lower().replace(' ', '-')}")
            if comprehensive:
                for mtype in profile.get("malware_type", []):
                    labels.add(f"malware_type:{mtype.lower().replace(' ', '-')}")
                for actor in profile.get("actors", []):
                    labels.add(f"threat_actor:{actor.lower().replace(' ', '-')}")
                for loc in profile.get("target_locations", []):
                    labels.add(f"target_country:{loc.lower().replace(' ', '-')}")
                for sector in profile.get("verticals_targeted", []):
                    labels.add(f"target_sector:{sector.lower().replace(' ', '-')}")
                for cve in profile.get("target_cves", []):
                    labels.add(f"cve:{cve.upper()}")
        return list(labels)

    def _create_entity_update_enhanced(
        self,
        entity: dict,
        score: int,
        external_refs: list,
        labels: list,
        config: dict | None = None,
        score_details: dict | None = None,
    ) -> dict:
        update = {
            "type": entity.get("type", "file"),
            "spec_version": "2.1",
            "id": entity["id"],
        }
        if entity.get("hashes"):
            update["hashes"] = entity["hashes"]
        if entity.get("name"):
            update["name"] = entity["name"]
        # The entity being enriched here is a ``file`` SCO (or
        # equivalent ``entity.get("type", "file")`` SCO). Author goes
        # on ``x_opencti_created_by_ref``, not the SDO/SRO-only
        # ``created_by_ref`` property — same SCO contract as the
        # ``domain-name`` / ``ipv4-addr`` / ``url`` blocks below and
        # the corresponding sibling sites in ``polyswarm-enrichment``.
        # ``test_created_by_refs_valid`` (extended in this PR) pins
        # the SCO-vs-SDO/SRO author contract end-to-end so a future
        # refactor cannot silently regress it.
        update["x_opencti_created_by_ref"] = self.author_id

        # #39: replace_with_lower_score — protect higher existing scores
        replace = True
        replace_with_lower = self._cfg(config, "replace_with_lower_score", True)
        if config and not replace_with_lower:
            existing = entity.get("x_opencti_score")
            if existing is not None:
                try:
                    if int(existing) > score:
                        self.helper.connector_logger.info(
                            f"[STIX] Keeping existing score {existing} > {score}"
                        )
                        replace = False
                except (TypeError, ValueError):
                    pass
        if replace:
            update["x_opencti_score"] = score
        if labels:
            update["x_opencti_labels"] = labels
        if external_refs:
            update["external_references"] = external_refs
        # Build score breakdown description with per-provider raw scores
        # OpenCTI renders descriptions as markdown — use double-newline for paragraphs
        desc_lines = [f"PolySwarm analysis score: {score}%"]
        if score_details:
            if "polyscore" in score_details:
                desc_lines.append(f"PolyScore={score_details['polyscore']['raw']}")
            if "cape" in score_details:
                desc_lines.append(f"Cape Score={score_details['cape']['raw']}/10")
            if "triage" in score_details:
                desc_lines.append(f"Triage Score={score_details['triage']['raw']}/10")
        update["x_opencti_description"] = "\n".join(desc_lines)
        return update

    # ============= INDICATOR (name = SHA256 from scan_data) =============

    def _create_indicator_enhanced(
        self,
        entity: dict,
        score: int,
        external_refs: list,
        comprehensive_labels: list,
        malware_id: str | None,
        profile: dict | None,
        scan_data: dict | None,
        sandbox_data: dict | None,
        note_ids: list | None = None,
    ) -> tuple[dict | None, list[dict]]:
        # Get SHA256 from scan_data first (preferred), fallback to entity
        sha256 = None
        if scan_data:
            sha256 = scan_data.get("sha256") or scan_data.get("hashes", {}).get(
                "SHA-256"
            )
        if not sha256:
            sha256 = self._get_sha256(entity)

        if not sha256:
            return None, []

        pattern = f"[file:hashes.'SHA-256' = '{sha256}']"
        ind_id = Indicator.generate_id(pattern)

        desc_parts = []
        if scan_data and scan_data.get("detection_stats"):
            stats = scan_data["detection_stats"]
            desc_parts.append(
                f"PolySwarm Detection: {stats.get('malicious', 0)}/{stats.get('total', 0)}"
                " engines flagged as malicious."
            )
        desc_parts.append(f"PolySwarm Score: {score}%.")

        family = (sandbox_data or {}).get("family") or (scan_data or {}).get("family")
        if family and family != "Unknown":
            desc_parts.append(f"Malware Family: {family}.")

        if profile:
            if profile.get("description"):
                desc_parts.append(profile["description"])
            if profile.get("actors"):
                desc_parts.append(
                    f"Associated Threat Actors: {', '.join(profile['actors'])}."
                )
            if profile.get("related_malware"):
                desc_parts.append(
                    f"Related Malware: {', '.join(profile['related_malware'])}."
                )
            if profile.get("target_locations"):
                desc_parts.append(
                    f"Target Countries: {', '.join(profile['target_locations'][:5])}."
                )
            if profile.get("verticals_targeted"):
                desc_parts.append(
                    f"Target Sectors: {', '.join(profile['verticals_targeted'][:5])}."
                )

        if sandbox_data and sandbox_data.get("ttps"):
            desc_parts.append(
                f"MITRE ATT&CK: {len(sandbox_data['ttps'])} techniques identified."
            )

        description = " ".join(desc_parts)

        all_external_refs = list(external_refs)
        if profile and profile.get("target_cves"):
            for cve in profile["target_cves"][:3]:
                all_external_refs.append(
                    {
                        "source_name": "cve",
                        "external_id": cve.upper(),
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve.upper()}",
                        "description": f"Exploited vulnerability: {cve}",
                    }
                )

        # INDICATOR NAME IS SHA256 FROM SCAN DATA
        indicator_name = sha256

        indicator = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "name": indicator_name,
            "description": description,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": self._now,
            "labels": comprehensive_labels,
            "confidence": 100,
            "x_opencti_score": score,
            "x_opencti_main_observable_type": "StixFile",
            "x_opencti_detection": score >= 50,
            "external_references": all_external_refs,
        }

        # Add note references to indicator
        if note_ids:
            indicator["object_refs"] = note_ids

        relationships = []
        if malware_id:
            relationships.append(
                self._create_rel(
                    ind_id,
                    "indicates",
                    malware_id,
                    "This indicator is associated with malware based on PolySwarm analysis",
                )
            )
        relationships.append(
            self._create_rel(
                ind_id,
                "based-on",
                entity["id"],
                "This indicator is based on the observed file hash",
            )
        )

        # Create relationships to related malware from profile
        if profile and profile.get("related_malware"):
            for related_name in profile["related_malware"]:
                related_malware_obj = self._create_related_malware(related_name)
                if related_malware_obj:
                    relationships.append(
                        self._create_rel(
                            ind_id,
                            "indicates",
                            related_malware_obj["id"],
                            f"This indicator may be related to {related_name}",
                        )
                    )

        return indicator, relationships

    def _create_related_malware(self, malware_name: str) -> dict | None:
        """Create a related malware object."""
        if not malware_name:
            return None

        malware_key = malware_name.lower()
        if malware_key in self._malware_cache:
            return self._malware_cache[malware_key]

        malware_id = Malware.generate_id(name=malware_name)
        malware_obj = {
            "type": "malware",
            "spec_version": "2.1",
            "id": malware_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "name": malware_name,
            "description": f"Related malware family: {malware_name}",
            "is_family": True,
            "confidence": 50,
        }
        self._malware_cache[malware_key] = malware_obj
        return malware_obj

    # ============= SEPARATE NOTES =============

    @staticmethod
    def _format_ai_summary_section(llm_report: str | dict | None) -> list[str]:
        """
        Parse LLM report JSON and format as markdown section.
        Renders: bottom_line, observations, recommended_actions.
        Returns list of content lines to insert into a note.

        The PolySwarm SDK returns the report already parsed as a dict; the S3
        download fallback returns a JSON string. Accept either.
        """
        if not llm_report:
            return []

        if isinstance(llm_report, dict):
            report_data = llm_report
        elif isinstance(llm_report, str):
            if not llm_report.strip():
                return []
            try:
                report_data = json.loads(llm_report)
            except (json.JSONDecodeError, TypeError):
                # If not valid JSON, treat as plain text
                return ["## AI Summary", llm_report.strip(), ""]
        else:
            return []

        if not isinstance(report_data, dict):
            return ["## AI Summary", str(report_data).strip(), ""]

        parts = ["## AI Summary\n"]

        def _to_str(val) -> str:
            """Safely convert API value (str or list) to string."""
            if isinstance(val, list):
                return "\n".join(str(item) for item in val)
            return str(val).strip() if val else ""

        bottom_line = _to_str(report_data.get("bottom_line", ""))
        if bottom_line:
            parts.append(f"**Bottom Line:** {bottom_line}")
            parts.append("")

        observations = _to_str(report_data.get("observations", ""))
        if observations:
            parts.append(f"**Observations:** {observations}")
            parts.append("")

        recommended_actions = _to_str(report_data.get("recommended_actions", ""))
        if recommended_actions:
            parts.append(f"**Recommended Actions:** {recommended_actions}")
            parts.append("")

        return parts

    def _create_scan_summary_note(
        self,
        entity: dict,
        scan_data: dict | None,
        score: int,
        llm_report: str | None = None,
    ) -> dict | None:
        """Create PolySwarm Scan Results note with hash info from scan_data['hashes']."""
        if not scan_data:
            return None

        content_parts = ["# PolySwarm Scan Results\n"]

        # Detection Summary
        if scan_data.get("detection_stats"):
            stats = scan_data["detection_stats"]
            polyscore = scan_data.get("raw_polyscore", scan_data.get("score", 0) / 100)
            content_parts.append("## Detection Summary")
            content_parts.append(
                f"- **Malicious:** {stats.get('malicious', 0)}/{stats.get('total', 0)} engines"
            )
            content_parts.append(
                f"- **Benign:** {stats.get('total', 0) - stats.get('malicious', 0)}/{stats.get('total', 0)} engines"
            )
            content_parts.append(f"- **PolyScore:** {polyscore:.4f}")
            content_parts.append("")

        # AI Summary (inserted right after score)
        ai_section = self._format_ai_summary_section(llm_report)
        if ai_section:
            content_parts.extend(ai_section)

        # Family from scan
        family = scan_data.get("family")
        if family and family != "Unknown":
            content_parts.append(f"## Malware Family\n- **PolyUnite:** {family}\n")

        # File Type Info
        extended_type = scan_data.get("extended_type")
        mimetype = scan_data.get("mimetype")
        if extended_type or mimetype:
            content_parts.append("## File Type")
            if extended_type:
                content_parts.append(f"- **Extended Type:** {extended_type}")
            if mimetype:
                content_parts.append(f"- **MIME Type:** {mimetype}")
            content_parts.append("")

        # First/Last Seen
        first_seen = scan_data.get("first_seen")
        last_seen = scan_data.get("last_seen")
        if first_seen or last_seen:
            content_parts.append("## Observation Timeline")
            if first_seen:
                content_parts.append(f"- **First Seen:** {first_seen}")
            if last_seen:
                content_parts.append(f"- **Last Seen:** {last_seen}")
            content_parts.append("")

        # Classification Labels (from polyunite)
        labels = scan_data.get("labels", [])
        if labels:
            content_parts.append("## Classification Labels")
            for lbl in labels:
                content_parts.append(f"- {lbl}")
            content_parts.append("")

        # Target Operating Systems (from polyunite)
        operating_systems = scan_data.get("operating_systems", [])
        if operating_systems:
            content_parts.append("## Target Operating Systems")
            for os_name in operating_systems:
                content_parts.append(f"- {os_name}")
            content_parts.append("")

        # Hash Information from scan_data['hashes'] (from metadata->tool:hash->tool_metadata)
        hashes = scan_data.get("hashes", {})
        if hashes:
            content_parts.append("## Hash Information")
            # Order hashes for readability
            hash_order = [
                "MD5",
                "SHA-1",
                "SHA-256",
                "SHA-512",
                "SHA3-256",
                "SHA3-512",
                "SSDEEP",
                "TLSH",
                "AUTHENTIHASH",
            ]
            for algo in hash_order:
                if algo in hashes:
                    content_parts.append(f"- **{algo}:** `{hashes[algo]}`")
            # Any remaining hashes not in the order list
            for algo, val in hashes.items():
                if algo not in hash_order:
                    content_parts.append(f"- **{algo}:** `{val}`")
            content_parts.append("")

        # External Reference
        ext_refs = []
        if scan_data.get("permalink"):
            ext_refs.append(
                {
                    "source_name": "PolySwarm Scan Report",
                    "url": scan_data["permalink"],
                    "description": "View detailed PolySwarm scan analysis",
                }
            )

        note_id = self._note_id(entity.get("id", ""), "scan-summary")
        note = {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "abstract": "PolySwarm Scan Results",
            "content": "\n".join(content_parts),
            "object_refs": [entity["id"]],
        }
        if ext_refs:
            note["external_references"] = ext_refs

        return note

    def _create_triage_sandbox_note(
        self, entity: dict, triage_result: dict, llm_report: str | None = None
    ) -> dict | None:
        """Create Triage Sandbox Analysis note."""
        if not triage_result:
            return None

        content_parts = ["# PolySwarm Triage Sandbox Analysis\n"]

        # Scores
        content_parts.append("## Analysis Scores")
        content_parts.append(
            f"- **Triage Behavioral Score:** {triage_result.get('triage_behavioral_score', 0)}/10"
        )
        content_parts.append(
            f"- **Triage Static Score:** {triage_result.get('triage_static_score', 0)}/10"
        )
        content_parts.append(
            f"- **Triage Sandbox Score:** {triage_result.get('triage_sandbox_score', 0)}/10"
        )
        content_parts.append("")

        # AI Summary (inserted right after scores)
        ai_section = self._format_ai_summary_section(llm_report)
        if ai_section:
            content_parts.extend(ai_section)

        # Family
        family = triage_result.get("family")
        if family:
            content_parts.append(f"## Malware Family\n- **Triage:** {family}\n")

        # Extracted Configuration
        extracted_configs = triage_result.get("extracted_configs", [])
        if extracted_configs:
            content_parts.append("## Extracted Configuration")
            for cfg in extracted_configs:
                if cfg.get("family"):
                    content_parts.append(f"- **Family:** {cfg['family']}")
                if cfg.get("version"):
                    content_parts.append(f"- **Version:** {cfg['version']}")
                if cfg.get("rule"):
                    content_parts.append(f"- **Rule:** {cfg['rule']}")
                if cfg.get("botnet"):
                    content_parts.append(f"- **Botnet:** {cfg['botnet']}")
                if cfg.get("c2"):
                    content_parts.append(f"- **C2 Servers:** {', '.join(cfg['c2'])}")
                if cfg.get("mutex"):
                    content_parts.append(f"- **Mutex:** {', '.join(cfg['mutex'])}")
                if cfg.get("keys"):
                    for key in cfg["keys"]:
                        key_name = key.get("key", "Key")
                        key_kind = key.get("kind", "")
                        key_value = key.get("value", "N/A")
                        if key_kind:
                            content_parts.append(
                                f"- **{key_name}** ({key_kind}): `{key_value}`"
                            )
                        else:
                            content_parts.append(f"- **{key_name}:** `{key_value}`")
                if cfg.get("attr"):
                    attr = cfg["attr"]
                    if attr.get("install_folder"):
                        content_parts.append(
                            f"- **Install Folder:** {attr['install_folder']}"
                        )
            content_parts.append("")

        # TTPs
        ttps = triage_result.get("ttps", [])
        if ttps:
            content_parts.append("## MITRE ATT&CK Techniques")
            for ttp in ttps[:15]:
                ttp_info = get_ttp_info(ttp)
                content_parts.append(f"- **{ttp}:** {ttp_info.get('name', ttp)}")
            content_parts.append("")

        # Signatures
        signatures = triage_result.get("signatures", [])
        if signatures:
            content_parts.append("## Triggered Signatures")
            for sig in signatures[:20]:
                content_parts.append(f"- {sig}")
            content_parts.append("")

        # Network IOCs
        domains = triage_result.get("domains", [])
        ips = triage_result.get("ips", [])
        c2s = triage_result.get("c2_candidates", [])

        if domains or ips or c2s:
            content_parts.append("## Network Indicators")
            if domains:
                content_parts.append(f"### Contacted Domains ({len(domains)})")
                for d in domains[:15]:
                    domain = d.get("domain", str(d)) if isinstance(d, dict) else str(d)
                    content_parts.append(f"- {domain}")
            if ips:
                content_parts.append(f"### Contacted IPs ({len(ips)})")
                for ip in ips[:15]:
                    content_parts.append(f"- {ip}")
            if c2s:
                content_parts.append(f"### C2 Candidates ({len(c2s)})")
                for c2 in c2s[:10]:
                    ip = c2.get("ip", "") if isinstance(c2, dict) else str(c2)
                    port = c2.get("port", "") if isinstance(c2, dict) else ""
                    reason = c2.get("reason", "") if isinstance(c2, dict) else ""
                    if port:
                        content_parts.append(f"- {ip}:{port} ({reason})")
                    else:
                        content_parts.append(f"- {ip} ({reason})")
            content_parts.append("")

        # External Reference with sandbox permalink
        ext_refs = []
        if triage_result.get("permalink"):
            ext_refs.append(
                {
                    "source_name": "PolySwarm Triage Sandbox Report",
                    "url": triage_result["permalink"],
                    "description": "View detailed Triage sandbox analysis",
                }
            )

        note_id = self._note_id(entity.get("id", ""), "sandbox-triage")
        note = {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "abstract": "PolySwarm Triage Sandbox Analysis",
            "content": "\n".join(content_parts),
            "object_refs": [entity["id"]],
        }
        if ext_refs:
            note["external_references"] = ext_refs

        return note

    def _create_cape_sandbox_note(
        self, entity: dict, cape_result: dict, llm_report: str | None = None
    ) -> dict | None:
        """Create Cape Sandbox Analysis note."""
        if not cape_result:
            return None

        content_parts = ["# PolySwarm Cape Sandbox Analysis\n"]

        # Score - Only Cape Malscore (no Report Malscore per user request)
        content_parts.append("## Analysis Score")
        content_parts.append(
            f"- **Cape Malscore:** {cape_result.get('cape_malscore', 0)}/10"
        )
        content_parts.append("")

        # AI Summary (inserted right after score)
        ai_section = self._format_ai_summary_section(llm_report)
        if ai_section:
            content_parts.extend(ai_section)

        # Family
        family = cape_result.get("family")
        if family:
            content_parts.append(f"## Malware Family\n- **Cape:** {family}\n")

        # TTPs
        ttps = cape_result.get("ttps", [])
        if ttps:
            content_parts.append("## MITRE ATT&CK Techniques")
            for ttp in ttps[:15]:
                ttp_info = get_ttp_info(ttp)
                content_parts.append(f"- **{ttp}:** {ttp_info.get('name', ttp)}")
            content_parts.append("")

        # Signatures
        signatures = cape_result.get("signatures", [])
        if signatures:
            content_parts.append("## Triggered Signatures")
            for sig in signatures[:20]:
                content_parts.append(f"- {sig}")
            content_parts.append("")

        # Network IOCs
        domains = cape_result.get("domains", [])
        ips = cape_result.get("ips", [])
        c2s = cape_result.get("c2_candidates", [])

        if domains or ips or c2s:
            content_parts.append("## Network Indicators")
            if domains:
                content_parts.append(f"### Contacted Domains ({len(domains)})")
                for d in domains[:15]:
                    domain = d.get("domain", str(d)) if isinstance(d, dict) else str(d)
                    content_parts.append(f"- {domain}")
            if ips:
                content_parts.append(f"### Contacted IPs ({len(ips)})")
                for ip in ips[:15]:
                    content_parts.append(f"- {ip}")
            if c2s:
                content_parts.append(f"### C2 Candidates ({len(c2s)})")
                for c2 in c2s[:10]:
                    ip = c2.get("ip", "") if isinstance(c2, dict) else str(c2)
                    port = c2.get("port", "") if isinstance(c2, dict) else ""
                    reason = c2.get("reason", "") if isinstance(c2, dict) else ""
                    if port:
                        content_parts.append(f"- {ip}:{port} ({reason})")
                    else:
                        content_parts.append(f"- {ip} ({reason})")
            content_parts.append("")

        # External Reference with sandbox permalink
        ext_refs = []
        if cape_result.get("permalink"):
            ext_refs.append(
                {
                    "source_name": "PolySwarm Cape Sandbox Report",
                    "url": cape_result["permalink"],
                    "description": "View detailed Cape sandbox analysis",
                }
            )

        note_id = self._note_id(entity.get("id", ""), "sandbox-cape")
        note = {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "abstract": "PolySwarm Cape Sandbox Analysis",
            "content": "\n".join(content_parts),
            "object_refs": [entity["id"]],
        }
        if ext_refs:
            note["external_references"] = ext_refs

        return note

    def _create_sandbox_failure_note(
        self, entity: dict, provider: str, failure_info: dict
    ) -> dict | None:
        """Create a note documenting a sandbox execution failure."""
        if not failure_info:
            return None

        status = failure_info.get("status", "UNKNOWN")
        error_msg = failure_info.get(
            "error", "No additional error information available"
        )
        raw_result = failure_info.get("raw_result", {})

        content_parts = [f"# PolySwarm {provider.upper()} Sandbox - Execution Failed\n"]

        # Failure status
        content_parts.append("## Execution Status")
        content_parts.append(f"- **Status:** {status}")
        content_parts.append(f"- **Provider:** {provider.upper()}")
        content_parts.append("")

        # Error details
        content_parts.append("## Failure Details")
        content_parts.append(f"{error_msg}")
        content_parts.append("")

        # Status explanations
        status_explanations = {
            "FAILED": "The sandbox analysis failed to complete. This may be due to the sample crashing, "
            "anti-analysis techniques, or incompatibility with the sandbox environment.",
            "TIMED OUT": "The sandbox analysis exceeded the maximum allowed execution time. "
            "The sample may have stalled or contain time-based evasion techniques.",
            "FAILED WITH QUOTA REIMBURSEMENT": "The analysis failed but your API quota has been reimbursed. "
            "This typically indicates an infrastructure issue.",
            "TIMED OUT WITH QUOTA REIMBURSEMENT": "The analysis timed out but your API quota has been reimbursed.",
            "FAILED REIMBURSED": "The analysis failed and your API quota has been reimbursed.",
        }

        explanation = status_explanations.get(
            status, "The sandbox execution did not complete successfully."
        )
        content_parts.append("## What This Means")
        content_parts.append(explanation)
        content_parts.append("")

        # Recommendations
        content_parts.append("## Recommendations")
        content_parts.append(
            "- Try submitting to a different sandbox provider (Cape or Triage)"
        )
        content_parts.append("- Check if the file format is supported by the sandbox")
        content_parts.append("- Review the scan results for initial threat assessment")
        content_parts.append(
            "- Consider manual analysis if automated sandboxing consistently fails"
        )
        content_parts.append("")
        content_parts.append("## Need Help?")
        content_parts.append(
            "Contact **sales@polyswarm.io** for assistance with sandbox failures, "
            "quota issues, or to upgrade your plan."
        )
        content_parts.append("")

        # Raw response info if available
        if raw_result:
            task_id = raw_result.get("id") or raw_result.get("task_id")
            if task_id:
                content_parts.append("## Task Information")
                content_parts.append(f"- **Task ID:** {task_id}")

        # External Reference with permalink if available
        ext_refs = []
        permalink = raw_result.get("permalink")
        if permalink:
            ext_refs.append(
                {
                    "source_name": f"PolySwarm {provider.upper()} Sandbox (Failed)",
                    "url": permalink,
                    "description": f"View {provider.upper()} sandbox task details",
                }
            )

        note_id = self._note_id(entity.get("id", ""), f"sandbox-fail:{provider}")
        note = {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "abstract": f"PolySwarm {provider.upper()} Sandbox - Execution {status}",
            "content": "\n".join(content_parts),
            "object_refs": [entity["id"]],
        }
        if ext_refs:
            note["external_references"] = ext_refs

        return note

    def create_error_note(
        self,
        entity: dict,
        error_category: str,
        error_detail: str,
        recommendations: list[str] | None = None,
    ) -> dict:
        """Create a STIX Note documenting an enrichment error, visible on the artifact in OpenCTI.

        Args:
            entity: The STIX entity being enriched
            error_category: Short category label (e.g. "File Size Exceeded", "API Error")
            error_detail: Human-readable error description
            recommendations: Optional list of recommended actions

        Returns:
            STIX Note dict ready to be included in a bundle
        """
        content_parts = ["# PolySwarm Enrichment — Error\n"]

        content_parts.append(f"## {error_category}")
        content_parts.append(f"{error_detail}")
        content_parts.append("")

        if recommendations:
            content_parts.append("## Recommended Actions")
            for i, rec in enumerate(recommendations, 1):
                content_parts.append(f"{i}. {rec}")
            content_parts.append("")

        content_parts.append("## Need Help?")
        content_parts.append(
            "For questions about API quotas, file size limits, feature access, or enterprise plans:"
        )
        content_parts.append("- **Email:** sales@polyswarm.io")
        content_parts.append("- **Website:** https://polyswarm.io")
        content_parts.append("")

        entity_id = entity.get("id", "") if isinstance(entity, dict) else str(entity)
        note_id = self._note_id(entity_id, f"error:{error_category}")
        return {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "abstract": f"PolySwarm Enrichment Error — {error_category}",
            "content": "\n".join(content_parts),
            "object_refs": [entity_id],
            "external_references": [
                {
                    "source_name": "PolySwarm Support",
                    "url": "https://polyswarm.io",
                    "description": "Contact sales@polyswarm.io for assistance",
                }
            ],
        }

    def _create_threat_intel_note(
        self, entity: dict, profile: dict, family: str | None
    ) -> dict | None:
        """Create Extended Threat Intelligence note from malware profile."""
        if not profile:
            return None

        content_parts = [f"# Extended Threat Intelligence: {family}\n"]

        if profile.get("description"):
            content_parts.append(f"## Description\n{profile['description']}\n")

        if profile.get("malware_type"):
            content_parts.append(
                f"## Malware Type\n{', '.join(profile['malware_type'])}\n"
            )

        if profile.get("actors"):
            content_parts.append("## Associated Threat Actors")
            for actor in profile["actors"]:
                content_parts.append(f"- {actor}")
            content_parts.append("")

        if profile.get("related_malware"):
            content_parts.append("## Related Malware (Known Associations)")
            for related in profile["related_malware"]:
                content_parts.append(f"- {related}")
            content_parts.append("")

        if profile.get("target_cves"):
            content_parts.append("## Exploited Vulnerabilities (CVEs)")
            for cve in profile["target_cves"]:
                content_parts.append(
                    f"- [{cve}](https://nvd.nist.gov/vuln/detail/{cve})"
                )
            content_parts.append("")

        if profile.get("target_locations"):
            content_parts.append(
                f"## Target Countries/Regions\n{', '.join(profile['target_locations'])}\n"
            )

        if profile.get("origin_locations"):
            content_parts.append(
                f"## Origin Countries/Regions\n{', '.join(profile['origin_locations'])}\n"
            )

        if profile.get("verticals_targeted"):
            content_parts.append("## Targeted Industries/Sectors")
            for sector in profile["verticals_targeted"]:
                content_parts.append(f"- {sector}")
            content_parts.append("")

        if profile.get("systems_targeted"):
            content_parts.append(
                f"## Targeted Operating Systems\n{', '.join(profile['systems_targeted'])}\n"
            )

        if profile.get("programming_languages"):
            content_parts.append(
                f"## Programming Languages\n{', '.join(profile['programming_languages'])}\n"
            )

        if profile.get("campaigns"):
            content_parts.append("## Associated Campaigns")
            for campaign in profile["campaigns"]:
                content_parts.append(f"- {campaign}")
            content_parts.append("")

        if profile.get("aliases"):
            content_parts.append(f"## Aliases\n{', '.join(profile['aliases'])}\n")

        note_id = self._note_id(entity.get("id", ""), f"threat-intel:{family}")
        return {
            "type": "note",
            "spec_version": "2.1",
            "id": note_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "abstract": f"Extended Threat Intelligence: {family}",
            "content": "\n".join(content_parts),
            "object_refs": [entity["id"]],
        }

    # ============= MALWARE =============

    def _create_malware_with_enrichment(
        self,
        family: str,
        score: int,
        external_refs: list,
        labels: list,
        scan_data: dict | None,
        sandbox_data: dict | None,
        profile: dict | None,
    ) -> tuple[dict | None, list[dict], list[dict]]:
        if not family:
            return None, [], []

        malware_id = Malware.generate_id(name=family)
        additional_objects: list[dict] = []
        relationships: list[dict] = []

        desc_parts = ["Malware family identified by PolySwarm analysis."]
        malware_types = []
        aliases = []

        if profile:
            if profile.get("description"):
                desc_parts = [profile["description"]]
            if profile.get("malware_type"):
                malware_types = profile["malware_type"]
            if profile.get("aliases"):
                aliases = profile["aliases"]

        # Add type hints from scan labels
        if scan_data and scan_data.get("labels"):
            type_mapping = {
                "trojan": "trojan",
                "ransomware": "ransomware",
                "worm": "worm",
                "backdoor": "backdoor",
                "spyware": "spyware",
                "rootkit": "rootkit",
                "adware": "adware",
                "bot": "bot",
                "dropper": "dropper",
                "downloader": "downloader",
                "keylogger": "spyware",
                "stealer": "spyware",
                "miner": "resource-exploitation",
                "rat": "remote-access-trojan",
            }
            for lbl in scan_data.get("labels", []):
                mapped = type_mapping.get(lbl.lower())
                if mapped and mapped not in malware_types:
                    malware_types.append(mapped)

        malware = {
            "type": "malware",
            "spec_version": "2.1",
            "id": malware_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "name": family,
            "description": " ".join(desc_parts),
            "is_family": True,
            "confidence": 100,
            "x_opencti_score": score,
            "external_references": external_refs,
        }

        if malware_types:
            malware["malware_types"] = malware_types
        if aliases:
            malware["aliases"] = aliases
        if labels:
            malware["labels"] = labels

        # Create related objects from profile
        if profile:
            # Target locations - store for threat actor relationships
            location_objs = []
            for loc_name in profile.get("target_locations", []):
                loc_obj = self._create_location(loc_name)
                if loc_obj and loc_obj["id"] not in [
                    o["id"] for o in additional_objects
                ]:
                    additional_objects.append(loc_obj)
                    location_objs.append(loc_obj)
                    relationships.append(
                        self._create_rel(malware_id, "targets", loc_obj["id"])
                    )

            # Target sectors - store for threat actor relationships
            sector_objs = []
            for sector_name in profile.get("verticals_targeted", []):
                sector_obj = self._create_sector(sector_name)
                if sector_obj and sector_obj["id"] not in [
                    o["id"] for o in additional_objects
                ]:
                    additional_objects.append(sector_obj)
                    sector_objs.append(sector_obj)
                    relationships.append(
                        self._create_rel(malware_id, "targets", sector_obj["id"])
                    )

            # CVEs
            for cve in profile.get("target_cves", []):
                vuln_obj = self._create_vulnerability(cve)
                if vuln_obj and vuln_obj["id"] not in [
                    o["id"] for o in additional_objects
                ]:
                    additional_objects.append(vuln_obj)
                    relationships.append(
                        self._create_rel(malware_id, "exploits", vuln_obj["id"])
                    )

            # Related Malware - store for threat actor relationships
            related_malware_objs = []
            for related_name in profile.get("related_malware", []):
                related_obj = self._create_related_malware(related_name)
                if related_obj and related_obj["id"] not in [
                    o["id"] for o in additional_objects
                ]:
                    additional_objects.append(related_obj)
                    related_malware_objs.append(related_obj)
                    relationships.append(
                        self._create_rel(
                            malware_id,
                            "related-to",
                            related_obj["id"],
                            "Related malware family",
                        )
                    )

            # Threat actors - with relationships to locations, sectors, and related malware
            for actor_name in profile.get("actors", []):
                actor_obj = self._create_threat_actor(actor_name, profile)
                if actor_obj and actor_obj["id"] not in [
                    o["id"] for o in additional_objects
                ]:
                    additional_objects.append(actor_obj)
                    relationships.append(
                        self._create_rel(
                            actor_obj["id"],
                            "uses",
                            malware_id,
                            f"Threat actor {actor_name} uses this malware",
                        )
                    )

                    # Threat Actor → targets → Location
                    for loc_obj in location_objs:
                        relationships.append(
                            self._create_rel(
                                actor_obj["id"],
                                "targets",
                                loc_obj["id"],
                                f"Threat actor targets {loc_obj['name']}",
                            )
                        )

                    # Threat Actor → targets → Sector
                    for sector_obj in sector_objs:
                        relationships.append(
                            self._create_rel(
                                actor_obj["id"],
                                "targets",
                                sector_obj["id"],
                                f"Threat actor targets {sector_obj['name']} sector",
                            )
                        )

                    # Threat Actor → uses → Related Malware
                    for related_obj in related_malware_objs:
                        relationships.append(
                            self._create_rel(
                                actor_obj["id"],
                                "uses",
                                related_obj["id"],
                                f"Threat actor may use related malware {related_obj['name']}",
                            )
                        )

        return malware, additional_objects, relationships

    # ============= ATTACK PATTERNS =============

    def _create_attack_patterns_enhanced(
        self,
        ttps: list[str],
        malware_id: str | None,
        indicator_id: str | None,
        observable_id: str | None,
    ) -> list[dict]:
        objects = []
        created_patterns = {}

        for ttp in ttps:
            if not ttp or ttp in created_patterns:
                continue

            ttp_info = get_ttp_info(ttp)
            ttp_name = ttp_info.get("name", f"ATT&CK Technique {ttp}")
            tactic = ttp_info.get("tactic", "unknown")
            description = ttp_info.get("description", f"MITRE ATT&CK technique {ttp}")

            ap_id = AttackPattern.generate_id(name=ttp_name, x_mitre_id=ttp)

            kill_chain_phases = []
            if tactic and tactic != "unknown":
                kill_chain_phases.append(
                    {"kill_chain_name": MITRE_KILL_CHAIN, "phase_name": tactic}
                )

            attack_pattern = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created": self._now,
                "modified": self._now,
                "created_by_ref": self.author_id,
                "name": ttp_name,
                "description": description,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": ttp,
                        "url": f"https://attack.mitre.org/techniques/{ttp.replace('.', '/')}",
                        "description": f"MITRE ATT&CK: {ttp_name}",
                    }
                ],
                "x_mitre_id": ttp,
            }
            if kill_chain_phases:
                attack_pattern["kill_chain_phases"] = kill_chain_phases

            objects.append(attack_pattern)
            created_patterns[ttp] = ap_id

            if malware_id:
                objects.append(self._create_rel(malware_id, "uses", ap_id))
            if indicator_id:
                objects.append(self._create_rel(indicator_id, "indicates", ap_id))
            if observable_id:
                objects.append(self._create_rel(observable_id, "related-to", ap_id))

        return objects

    # ============= NETWORK OBSERVABLES =============

    def _create_network_observables(
        self, sandbox_data: dict, entity: dict, malware_id: str | None
    ) -> list[dict]:
        objects = []

        # === DOMAIN OBSERVABLES ===
        domains_data = sandbox_data.get("domains", [])
        processed_domains = set()

        for domain_item in domains_data[:50]:
            if isinstance(domain_item, dict):
                domain = domain_item.get("domain")
            elif isinstance(domain_item, str):
                domain = domain_item
            else:
                continue

            if not domain:
                continue

            domain = domain.lower().strip()
            if domain in processed_domains:
                continue

            # PROD-17: Use shared benign-domain filter (single source of truth)
            if _is_benign_domain(domain):
                continue

            processed_domains.add(domain)

            domain_id = f"domain-name--{uuid.uuid5(uuid.NAMESPACE_URL, domain)}"
            # ``domain-name`` is a STIX 2.1 SCO. ``created_by_ref`` is
            # not a valid SCO property and breaks strict STIX
            # validation; OpenCTI carries the author on observables
            # through ``x_opencti_created_by_ref`` instead. Same
            # treatment for ipv4-addr below.
            domain_obj = {
                "type": "domain-name",
                "spec_version": "2.1",
                "id": domain_id,
                "value": domain,
                "x_opencti_created_by_ref": self.author_id,
                "x_opencti_description": self.OBSERVABLE_DESCRIPTION,
            }
            objects.append(domain_obj)
            objects.append(
                self._create_rel(entity["id"], "communicates-with", domain_id)
            )

        # === IP OBSERVABLES ===
        processed_ips = set()

        # From c2_candidates
        c2_candidates = sandbox_data.get("c2_candidates", [])
        for c2 in c2_candidates[:20]:
            ip = c2.get("ip") if isinstance(c2, dict) else c2
            if not ip:
                continue

            ip = str(ip).strip()
            if ip in processed_ips:
                continue
            processed_ips.add(ip)

            ip_id = f"ipv4-addr--{uuid.uuid5(uuid.NAMESPACE_URL, ip)}"
            ip_obj = {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": ip_id,
                "value": ip,
                "x_opencti_created_by_ref": self.author_id,
                "x_opencti_description": self.OBSERVABLE_DESCRIPTION,
            }

            if isinstance(c2, dict):
                if c2.get("port"):
                    ip_obj["x_polyswarm_port"] = c2.get("port")
                if c2.get("reason"):
                    ip_obj["x_polyswarm_reason"] = c2.get("reason")

            objects.append(ip_obj)
            objects.append(self._create_rel(entity["id"], "communicates-with", ip_id))

            if malware_id:
                objects.append(self._create_rel(malware_id, "communicates-with", ip_id))

        # From ips list
        ips_list = sandbox_data.get("ips", [])
        for ip in ips_list[:30]:
            if not ip:
                continue

            ip = str(ip).strip()
            if ip in processed_ips:
                continue
            processed_ips.add(ip)

            ip_id = f"ipv4-addr--{uuid.uuid5(uuid.NAMESPACE_URL, ip)}"
            # Same SCO-author treatment as the c2_candidates loop above:
            # observables carry the author via ``x_opencti_created_by_ref``,
            # not the SDO/SRO ``created_by_ref`` property.
            ip_obj = {
                "type": "ipv4-addr",
                "spec_version": "2.1",
                "id": ip_id,
                "value": ip,
                "x_opencti_created_by_ref": self.author_id,
                "x_opencti_description": self.OBSERVABLE_DESCRIPTION,
            }

            objects.append(ip_obj)
            objects.append(self._create_rel(entity["id"], "communicates-with", ip_id))

            if malware_id:
                objects.append(self._create_rel(malware_id, "communicates-with", ip_id))

        return objects

    # ============= HELPER OBJECTS =============

    def _create_location(self, location_name: str) -> dict | None:
        if not location_name:
            return None
        if location_name in self._location_cache:
            return self._location_cache[location_name]

        location_id = Location.generate_id(
            name=location_name, x_opencti_location_type="Country"
        )
        location = {
            "type": "location",
            "spec_version": "2.1",
            "id": location_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "name": location_name,
            "x_opencti_location_type": "Country",
            "confidence": 75,
        }
        self._location_cache[location_name] = location
        return location

    def _create_sector(self, sector_name: str) -> dict | None:
        sector_key = sector_name.lower()
        if sector_key in self._sector_cache:
            return self._sector_cache[sector_key]

        sector_id = Identity.generate_id(name=sector_name, identity_class="class")
        sector = {
            "type": "identity",
            "spec_version": "2.1",
            "id": sector_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "name": sector_name.capitalize(),
            "identity_class": "class",
            "x_opencti_type": "Sector",
            "confidence": 75,
        }
        self._sector_cache[sector_key] = sector
        return sector

    def _create_vulnerability(self, cve_id: str) -> dict | None:
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            return None
        cve_id = cve_id.upper()
        if cve_id in self._vulnerability_cache:
            return self._vulnerability_cache[cve_id]

        vuln_id = Vulnerability.generate_id(name=cve_id)
        vulnerability = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "name": cve_id,
            "description": f"Vulnerability {cve_id} exploited by malware",
            "external_references": [
                {
                    "source_name": "cve",
                    "external_id": cve_id,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                }
            ],
            "confidence": 90,
        }
        self._vulnerability_cache[cve_id] = vulnerability
        return vulnerability

    def _create_threat_actor(
        self, actor_name: str, profile: dict | None = None
    ) -> dict | None:
        if not actor_name:
            return None
        actor_key = actor_name.lower()
        if actor_key in self._actor_cache:
            return self._actor_cache[actor_key]

        actor_id = ThreatActor.generate_id(
            name=actor_name, opencti_type="Threat-Actor-Group"
        )

        # Build description with profile info
        desc_parts = ["Threat actor associated with malware."]
        if profile:
            if profile.get("target_locations"):
                desc_parts.append(
                    f"Target Countries: {', '.join(profile['target_locations'])}."
                )
            if profile.get("verticals_targeted"):
                desc_parts.append(
                    f"Target Sectors: {', '.join(profile['verticals_targeted'])}."
                )
            if profile.get("related_malware"):
                desc_parts.append(
                    f"Related Malware: {', '.join(profile['related_malware'])}."
                )

        actor = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "name": actor_name,
            "description": " ".join(desc_parts),
            "confidence": 75,
        }

        # Add goals from profile
        if profile:
            goals = []
            if profile.get("verticals_targeted"):
                goals.extend(
                    [f"Target {sector}" for sector in profile["verticals_targeted"][:5]]
                )
            if goals:
                actor["goals"] = goals

        self._actor_cache[actor_key] = actor
        return actor

    def _create_rel(
        self, src: str, rel_type: str, target: str, description: str | None = None
    ) -> dict:
        rel = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": StixCoreRelationship.generate_id(rel_type, src, target),
            "created": self._now,
            "modified": self._now,
            "created_by_ref": self.author_id,
            "relationship_type": rel_type,
            "source_ref": src,
            "target_ref": target,
        }
        if description:
            rel["description"] = description
        return rel

    def _get_sha256(self, entity: dict) -> str | None:
        hashes = entity.get("hashes", {})
        if isinstance(hashes, dict):
            return hashes.get("SHA-256") or hashes.get("sha256")
        if isinstance(hashes, list):
            for h in hashes:
                if h.get("algorithm") == "SHA-256":
                    return h.get("hash")
        obs_val = entity.get("observable_value", "")
        if len(obs_val) == 64 and all(c in "0123456789abcdefABCDEF" for c in obs_val):
            return obs_val
        return None
