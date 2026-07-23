from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from .stairwell import StairwellClient
from .stairwell.score import monotonic_score, score_for_bucket
from .stix_builder import (
    bundle,
    make_external_reference,
    make_file_by_sha256,
    make_identity_system,
    make_note,
    make_relationship,
    make_sighting,
    make_x509_certificate,
    network_observable_for,
    stairwell_identity,
    stix_id,
    tlp_marking,
)

DEFAULT_VARIANT_LIMIT = 25
DEFAULT_SIGHTINGS_LIMIT = 100

logger = logging.getLogger(__name__)

_SEVERITY_LABELS = {
    "SEVERITY_HIGH": "stairwell:severity-high",
    "SEVERITY_MEDIUM": "stairwell:severity-medium",
    "SEVERITY_LOW": "stairwell:severity-low",
    "SEVERITY_INFORMATIONAL": "stairwell:severity-informational",
}


def _to_float(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class FileEnricher:
    def __init__(
        self,
        helper,
        client: StairwellClient,
        default_tlp: str,
        variant_limit: int = DEFAULT_VARIANT_LIMIT,
        sightings_limit: int = DEFAULT_SIGHTINGS_LIMIT,
        opencti_base_url: str = "http://localhost:8080",
    ) -> None:
        self.helper = helper
        self.client = client
        self.tlp = default_tlp
        self.variant_limit = max(0, int(variant_limit))
        self.sightings_limit = max(0, int(sightings_limit))
        self.opencti_base_url = opencti_base_url.rstrip("/")

    # ------------------------------------------------------------------
    # Hash selection
    # ------------------------------------------------------------------
    @staticmethod
    def _hash_dict(observable: dict[str, Any]) -> dict[str, str]:
        result: dict[str, str] = {}
        for h in observable.get("hashes") or []:
            algo = (h.get("algorithm") or "").upper().replace("-", "")
            value = h.get("hash") or ""
            if algo and value:
                result[algo] = value
        return result

    def _choose_hash(
        self, observable: dict[str, Any]
    ) -> tuple[str | None, str | None, bool]:
        hashes = self._hash_dict(observable)
        if "SHA256" in hashes:
            return hashes["SHA256"], "SHA256", False
        if "SHA1" in hashes:
            return hashes["SHA1"], "SHA1", True
        if "MD5" in hashes:
            return hashes["MD5"], "MD5", True
        return None, None, False

    # ------------------------------------------------------------------
    # Entrypoint
    # ------------------------------------------------------------------
    def enrich(self, observable: dict[str, Any]) -> str:
        entity_id = observable.get("standard_id") or observable.get("id")
        primary_hash, algo, fallback = self._choose_hash(observable)
        if not primary_hash:
            return "No usable hash on file observable; skipping Stairwell enrichment"

        status, metadata = self.client.get_object_metadata(primary_hash)
        if status == 404:
            self._mark_not_found(observable, primary_hash)
            return f"Stairwell: {primary_hash} not in corpus"
        if metadata is None:
            return (
                f"Stairwell metadata fetch failed for {primary_hash} (status {status})"
            )

        _, summary = self.client.summarize_file(primary_hash)

        variants_payload: dict[str, Any] | None = None
        if self.variant_limit > 0:
            v_status, v_body = self.client.get_variants(primary_hash)
            top_keys = list(v_body.keys())[:8] if isinstance(v_body, dict) else None
            logger.info(
                "Stairwell variants for %s: status=%s top_keys=%s",
                primary_hash,
                v_status,
                top_keys,
            )
            if isinstance(v_body, dict):
                variants_payload = v_body

        sightings_records: list[dict[str, Any]] = []
        sightings_truncated = False
        if self.sightings_limit > 0:
            sightings_records, sightings_truncated = self._fetch_sightings(primary_hash)

        return self._build_and_send_bundle(
            observable=observable,
            entity_id=entity_id,
            primary_hash=primary_hash,
            hash_algo=algo or "SHA256",
            fallback=fallback,
            metadata=metadata,
            summary=summary,
            variants_payload=variants_payload,
            sightings_records=sightings_records,
            sightings_truncated=sightings_truncated,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _mark_not_found(self, observable: dict[str, Any], primary_hash: str) -> None:
        """Attach a `stairwell:not-found` label + search link to the observable.

        Emitted as a STIX bundle (never via direct API writes) so the update
        flows through the OpenCTI worker like every other enrichment result.
        """
        entity_id = observable.get("standard_id") or observable.get("id")
        if not entity_id:
            return

        file_sco: dict[str, Any] = {
            "type": "file",
            "spec_version": "2.1",
            "id": entity_id,
            "labels": ["stairwell:not-found"],
            "object_marking_refs": [tlp_marking(self.tlp)],
            "external_references": [
                make_external_reference(
                    "Stairwell",
                    self.client.object_ui_url(primary_hash),
                    f"Stairwell search for {primary_hash}",
                )
            ],
        }
        stix_hashes: dict[str, str] = {}
        for algo, hashed in self._hash_dict(observable).items():
            if algo == "SHA256":
                stix_hashes["SHA-256"] = hashed
            elif algo == "SHA1":
                stix_hashes["SHA-1"] = hashed
            elif algo == "MD5":
                stix_hashes["MD5"] = hashed
        if stix_hashes:
            file_sco["hashes"] = stix_hashes

        self.helper.send_stix2_bundle(
            bundle([stairwell_identity(), file_sco]),
            cleanup_inconsistent_bundle=True,
        )

    def _build_and_send_bundle(
        self,
        observable: dict[str, Any],
        entity_id: str,
        primary_hash: str,
        hash_algo: str,
        fallback: bool,
        metadata: dict[str, Any],
        summary: dict[str, Any] | None,
        variants_payload: dict[str, Any] | None = None,
        sightings_records: list[dict[str, Any]] | None = None,
        sightings_truncated: bool = False,
    ) -> str:
        objects: list[dict[str, Any]] = [stairwell_identity()]

        mal_eval = metadata.get("mal_eval") or metadata.get("malEval") or {}
        prob_bucket = mal_eval.get("probability_bucket") or mal_eval.get(
            "probabilityBucket"
        )
        severity = mal_eval.get("severity")
        proposed_score = score_for_bucket(prob_bucket)
        current_score = observable.get("x_opencti_score")
        final_score = monotonic_score(current_score, proposed_score)

        labels: list[str] = []
        if severity and severity in _SEVERITY_LABELS:
            labels.append(_SEVERITY_LABELS[severity])
        for rule in self._yara_rule_names(metadata):
            labels.append(f"stairwell:yara:{rule}")
        if fallback:
            labels.append(f"stairwell:hash-fallback-{hash_algo.lower()}")

        family = (variants_payload or {}).get("family") or ""
        if family:
            labels.append(f"stairwell:family-{self._slug(family)}")

        for tag_label in self._stairwell_tag_labels(metadata):
            labels.append(tag_label)

        ext_ref = make_external_reference(
            "Stairwell",
            self.client.object_ui_url(primary_hash),
            f"Stairwell file detail for {primary_hash}",
        )

        tldr = (summary or {}).get("tldr") or (summary or {}).get("summary") or ""
        full_summary = (summary or {}).get("summary") or ""

        prevalences = metadata.get("prevalences") or []
        if not isinstance(prevalences, list):
            prevalences = []
        max_prevalence: float | None = None
        for pv in prevalences:
            if not isinstance(pv, dict):
                continue
            try:
                p = float(pv.get("prevalence", 0) or 0)
            except (TypeError, ValueError):
                continue
            if max_prevalence is None or p > max_prevalence:
                max_prevalence = p
        # Backwards-compat: scalar `prevalence` field if the response ever
        # carries it directly.
        if max_prevalence is None:
            scalar = metadata.get("prevalence") or metadata.get("globalPrevalence")
            if scalar is not None:
                try:
                    max_prevalence = float(scalar)
                except (TypeError, ValueError):
                    max_prevalence = None

        variants = metadata.get("variants") or {}
        variant_count = (
            variants.get("total")
            if isinstance(variants, dict)
            else (len(variants) if isinstance(variants, list) else None)
        )

        file_sco = self._updated_file_sco(
            entity_id=entity_id,
            observable=observable,
            tldr=tldr,
            final_score=final_score,
            current_score=current_score,
            labels=labels,
            ext_ref=ext_ref,
            prob_bucket=prob_bucket,
            prevalence=max_prevalence,
            variant_count=variant_count,
            metadata=metadata,
        )
        objects.append(file_sco)

        # Lineage from relationships.parents/children
        objects.extend(self._lineage_objects(entity_id, primary_hash, metadata))

        # x509 certificate observables from objectSignature
        objects.extend(self._certificate_objects(entity_id, metadata))

        # Consolidated "Stairwell Enrichment Summary" Note covering hashes,
        # file properties, MalEval, YARA, network indicators, and signature
        # info. The AI Triage and Variants notes remain separate alongside it.
        summary_note = self._summary_note(
            entity_id=entity_id,
            observable=observable,
            metadata=metadata,
            mal_eval=mal_eval,
        )
        if summary_note:
            objects.append(summary_note)

        # AI File Triage Note (long-form Stairwell AI writeup)
        if full_summary:
            objects.append(
                make_note(
                    seed=f"stairwell-ai-triage|{entity_id}",
                    abstract="Stairwell AI File Triage",
                    content=full_summary,
                    object_refs=[entity_id],
                    tlp=self.tlp,
                )
            )

        # Sightings: per-asset aggregated Sighting SDOs + asset Identities
        sighting_score = score_for_bucket(prob_bucket)
        objects.extend(
            self._sighting_objects(
                entity_id=entity_id,
                primary_hash=primary_hash,
                records=sightings_records or [],
                truncated=sightings_truncated,
                confidence=sighting_score,
            )
        )

        # Related observables from network_indicators
        objects.extend(self._network_indicator_objects(entity_id, metadata))

        # Variant SCOs + `derived-from` rels + descriptive Variants Note
        capped_variants = self._capped_variants(primary_hash, variants_payload)
        variant_displayed = len(capped_variants)
        objects.extend(self._variant_objects(entity_id, primary_hash, capped_variants))
        if variant_displayed > 0:
            objects.append(
                self._variants_note(
                    entity_id,
                    primary_hash,
                    variants_payload or {},
                    capped_variants,
                )
            )

        self.helper.send_stix2_bundle(bundle(objects), cleanup_inconsistent_bundle=True)
        return (
            f"Enriched file {primary_hash} "
            f"(score {final_score}, verdict {prob_bucket or 'none'}, "
            f"variants {variant_displayed})"
        )

    @staticmethod
    def _slug(value: str) -> str:
        return "".join(
            ch.lower() if ch.isalnum() else "-" for ch in value.strip()
        ).strip("-")

    def _capped_variants(
        self,
        primary_hash: str,
        variants_payload: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        if self.variant_limit <= 0 or not variants_payload:
            return []
        raw = variants_payload.get("variants") or []
        if not isinstance(raw, list):
            return []

        normalized: list[dict[str, Any]] = []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            sha256 = entry.get("sha256") or entry.get("SHA256") or entry.get("hash")
            if not sha256 or sha256.lower() == primary_hash.lower():
                continue
            # v202112 variants endpoint returns: similarity, sha256, sha1, md5.
            # Older drafts of this connector also accepted `confidence` as a
            # synonym; kept for forward-compat if the API ever adds it.
            similarity = _to_float(entry.get("similarity"))
            if similarity is None:
                similarity = _to_float(entry.get("confidence"))
            normalized.append(
                {
                    "sha256": str(sha256),
                    "sha1": entry.get("sha1") or entry.get("SHA1"),
                    "md5": entry.get("md5") or entry.get("MD5"),
                    "similarity": similarity,
                }
            )
        normalized.sort(
            key=lambda v: v["similarity"] if v["similarity"] is not None else -1.0,
            reverse=True,
        )
        return normalized[: self.variant_limit]

    def _variant_objects(
        self,
        source_entity_id: str,
        primary_hash: str,
        capped: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for v in capped:
            extra: dict[str, Any] = {
                "external_references": [
                    make_external_reference(
                        "Stairwell",
                        self.client.object_ui_url(v["sha256"]),
                        f"Stairwell variant of {primary_hash}",
                    )
                ]
            }
            if v["similarity"] is not None:
                extra["x_stairwell_variant_similarity"] = v["similarity"]
            sco = make_file_by_sha256(
                v["sha256"],
                tlp=self.tlp,
                extra=extra,
                sha1=v.get("sha1"),
                md5=v.get("md5"),
            )
            out.append(sco)
            out.append(
                make_relationship(
                    source_id=source_entity_id,
                    target_id=sco["id"],
                    relationship_type="derived-from",
                    tlp=self.tlp,
                )
            )
        return out

    def _variants_note(
        self,
        entity_id: str,
        primary_hash: str,
        variants_payload: dict[str, Any],
        capped: list[dict[str, Any]],
    ) -> dict[str, Any]:
        displayed = len(capped)
        family = variants_payload.get("family") or ""
        total = (
            variants_payload.get("variant_count")
            or variants_payload.get("variantCount")
            or len(variants_payload.get("variants") or [])
        )

        lines: list[str] = []
        if family:
            lines.append(f"**Family:** {family}")
        lines.append(f"**Total variants:** {total}")
        cap_note = (
            ""
            if displayed >= int(total or 0)
            else f" (capped at STAIRWELL_VARIANT_LIMIT={self.variant_limit})"
        )
        lines.append(f"**Displayed:** {displayed}{cap_note}")
        lines.append("")
        lines.append("| # | SHA-256 | Similarity | Links |")
        lines.append("|---|---|---|---|")
        for idx, v in enumerate(capped, start=1):
            sha = v["sha256"]
            sim = v["similarity"]
            if isinstance(sim, float):
                sim_pct = sim * 100 if sim <= 1.0 else sim
                sim_str = f"{sim_pct:.0f}%"
            else:
                sim_str = "—"
            opencti_link = (
                f"[OpenCTI]({self.opencti_base_url}/dashboard/search/knowledge/{sha})"
            )
            stairwell_link = f"[Stairwell]({self.client.object_ui_url(sha)})"
            lines.append(
                f"| {idx} | `{sha[:12]}…{sha[-8:]}` | {sim_str} | "
                f"{opencti_link} · {stairwell_link} |"
            )

        return make_note(
            seed=f"stairwell-variants|{entity_id}",
            abstract="Stairwell Variants",
            content="\n".join(lines),
            object_refs=[entity_id],
            tlp=self.tlp,
        )

    def _summary_note(
        self,
        entity_id: str,
        observable: dict[str, Any],
        metadata: dict[str, Any],
        mal_eval: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Build the single consolidated `Stairwell Enrichment Summary` Note.

        Sections (in order): Hashes, File properties, Stairwell observation,
        YARA matches, Network indicators, Object signature.
        """
        lines: list[str] = []
        had_content = False

        # Hashes — prefer values from the metadata response, falling back to
        # the input observable.
        obs_hashes = self._hash_dict(observable)
        h_md5 = metadata.get("md5") or obs_hashes.get("MD5")
        h_sha1 = metadata.get("sha1") or obs_hashes.get("SHA1")
        h_sha256 = metadata.get("sha256") or obs_hashes.get("SHA256")
        h_sha3 = metadata.get("sha3256") or metadata.get("sha3_256")
        if any((h_md5, h_sha1, h_sha256, h_sha3)):
            lines.append("## Hashes")
            if h_md5:
                lines.append(f"- **MD5:** `{h_md5}`")
            if h_sha1:
                lines.append(f"- **SHA-1:** `{h_sha1}`")
            if h_sha256:
                lines.append(f"- **SHA-256:** `{h_sha256}`")
            if h_sha3:
                lines.append(f"- **SHA-3 256:** `{h_sha3}`")
            lines.append("")
            had_content = True

        # File properties
        prop_lines: list[str] = []
        name = metadata.get("name") or ""
        if name and not name.startswith("objects/"):
            prop_lines.append(f"- **Name:** `{name}`")
        size = metadata.get("size")
        if size is not None:
            try:
                size_int = int(size)
                if size_int < 1_000_000:
                    prop_lines.append(f"- **Size:** {size_int / 1_000:.2f} KB")
                else:
                    prop_lines.append(f"- **Size:** {size_int / 1_000_000:.2f} MB")
            except (TypeError, ValueError):
                prop_lines.append(f"- **Size:** {size}")
        if metadata.get("mimeType"):
            prop_lines.append(f"- **MIME type:** `{metadata['mimeType']}`")
        if metadata.get("magic"):
            prop_lines.append(f"- **Magic:** `{metadata['magic']}`")
        if metadata.get("shannonEntropy") is not None:
            try:
                prop_lines.append(
                    f"- **Shannon entropy:** {float(metadata['shannonEntropy']):.4f}"
                )
            except (TypeError, ValueError):
                prop_lines.append(
                    f"- **Shannon entropy:** {metadata['shannonEntropy']}"
                )
        if metadata.get("imphash"):
            prop_lines.append(f"- **imphash:** `{metadata['imphash']}`")
        if metadata.get("imphashSorted"):
            prop_lines.append(f"- **imphash (sorted):** `{metadata['imphashSorted']}`")
        if metadata.get("tlsh"):
            prop_lines.append(f"- **TLSH:** `{metadata['tlsh']}`")
        if prop_lines:
            lines.append("## File properties")
            lines.extend(prop_lines)
            lines.append("")
            had_content = True

        # Stairwell observation: first seen + MalEval
        obs_lines: list[str] = []
        if metadata.get("stairwellFirstSeenTime"):
            obs_lines.append(f"- **First seen:** {metadata['stairwellFirstSeenTime']}")
        verdict = mal_eval.get("probability_bucket") or mal_eval.get(
            "probabilityBucket"
        )
        severity = mal_eval.get("severity")
        mal_labels = mal_eval.get("labels") or []
        if verdict:
            obs_lines.append(f"- **MalEval verdict:** `{verdict}`")
        if severity:
            obs_lines.append(f"- **MalEval severity:** `{severity}`")
        if isinstance(mal_labels, list) and mal_labels:
            joined = ", ".join(f"`{lbl}`" for lbl in mal_labels)
            obs_lines.append(f"- **MalEval labels:** {joined}")
        if obs_lines:
            lines.append("## Stairwell observation")
            lines.extend(obs_lines)
            lines.append("")
            had_content = True

        # YARA matches — current Stairwell response uses `yaraRuleMatches` (a
        # flat list of strings); legacy/internal builds also expose
        # `yara_results.matches[].rule_name`. Surface both shapes.
        yara_names: list[str] = []
        flat = metadata.get("yaraRuleMatches") or metadata.get("yara_rule_matches")
        if isinstance(flat, list):
            for entry in flat:
                if isinstance(entry, str) and entry:
                    yara_names.append(entry)
        for name_ in self._yara_rule_names(metadata):
            if name_ not in yara_names:
                yara_names.append(name_)
        if yara_names:
            lines.append("## YARA matches")
            for rule in yara_names:
                lines.append(f"- `{rule}`")
            lines.append("")
            had_content = True

        # Network indicators
        net = (
            metadata.get("network_indicators")
            or metadata.get("networkIndicators")
            or {}
        )
        if isinstance(net, dict):
            ips = self._collect_net_values(
                net.get("ip_addresses") or net.get("ipAddresses")
            )
            hostnames = self._collect_net_values(net.get("hostnames"))
            urls = self._collect_net_values(net.get("urls"))
            if ips or hostnames or urls:
                lines.append("## Network indicators")
                if ips:
                    lines.append(
                        f"- **IP addresses:** {', '.join(f'`{v}`' for v in ips)}"
                    )
                if hostnames:
                    lines.append(
                        f"- **Hostnames:** {', '.join(f'`{v}`' for v in hostnames)}"
                    )
                if urls:
                    lines.append(f"- **URLs:** {', '.join(f'`{v}`' for v in urls)}")
                lines.append("")
                had_content = True

        # Object signature — x509 cert summary + PKCS7 verification result
        sig = metadata.get("objectSignature") or {}
        if isinstance(sig, dict):
            certs = sig.get("x509Certificates") or []
            pkcs7 = sig.get("pkcs7VerificationResult")
            if (isinstance(certs, list) and certs) or pkcs7:
                lines.append("## Object signature")
                if pkcs7:
                    lines.append(f"- **PKCS7 verification:** `{pkcs7}`")
                if isinstance(certs, list):
                    for idx, cert in enumerate(certs, start=1):
                        if not isinstance(cert, dict):
                            continue
                        lines.append(f"- **Certificate {idx}:**")
                        if cert.get("subject"):
                            lines.append(f"  - Subject: `{cert['subject']}`")
                        if cert.get("issuer"):
                            lines.append(f"  - Issuer: `{cert['issuer']}`")
                        if cert.get("earliestValidTime"):
                            lines.append(f"  - Valid from: {cert['earliestValidTime']}")
                        if cert.get("latestValidTime"):
                            lines.append(f"  - Valid until: {cert['latestValidTime']}")
                        if cert.get("signature"):
                            lines.append(f"  - Signature: `{cert['signature']}`")
                lines.append("")
                had_content = True

        if not had_content:
            return None

        return make_note(
            seed=f"stairwell-enrichment-summary|{entity_id}",
            abstract="Stairwell Enrichment Summary",
            content="\n".join(lines).rstrip(),
            object_refs=[entity_id],
            tlp=self.tlp,
        )

    @staticmethod
    def _collect_net_values(raw: Any) -> list[str]:
        out: list[str] = []
        if not isinstance(raw, list):
            return out
        for entry in raw:
            if isinstance(entry, dict):
                value = entry.get("value")
            else:
                value = entry
            if isinstance(value, str) and value and value not in out:
                out.append(value)
        return out

    def _updated_file_sco(
        self,
        entity_id: str,
        observable: dict[str, Any],
        tldr: str,
        final_score: int | None,
        current_score: int | None,
        labels: list[str],
        ext_ref: dict[str, Any],
        prob_bucket: str | None,
        prevalence: float | None,
        variant_count: int | None,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        metadata = metadata or {}
        hashes = self._hash_dict(observable)
        stix_hashes: dict[str, str] = {}
        for algo, hashed in hashes.items():
            if algo == "SHA256":
                stix_hashes["SHA-256"] = hashed
            elif algo == "SHA1":
                stix_hashes["SHA-1"] = hashed
            elif algo == "MD5":
                stix_hashes["MD5"] = hashed
        # Backfill hashes from the metadata response when the input observable
        # didn't carry them.
        if metadata.get("sha256") and "SHA-256" not in stix_hashes:
            stix_hashes["SHA-256"] = metadata["sha256"]
        if metadata.get("sha1") and "SHA-1" not in stix_hashes:
            stix_hashes["SHA-1"] = metadata["sha1"]
        if metadata.get("md5") and "MD5" not in stix_hashes:
            stix_hashes["MD5"] = metadata["md5"]

        sco: dict[str, Any] = {
            "type": "file",
            "spec_version": "2.1",
            "id": entity_id,
            "object_marking_refs": [tlp_marking(self.tlp)],
            "external_references": [ext_ref],
        }
        if stix_hashes:
            sco["hashes"] = stix_hashes
        if tldr:
            sco["x_opencti_description"] = tldr
        if final_score is not None and final_score != current_score:
            sco["x_opencti_score"] = final_score
        if labels:
            sco["labels"] = labels
        if prob_bucket:
            sco["x_stairwell_maleval_probability"] = prob_bucket
        if prevalence is not None:
            sco["x_stairwell_prevalence"] = prevalence
        if variant_count is not None:
            sco["x_stairwell_variant_count"] = int(variant_count)

        # Stairwell metadata → standard + custom STIX file properties.
        # Some Stairwell responses echo back the API path (e.g.
        # "objects/{hash}/metadata") as `name` when the file was ingested
        # without an original filename — skip those.
        meta_name = metadata.get("name") or ""
        if meta_name and not sco.get("name") and not meta_name.startswith("objects/"):
            sco["name"] = meta_name
        size = metadata.get("size")
        if size is not None:
            try:
                sco["size"] = int(size)
            except (TypeError, ValueError):
                pass
        if metadata.get("mimeType"):
            sco["mime_type"] = metadata["mimeType"]
        if metadata.get("magic"):
            sco["x_stairwell_magic"] = metadata["magic"]
        if metadata.get("imphash"):
            sco["x_stairwell_imphash"] = metadata["imphash"]
        if metadata.get("imphashSorted"):
            sco["x_stairwell_imphash_sorted"] = metadata["imphashSorted"]
        if metadata.get("tlsh"):
            sco["x_stairwell_tlsh"] = metadata["tlsh"]
        if metadata.get("shannonEntropy") is not None:
            try:
                sco["x_stairwell_shannon_entropy"] = float(metadata["shannonEntropy"])
            except (TypeError, ValueError):
                pass
        if metadata.get("stairwellFirstSeenTime"):
            sco["x_stairwell_first_seen"] = metadata["stairwellFirstSeenTime"]
        environments = metadata.get("environments")
        if isinstance(environments, list) and environments:
            sco["x_stairwell_environments"] = list(environments)
        return sco

    @staticmethod
    def _yara_rule_names(metadata: dict[str, Any]) -> list[str]:
        rules: list[str] = []
        for path in (
            ("yara_results", "matches"),
            ("yaraResults", "matches"),
            ("yara", "matches"),
        ):
            current: Any = metadata
            for segment in path:
                if isinstance(current, dict) and segment in current:
                    current = current[segment]
                else:
                    current = None
                    break
            if isinstance(current, list):
                for entry in current:
                    if isinstance(entry, dict):
                        name = (
                            entry.get("rule_name")
                            or entry.get("ruleName")
                            or entry.get("name")
                        )
                        if name:
                            rules.append(str(name))
                break
        return list(dict.fromkeys(rules))

    # ------------------------------------------------------------------
    # Sightings
    # ------------------------------------------------------------------
    def _fetch_sightings(self, primary_hash: str) -> tuple[list[dict[str, Any]], bool]:
        """Page through `/v1/objects/{hash}/sightings` until cap or end.

        Returns (records, truncated). The cap is on UNIQUE assets, not
        records; we keep paginating as long as we're still discovering new
        assets, but stop once we've already collected `sightings_limit`
        distinct assets and the next page only adds more events for assets
        we've already capped.
        """
        records: list[dict[str, Any]] = []
        seen_assets: set[str] = set()
        truncated = False
        page_token: str | None = None
        page_size = min(1000, max(1, self.sightings_limit * 2))
        max_pages = 50  # hard safety stop

        for _ in range(max_pages):
            status, body = self.client.list_object_sightings(
                primary_hash, page_size=page_size, page_token=page_token
            )
            if status >= 400 or not isinstance(body, dict):
                break
            page = body.get("objectSightings") or body.get("object_sightings") or []
            if not isinstance(page, list):
                break

            for record in page:
                if not isinstance(record, dict):
                    continue
                asset = record.get("asset") or ""
                if not asset:
                    continue
                if asset not in seen_assets:
                    if len(seen_assets) >= self.sightings_limit:
                        truncated = True
                        continue
                    seen_assets.add(asset)
                records.append(record)

            page_token = body.get("nextPageToken") or body.get("next_page_token")
            if not page_token:
                break
            # If we've hit the cap and the rest of the page added nothing new,
            # the next page is unlikely to either — bail.
            if truncated and len(seen_assets) >= self.sightings_limit:
                # One more page in case the truncated flag is for assets at the
                # very end of THIS page; otherwise stop here.
                truncated = True
                break

        return records, truncated

    def _sighting_objects(
        self,
        entity_id: str,
        primary_hash: str,
        records: list[dict[str, Any]],
        truncated: bool,
        confidence: int | None,
    ) -> list[dict[str, Any]]:
        if not records:
            return []

        # Group records by asset id.
        per_asset: dict[str, list[dict[str, Any]]] = {}
        for record in records:
            asset = record.get("asset") or ""
            if not asset:
                continue
            per_asset.setdefault(asset, []).append(record)

        out: list[dict[str, Any]] = []
        environments: set[str] = set()

        for asset_id, asset_records in per_asset.items():
            asset_name = next(
                (
                    r.get("assetName") or r.get("asset_name")
                    for r in asset_records
                    if r.get("assetName") or r.get("asset_name")
                ),
                asset_id,
            )
            env_id = next(
                (r.get("environment") for r in asset_records if r.get("environment")),
                None,
            )
            if env_id:
                environments.add(env_id)

            timestamps = sorted(
                t
                for t in (
                    self._normalize_timestamp(r.get("sightingTime"))
                    for r in asset_records
                )
                if t
            )
            first_seen = timestamps[0] if timestamps else None
            last_seen = timestamps[-1] if timestamps else None
            if not first_seen or not last_seen:
                continue

            description_lines = [f"**Stairwell asset:** `{asset_id}`"]
            if env_id:
                description_lines.append(f"**Environment:** `{env_id}`")
            description_lines.append(f"**Events:** {len(asset_records)}")
            paths_seen = sorted(
                {
                    f"{r.get('filepath') or ''}{r.get('filename') or ''}"
                    for r in asset_records
                    if (r.get("filepath") or r.get("filename"))
                }
            )[:5]
            if paths_seen:
                description_lines.append("**Paths (sample):**")
                for p in paths_seen:
                    description_lines.append(f"- `{p}`")

            identity = make_identity_system(
                asset_id=asset_id,
                name=str(asset_name),
                description=(
                    f"Stairwell-managed asset {asset_name} " f"(environment {env_id})"
                    if env_id
                    else None
                ),
                tlp=self.tlp,
            )
            out.append(identity)

            sighting = make_sighting(
                seed=f"stairwell-sighting|{primary_hash.lower()}|{asset_id}",
                sighting_of_ref=entity_id,
                where_sighted_refs=[identity["id"]],
                first_seen=first_seen,
                last_seen=last_seen,
                count=len(asset_records),
                confidence=confidence,
                description="\n".join(description_lines),
                external_references=[
                    make_external_reference(
                        "Stairwell",
                        self.client.object_ui_url(primary_hash),
                        f"Stairwell sightings for {primary_hash}",
                    )
                ],
                tlp=self.tlp,
            )
            out.append(sighting)

        if truncated:
            out.append(
                make_note(
                    seed=f"stairwell-sightings-truncation|{entity_id}",
                    abstract="Stairwell Sightings Truncation",
                    content=(
                        f"Sightings were truncated at "
                        f"STAIRWELL_SIGHTINGS_LIMIT={self.sightings_limit} "
                        f"unique assets. Additional assets exist but were "
                        f"dropped from this enrichment run."
                    ),
                    object_refs=[entity_id],
                    tlp=self.tlp,
                )
            )

        return out

    @staticmethod
    def _normalize_timestamp(raw: Any) -> str | None:
        """Stairwell returns RFC3339 with nanosecond precision (e.g.
        `2025-04-29T19:42:30.534916301Z`). STIX requires millisecond precision
        max. Truncate fractional seconds to 3 digits and re-emit as UTC Z.
        """
        if not isinstance(raw, str) or not raw:
            return None
        cleaned = raw.replace("Z", "+00:00")
        # Truncate fractional seconds to 6 digits if longer (datetime caps at us)
        if "." in cleaned:
            head, _, tail = cleaned.partition(".")
            # tail looks like "534916301+00:00" — split off timezone first
            for sep in ("+", "-"):
                # rfind because the tz sign appears AFTER the digits
                idx = tail.rfind(sep)
                if idx > 0:
                    frac = tail[:idx][:6]
                    tz = tail[idx:]
                    cleaned = f"{head}.{frac}{tz}"
                    break
        try:
            parsed = datetime.fromisoformat(cleaned)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (
            parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        )

    # ------------------------------------------------------------------
    # Object metadata: tags, prevalence, lineage, certificates
    # ------------------------------------------------------------------
    @staticmethod
    def _stairwell_tag_labels(metadata: dict[str, Any]) -> list[str]:
        out: list[str] = []
        for tag in metadata.get("tags") or []:
            if not isinstance(tag, dict):
                continue
            name = (tag.get("name") or "").strip()
            value = (tag.get("value") or "").strip()
            if not name:
                continue
            if value:
                out.append(f"stairwell:tag:{name}={value}")
            else:
                out.append(f"stairwell:tag:{name}")
        return out

    def _lineage_objects(
        self, entity_id: str, primary_hash: str, metadata: dict[str, Any]
    ) -> list[dict[str, Any]]:
        rels = metadata.get("relationships") or {}
        if not isinstance(rels, dict):
            return []
        out: list[dict[str, Any]] = []
        primary_lc = primary_hash.lower()

        def _emit(items: list[Any], direction: str) -> None:
            if not isinstance(items, list):
                return
            for entry in items:
                if not isinstance(entry, dict):
                    continue
                sha = (entry.get("sha256") or "").lower()
                if not sha or sha == primary_lc:
                    continue
                related = make_file_by_sha256(
                    sha,
                    tlp=self.tlp,
                    extra={
                        "external_references": [
                            make_external_reference(
                                "Stairwell",
                                self.client.object_ui_url(sha),
                                f"Stairwell file detail for {sha}",
                            )
                        ]
                    },
                )
                out.append(related)
                # `derived-from`: source is derived from target. Children are
                # derived from this file; this file is derived from parents.
                if direction == "child":
                    src, dst = related["id"], entity_id
                else:  # parent
                    src, dst = entity_id, related["id"]
                out.append(
                    make_relationship(
                        source_id=src,
                        target_id=dst,
                        relationship_type="derived-from",
                        tlp=self.tlp,
                    )
                )

        _emit(rels.get("parents") or [], direction="parent")
        _emit(rels.get("children") or [], direction="child")
        return out

    def _certificate_objects(
        self, entity_id: str, metadata: dict[str, Any]
    ) -> list[dict[str, Any]]:
        sig = metadata.get("objectSignature") or {}
        if not isinstance(sig, dict):
            return []
        certs = sig.get("x509Certificates") or []
        if not isinstance(certs, list):
            return []
        out: list[dict[str, Any]] = []
        for cert in certs:
            if not isinstance(cert, dict):
                continue
            cert_obj = make_x509_certificate(cert, tlp=self.tlp)
            if not cert_obj:
                continue
            out.append(cert_obj)
            out.append(
                make_relationship(
                    source_id=entity_id,
                    target_id=cert_obj["id"],
                    relationship_type="related-to",
                    tlp=self.tlp,
                )
            )
        return out

    def _network_indicator_objects(
        self, source_id: str, metadata: dict[str, Any]
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        net = (
            metadata.get("network_indicators")
            or metadata.get("networkIndicators")
            or {}
        )
        if not isinstance(net, dict):
            return out

        groups = (
            (net.get("ip_addresses") or net.get("ipAddresses") or [], "ip"),
            (net.get("hostnames") or [], "hostname"),
            (net.get("urls") or [], "url"),
        )

        seen: set[str] = set()
        for values, kind in groups:
            if not isinstance(values, list):
                continue
            for v in values:
                value = (
                    v.get("value")
                    if isinstance(v, dict)
                    else (str(v) if v is not None else "")
                )
                if not value or value in seen:
                    continue
                seen.add(value)
                sco = network_observable_for(value, kind, self.tlp)
                if not sco:
                    continue
                out.append(sco)
                out.append(
                    make_relationship(
                        source_id=source_id,
                        target_id=sco["id"],
                        relationship_type="related-to",
                        tlp=self.tlp,
                    )
                )
        return out
