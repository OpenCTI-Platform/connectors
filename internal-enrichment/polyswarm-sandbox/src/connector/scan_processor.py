"""
ScanProcessor - Processes raw PolySwarm scan results

Uses pre-computed API fields (detections, polyscore, top-level hashes) where
available, falling back to metadata iteration only for extended data
(PE info, exiftool, LIEF) that has no top-level equivalent.
"""

from typing import Any


class ScanProcessor:
    """Processes raw PolySwarm scan results into structured data for STIX mapping."""

    @staticmethod
    def process(result: dict, scan_id: str | None = None) -> dict[str, Any] | None:
        """Process raw PolySwarm scan results.

        Extracts polyscore, malware family, labels, OS, engine detections,
        and comprehensive hash info.

        Args:
            result: Raw scan result dict from PolySwarm API.
            scan_id: Scan instance ID (used for permalink fallback).
        """
        if not result or not isinstance(result, dict):
            return None

        # Threat score from API polyscore (0.0-1.0 → 0-100)
        raw_polyscore = result.get("polyscore", 0)
        try:
            raw_polyscore = float(raw_polyscore) if raw_polyscore else 0.0
        except (TypeError, ValueError):
            raw_polyscore = 0.0
        threat_score = max(0, min(100, int(raw_polyscore * 100)))

        # Polyunite metadata — walk metadata list for family/labels/OS
        # (no top-level API field for these)
        family = None
        labels = []
        operating_systems = []
        metadata = result.get("metadata", [])
        if isinstance(metadata, list):
            for entry in metadata:
                if entry.get("tool") == "polyunite":
                    tool_meta = entry.get("tool_metadata", {})
                    family = tool_meta.get("malware_family")
                    labels = tool_meta.get("labels", [])
                    operating_systems = tool_meta.get("operating_system", [])
                    break

        # Engine detections — still need assertion iteration for per-engine detail
        raw_assertions = result.get("assertions", [])
        if not isinstance(raw_assertions, list):
            raw_assertions = []
        engine_detections = ScanProcessor._extract_engine_detections(raw_assertions)

        # Hashes — use top-level fields + metadata hash tool for extended hashes
        hashes = ScanProcessor._extract_hashes(
            result, metadata if isinstance(metadata, list) else []
        )

        # File metadata — PE/exiftool/LIEF (no top-level equivalent)
        file_info = ScanProcessor._extract_file_info(
            result, metadata if isinstance(metadata, list) else []
        )

        # STIX labels
        stix_labels = []
        if family:
            stix_labels.append(f"polyswarm-family:{family.lower()}")
        stix_labels.append(f"polyscore:{threat_score}")
        for label in labels:
            stix_labels.append(f"polyswarm-type:{label.lower()}")

        # Detection stats — use pre-computed API field
        api_detections = result.get("detections", {})
        malicious_count = api_detections.get("malicious", 0)
        total_engines = api_detections.get("total", 0)

        return {
            "score": threat_score,
            "raw_polyscore": raw_polyscore,
            "family": family or "Unknown",
            "labels": labels,
            "stix_labels": stix_labels,
            "operating_systems": operating_systems,
            "permalink": (
                f"https://polyswarm.network/scan/results/file/{result.get('sha256')}"
                if result.get("sha256")
                else result.get("permalink")
            ),
            "sha256": result.get("sha256"),
            "sha1": result.get("sha1"),
            "md5": result.get("md5"),
            "hashes": hashes,
            "file_info": file_info,
            "engine_detections": engine_detections,
            "detection_stats": {
                "malicious": malicious_count,
                "total": total_engines,
            },
            "first_seen": result.get("first_seen"),
            "last_seen": result.get("last_seen"),
            "extended_type": result.get("extended_type"),
            "mimetype": result.get("mimetype"),
        }

    @staticmethod
    def _extract_engine_detections(assertions: list[dict]) -> list[dict[str, Any]]:
        """Extract detection details from each AV engine.

        Per-engine family attribution requires assertion iteration —
        there's no pre-computed API equivalent for this.
        """
        detections = []
        for assertion in assertions:
            if assertion.get("verdict") is True:
                detections.append(
                    {
                        "engine": assertion.get("author_name"),
                        "family": assertion.get("metadata", {}).get(
                            "malware_family", "Malicious"
                        ),
                        "engine_info": assertion.get("engine", {}).get(
                            "description", ""
                        )[:200],
                    }
                )
        return detections

    @staticmethod
    def _extract_hashes(result: dict, metadata: list) -> dict[str, str]:
        """Extract all available hashes.

        Top-level fields (sha256/sha1/md5) are authoritative.
        Extended hashes (sha512, sha3, ssdeep, tlsh, authentihash) come
        from the metadata hash tool entry.
        """
        hashes = {}

        # Top-level hashes — always prefer these
        if result.get("sha256"):
            hashes["SHA-256"] = result["sha256"]
        if result.get("sha1"):
            hashes["SHA-1"] = result["sha1"]
        if result.get("md5"):
            hashes["MD5"] = result["md5"]

        # Extended hashes from metadata hash tool
        for entry in metadata:
            if entry.get("tool") == "hash":
                tool_meta = entry.get("tool_metadata", {})
                for api_key, stix_key in [
                    ("sha512", "SHA-512"),
                    ("sha3_256", "SHA3-256"),
                    ("sha3_512", "SHA3-512"),
                    ("ssdeep", "SSDEEP"),
                    ("tlsh", "TLSH"),
                    ("authentihash", "AUTHENTIHASH"),
                ]:
                    if tool_meta.get(api_key):
                        hashes[stix_key] = tool_meta[api_key]
                break

        return hashes

    @staticmethod
    def _extract_file_info(result: dict, metadata: list) -> dict[str, Any]:
        """Extract file metadata from PE/exiftool/LIEF tools.

        These have no top-level API equivalent — metadata iteration required.
        """
        file_info = {
            "size": result.get("size"),
            "mimetype": result.get("mimetype"),
            "extended_type": result.get("extended_type"),
            "filename": result.get("filename"),
        }

        for entry in metadata:
            if entry.get("tool") == "pefile":
                pe_meta = entry.get("tool_metadata", {})
                file_info.update(
                    {
                        "is_signed": pe_meta.get("signed", False),
                        "is_packed": pe_meta.get("is_probably_packed", False),
                        "imphash": pe_meta.get("imphash"),
                        "compile_date": pe_meta.get("compile_date"),
                        "is_dll": pe_meta.get("is_dll", False),
                        "is_exe": pe_meta.get("is_exe", False),
                        "is_driver": pe_meta.get("is_driver", False),
                        "libraries": pe_meta.get("libraries", []),
                        "imported_functions": pe_meta.get("imported_functions", []),
                    }
                )
                certs = pe_meta.get("certificate", [])
                if certs:
                    file_info["signer"] = certs[0].get("subject", {}).get("common_name")
                # Continue walking the metadata list so exiftool / lief
                # blocks that follow a pefile block are still merged in.
                # The previous ``break`` here meant that whenever a
                # pefile entry was present (the common case for PE
                # samples), every later entry was silently discarded
                # and the resulting ``file_info`` was incomplete.
                continue

            if entry.get("tool") == "exiftool":
                exif_meta = entry.get("tool_metadata", {})
                file_info.update(
                    {
                        "product_name": exif_meta.get("productname"),
                        "company_name": exif_meta.get("companyname"),
                        "file_description": exif_meta.get("filedescription"),
                        "original_filename": exif_meta.get("originalfilename"),
                        "file_version": exif_meta.get("fileversion"),
                    }
                )

            elif entry.get("tool") == "lief":
                lief_meta = entry.get("tool_metadata", {})
                file_info.update(
                    {
                        "libraries": lief_meta.get("libraries", []),
                        "imported_functions": lief_meta.get("imported_functions", []),
                        "exported_functions": lief_meta.get("exported_functions", []),
                        "has_nx": lief_meta.get("has_nx"),
                        "is_pie": lief_meta.get("is_pie"),
                    }
                )

        return {k: v for k, v in file_info.items() if v}
