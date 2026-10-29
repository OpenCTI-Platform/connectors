import json
import re
from unittest.mock import MagicMock

import pytest
from connector.file_enricher import FileEnricher
from connector.stairwell import StairwellClient
from connectors_sdk.exceptions.error import DataRetrievalError

SHA256 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"  # WannaCry


def _client(monkeypatch_responses):
    c = StairwellClient.__new__(StairwellClient)
    c._base_url = "https://app.stairwell.com"
    c._timeout = 30
    c._session = None
    # Default the sightings call to empty so tests that don't care about
    # sightings stay simple; individual tests can override.
    monkeypatch_responses.setdefault(
        "list_object_sightings", (200, {"objectSightings": [], "nextPageToken": ""})
    )
    for name, value in monkeypatch_responses.items():
        setattr(c, name, MagicMock(return_value=value))
    return c


def _observable_with_sha256(sha256: str = SHA256, score=None):
    obs = {
        "id": "stix-cyber-observable--1234",
        "standard_id": f"file--{sha256[:8]}-aaaa-bbbb-cccc-dddddddddddd",
        "entity_type": "StixFile",
        "hashes": [{"algorithm": "SHA-256", "hash": sha256}],
    }
    if score is not None:
        obs["x_opencti_score"] = score
    return obs


def _helper():
    helper = MagicMock()
    helper.send_stix2_bundle = MagicMock()
    return helper


def test_happy_path_produces_bundle_with_expected_shape():
    metadata = {
        "mal_eval": {
            "probability_bucket": "PROBABILITY_HIGH",
            "severity": "SEVERITY_HIGH",
        },
        "prevalence": 0.0123,
        "variants": {"total": 7},
        "yara_results": {
            "matches": [
                {"rule_name": "Win_Trojan_WannaCry"},
                {"rule_name": "Win_Worm_WannaCry"},
            ]
        },
        "network_indicators": {
            "ip_addresses": [{"value": "8.8.8.8"}],
            "hostnames": [{"value": "evil.example.com"}],
            "urls": [{"value": "http://evil.example.com/x"}],
        },
    }
    summary = {"tldr": "Malicious WannaCry variant.", "summary": "Long writeup..."}

    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, summary),
            "get_variants": (200, {"variants": []}),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber")

    msg = enricher.enrich(_observable_with_sha256(score=20))
    assert "Enriched file" in msg

    helper.send_stix2_bundle.assert_called_once()
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    types = [o["type"] for o in payload["objects"]]
    assert "file" in types
    # Two notes: Stairwell Enrichment Summary + AI File Triage
    notes = [o for o in payload["objects"] if o["type"] == "note"]
    abstracts = {n["abstract"] for n in notes}
    assert "Stairwell Enrichment Summary" in abstracts
    assert "Stairwell AI File Triage" in abstracts
    # Three related observables + three relationships
    assert types.count("ipv4-addr") == 1
    assert types.count("domain-name") == 1
    assert types.count("url") == 1
    assert types.count("relationship") == 3

    file_sco = next(o for o in payload["objects"] if o["type"] == "file")
    assert file_sco["x_opencti_score"] == 75  # PROBABILITY_HIGH
    assert file_sco["x_stairwell_maleval_probability"] == "PROBABILITY_HIGH"
    assert file_sco["x_stairwell_variant_count"] == 7
    assert "stairwell:severity-high" in file_sco["labels"]
    assert "stairwell:yara:Win_Trojan_WannaCry" in file_sco["labels"]
    assert any(
        ref["source_name"] == "Stairwell" for ref in file_sco["external_references"]
    )


def test_score_does_not_lower_existing_higher_score():
    metadata = {"mal_eval": {"probability_bucket": "PROBABILITY_LOW"}}
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": []}),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber")

    enricher.enrich(_observable_with_sha256(score=80))

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    file_sco = next(o for o in payload["objects"] if o["type"] == "file")
    # The existing 80, never the proposed 25. It is sent even unchanged, so a
    # playbook merge cannot keep a lower score from an earlier step.
    assert file_sco["x_opencti_score"] == 80


def test_404_path_marks_not_found_via_bundle_without_api_writes():
    client = _client(
        {
            "get_object_metadata": (404, None),
        }
    )
    helper = _helper()
    helper.api.stix_cyber_observable.add_label = MagicMock()
    helper.api.external_reference.create = MagicMock(return_value={"id": "ext-1"})
    helper.api.stix_cyber_observable.add_external_reference = MagicMock()

    enricher = FileEnricher(helper, client, default_tlp="amber")
    msg = enricher.enrich(_observable_with_sha256())

    assert "not in corpus" in msg
    # Not-found is now expressed as a STIX bundle, never via direct API writes.
    helper.api.stix_cyber_observable.add_label.assert_not_called()
    helper.api.external_reference.create.assert_not_called()
    helper.api.stix_cyber_observable.add_external_reference.assert_not_called()

    helper.send_stix2_bundle.assert_called_once()
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    file_sco = next(o for o in payload["objects"] if o["type"] == "file")
    assert "stairwell:not-found" in file_sco["labels"]
    assert file_sco["hashes"]["SHA-256"] == SHA256
    assert any(
        ref["source_name"] == "Stairwell" for ref in file_sco["external_references"]
    )


def test_md5_fallback_attaches_transparency_label():
    metadata = {"mal_eval": {"probability_bucket": "PROBABILITY_MEDIUM"}}
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": []}),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber")

    md5_observable = {
        "id": "stix-cyber-observable--md5only",
        "standard_id": "file--md5only-aaaa-bbbb-cccc-dddddddddddd",
        "entity_type": "StixFile",
        "hashes": [{"algorithm": "MD5", "hash": "44d88612fea8a8f36de82e1278abb02f"}],
    }
    enricher.enrich(md5_observable)
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    file_sco = next(o for o in payload["objects"] if o["type"] == "file")
    assert "stairwell:hash-fallback-md5" in file_sco["labels"]
    # Ensure the API was called with the MD5 hash, not SHA256
    client.get_object_metadata.assert_called_once_with(
        "44d88612fea8a8f36de82e1278abb02f"
    )


def test_variants_capped_sorted_and_family_label():
    metadata = {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}}
    variants_payload = {
        "family": "WannaCry",
        "variant_count": 4,
        "variants": [
            {"sha256": "a" * 64, "sha1": "a" * 40, "md5": "a" * 32, "similarity": 0.50},
            {"sha256": "b" * 64, "sha1": "b" * 40, "md5": "b" * 32, "similarity": 0.95},
            {"sha256": "c" * 64, "sha1": "c" * 40, "md5": "c" * 32, "similarity": 0.80},
            # Self-reference must be filtered out:
            {"sha256": SHA256, "similarity": 1.0},
        ],
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, variants_payload),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber", variant_limit=2)

    msg = enricher.enrich(_observable_with_sha256())
    assert "variants 2" in msg

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    files = [o for o in payload["objects"] if o["type"] == "file"]
    # Source file + 2 variants (cap=2, self filtered)
    assert len(files) == 3

    # Derived-from relationships from each variant to the primary file
    derived = [
        o
        for o in payload["objects"]
        if o["type"] == "relationship" and o["relationship_type"] == "derived-from"
    ]
    assert len(derived) == 2

    # Top by similarity: b (0.95), c (0.80)
    variant_files = [f for f in files if f.get("hashes", {}).get("SHA-256") != SHA256]
    assert [f["hashes"]["SHA-256"] for f in variant_files] == ["b" * 64, "c" * 64]
    # Similarity is relative to this file, so it stays off the shared variant
    # objects and goes in the Variants Note.
    assert not [f for f in variant_files if "x_stairwell_variant_similarity" in f]

    # All three hashes propagated to variant SCOs
    top_variant = variant_files[0]
    assert [r["description"] for r in top_variant["external_references"]] == [
        f"Stairwell file detail for {'b' * 64}"
    ]
    assert top_variant["hashes"]["SHA-256"] == "b" * 64
    assert top_variant["hashes"]["SHA-1"] == "b" * 40
    assert top_variant["hashes"]["MD5"] == "b" * 32

    # Family label landed on source file
    source = next(f for f in files if f.get("hashes", {}).get("SHA-256") == SHA256)
    assert "stairwell:family-wannacry" in source["labels"]

    # Stairwell Variants Note exists alongside the consolidated summary
    notes = [o for o in payload["objects"] if o["type"] == "note"]
    var_note = next(n for n in notes if n["abstract"] == "Stairwell Variants")
    assert "Similarity" in var_note["content"]
    assert "95%" in var_note["content"]


def test_variants_accepts_confidence_synonym():
    # Forward-compat: if the API ever returns `confidence` instead of `similarity`,
    # we still pick it up.
    metadata = {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}}
    variants_payload = {
        "variants": [{"sha256": "d" * 64, "confidence": 0.42}],
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, variants_payload),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber", variant_limit=5)
    enricher.enrich(_observable_with_sha256())
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    var_note = next(
        o for o in payload["objects"] if o.get("abstract") == "Stairwell Variants"
    )
    assert "42%" in var_note["content"]


def test_variant_limit_zero_skips_variant_calls():
    metadata = {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}}
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": [{"sha256": "z" * 64}]}),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber", variant_limit=0)
    enricher.enrich(_observable_with_sha256())

    client.get_variants.assert_not_called()
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    assert all(
        o["type"] != "file"
        or o.get("id", "").endswith("dddddddddddd")
        or "x_stairwell_variant_confidence" not in o
        for o in payload["objects"]
    )


def test_sightings_aggregated_per_asset_with_count_first_last():
    metadata = {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}}
    sightings_payload = {
        "objectSightings": [
            # Asset RISER, two events
            {
                "sightingTime": "2025-04-29T19:42:30.534916301Z",
                "environment": "ENV-A",
                "asset": "assets/RISER-ID",
                "filename": "plugin_host.exe",
                "filepath": "C:\\\\foo\\\\",
                "assetName": "RISER",
            },
            {
                "sightingTime": "2025-04-30T16:03:02.856483963Z",
                "environment": "ENV-A",
                "asset": "assets/RISER-ID",
                "filename": "plugin_host.exe",
                "filepath": "C:\\\\bar\\\\",
                "assetName": "RISER",
            },
            # Asset BANNISTER, one event
            {
                "sightingTime": "2025-04-30T17:03:32.598679267Z",
                "environment": "ENV-A",
                "asset": "assets/BANNISTER-ID",
                "filename": "plugin_host.exe",
                "filepath": "C:\\\\baz\\\\",
                "assetName": "BANNISTER",
            },
        ],
        "nextPageToken": "",
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": []}),
            "list_object_sightings": (200, sightings_payload),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber", sightings_limit=100)
    enricher.enrich(_observable_with_sha256())

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    sightings = [o for o in payload["objects"] if o["type"] == "sighting"]
    identities = [
        o
        for o in payload["objects"]
        if o["type"] == "identity" and o.get("identity_class") == "system"
    ]
    assert len(sightings) == 2  # one per unique asset
    assert len(identities) == 2

    by_count = {s["count"]: s for s in sightings}
    assert set(by_count.keys()) == {1, 2}

    riser = by_count[2]
    assert riser["first_seen"].startswith("2025-04-29T19:42:30")
    assert riser["last_seen"].startswith("2025-04-30T16:03:02")
    # Enricher prefers standard_id (file--…) over the cyber-observable id
    assert riser["sighting_of_ref"].startswith("file--")
    assert len(riser["where_sighted_refs"]) == 1
    # The where_sighted_ref should point at one of our system identities
    assert riser["where_sighted_refs"][0] in {i["id"] for i in identities}
    # Confidence is the platform's to set, from the importing user's level.
    assert "confidence" not in riser

    riser_identity = next(
        i for i in identities if i["id"] == riser["where_sighted_refs"][0]
    )
    assert riser_identity["name"] == "assets/RISER-ID"
    assert "x_opencti_aliases" not in riser_identity
    assert "RISER" in riser_identity["description"]


def test_sightings_truncation_emits_note_and_stops_at_limit():
    metadata = {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}}
    # 5 unique assets but limit=2
    sightings_payload = {
        "objectSightings": [
            {
                "sightingTime": f"2025-04-{i:02d}T00:00:00.000000Z",
                "environment": "ENV-A",
                "asset": f"assets/HOST-{i}",
                "filename": "x.exe",
                "filepath": "C:\\\\",
                "assetName": f"HOST{i}",
            }
            for i in range(1, 6)
        ],
        "nextPageToken": "",
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": []}),
            "list_object_sightings": (200, sightings_payload),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber", sightings_limit=2)
    enricher.enrich(_observable_with_sha256())

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    sightings = [o for o in payload["objects"] if o["type"] == "sighting"]
    assert len(sightings) == 2

    notes = [o for o in payload["objects"] if o["type"] == "note"]
    truncation_note = next(
        (n for n in notes if "Sightings Truncation" in n["abstract"]), None
    )
    assert truncation_note is not None
    assert "STAIRWELL_SIGHTINGS_LIMIT=2" in truncation_note["content"]


def test_sightings_limit_zero_skips_call():
    metadata = {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}}
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": []}),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber", sightings_limit=0)
    enricher.enrich(_observable_with_sha256())
    client.list_object_sightings.assert_not_called()


def test_sightings_empty_payload_emits_no_sighting_objects():
    metadata = {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}}
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": []}),
            # Default list_object_sightings via _client returns empty
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber", sightings_limit=100)
    enricher.enrich(_observable_with_sha256())

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    assert not [o for o in payload["objects"] if o["type"] == "sighting"]
    assert not [
        o
        for o in payload["objects"]
        if o["type"] == "identity" and o.get("identity_class") == "system"
    ]


def test_metadata_properties_landed_on_file_sco():
    metadata = {
        "name": "evil.exe",
        "size": 12345,
        "mimeType": "application/x-msdownload",
        "magic": "PE32 executable",
        "imphash": "abc123",
        "imphashSorted": "sortedabc",
        "tlsh": "T1ABC",
        "shannonEntropy": 7.42,
        "stairwellFirstSeenTime": "2025-04-29T19:00:00Z",
        "environments": ["ENV-A", "ENV-B"],
        "tags": [
            {"name": "campaign", "value": "WannaCry", "environment": "ENV-A"},
            {"name": "yolo", "value": "", "environment": "ENV-A"},
        ],
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": []}),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber")
    enricher.enrich(_observable_with_sha256())

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    file_sco = next(o for o in payload["objects"] if o["type"] == "file")
    assert file_sco["name"] == "evil.exe"
    assert file_sco["size"] == 12345
    assert file_sco["mime_type"] == "application/x-msdownload"
    assert file_sco["x_stairwell_magic"] == "PE32 executable"
    assert file_sco["x_stairwell_imphash"] == "abc123"
    assert file_sco["x_stairwell_imphash_sorted"] == "sortedabc"
    assert file_sco["x_stairwell_tlsh"] == "T1ABC"
    assert file_sco["x_stairwell_shannon_entropy"] == 7.42
    assert file_sco["x_stairwell_first_seen"] == "2025-04-29T19:00:00Z"
    assert file_sco["x_stairwell_environments"] == ["ENV-A", "ENV-B"]
    assert "stairwell:tag:campaign=WannaCry" in file_sco["labels"]
    assert "stairwell:tag:yolo" in file_sco["labels"]


def test_summary_note_consolidates_all_user_specified_fields():
    metadata = {
        "name": "evil.exe",
        "size": 12345,
        "md5": "a" * 32,
        "sha1": "b" * 40,
        "sha256": "c" * 64,
        "sha3256": "d" * 64,
        "mimeType": "application/x-msdownload",
        "magic": "PE32 executable",
        "imphash": "abc123",
        "imphashSorted": "sortedabc",
        "tlsh": "T1ABC",
        "shannonEntropy": 7.42,
        "stairwellFirstSeenTime": "2025-04-29T19:00:00Z",
        "yaraRuleMatches": ["Win_Trojan_WannaCry", "Win_Worm_WannaCry"],
        "networkIndicators": {
            "ipAddresses": ["8.8.8.8"],
            "hostnames": ["evil.example.com"],
            "urls": ["http://evil.example.com/x"],
        },
        "objectSignature": {
            "x509Certificates": [
                {
                    "signature": "MEQCIGNlcnQtc2lnbmF0dXJlLWJ5dGVzLWV4YW1wbGU=",
                    "issuer": "CN=Evil CA",
                    "subject": "CN=Bad",
                    "earliestValidTime": "2024-01-01T00:00:00Z",
                    "latestValidTime": "2025-01-01T00:00:00Z",
                }
            ],
            "pkcs7VerificationResult": "PKCS7_VERIFICATION_RESULT_VALID",
        },
        "malEval": {
            "probabilityBucket": "PROBABILITY_VERY_HIGH",
            "severity": "SEVERITY_HIGH",
            "labels": ["VB:Trojan.X"],
        },
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {"summary": "ignored"}),
            "get_variants": (200, {"variants": []}),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber")
    enricher.enrich(_observable_with_sha256())

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    notes = [o for o in payload["objects"] if o["type"] == "note"]
    abstracts = [n["abstract"] for n in notes]
    # Only the consolidated summary Note is emitted by Stairwell.
    # Summary is present alongside AI Triage (the Triage Note is whatever the
    # `summarize_file` mock returned — non-empty here triggers it).
    assert "Stairwell Enrichment Summary" in abstracts
    assert "Stairwell AI File Triage" in abstracts
    # Old consolidated-into-summary notes must NOT come back.
    assert "Stairwell Analysis Summary" not in abstracts
    assert "Stairwell Environment Prevalence" not in abstracts

    body = notes[0]["content"]
    # Hashes section
    assert "## Hashes" in body
    assert f"`{'a' * 32}`" in body  # md5
    assert f"`{'b' * 40}`" in body  # sha1
    assert f"`{'c' * 64}`" in body  # sha256
    assert f"`{'d' * 64}`" in body  # sha3256
    # File properties
    assert "## File properties" in body
    assert "**Name:** `evil.exe`" in body
    assert "**Size:** 12.35 KB" in body
    assert "**MIME type:** `application/x-msdownload`" in body
    assert "**Magic:** `PE32 executable`" in body
    assert "**Shannon entropy:** 7.4200" in body
    assert "**imphash:** `abc123`" in body
    assert "**imphash (sorted):** `sortedabc`" in body
    assert "**TLSH:** `T1ABC`" in body
    # Stairwell observation
    assert "## Stairwell observation" in body
    assert "**First seen:** 2025-04-29T19:00:00Z" in body
    assert "**MalEval verdict:** `PROBABILITY_VERY_HIGH`" in body
    assert "**MalEval severity:** `SEVERITY_HIGH`" in body
    assert "**MalEval labels:** `VB:Trojan.X`" in body
    # YARA matches
    assert "## YARA matches" in body
    assert "Win_Trojan_WannaCry" in body
    assert "Win_Worm_WannaCry" in body
    # Network indicators
    assert "## Network indicators" in body
    assert "8.8.8.8" in body
    assert "evil.example.com" in body
    assert "http://evil.example.com/x" in body
    # Object signature
    assert "## Object signature" in body
    assert "**PKCS7 verification:** `PKCS7_VERIFICATION_RESULT_VALID`" in body
    assert "CN=Evil CA" in body
    assert "CN=Bad" in body


def test_lineage_emits_parents_and_children_with_derived_from():
    primary = SHA256
    parent = "e" * 64
    child = "c" * 64
    metadata = {
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "relationships": {
            "parents": [
                {"sha256": parent, "relation": "OBJECT_RELATION_TYPE_UNSPECIFIED"},
                # Self-reference must be filtered
                {"sha256": primary, "relation": "OBJECT_RELATION_TYPE_UNSPECIFIED"},
            ],
            "children": [
                {"sha256": child, "relation": "OBJECT_RELATION_TYPE_UNSPECIFIED"},
            ],
        },
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": []}),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber")
    enricher.enrich(_observable_with_sha256())

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    derived = [
        o
        for o in payload["objects"]
        if o["type"] == "relationship" and o["relationship_type"] == "derived-from"
    ]
    # 1 parent (self filtered) + 1 child = 2 derived-from rels
    assert len(derived) == 2

    files = [o for o in payload["objects"] if o["type"] == "file"]
    parent_files = [f for f in files if f.get("hashes", {}).get("SHA-256") == parent]
    child_files = [f for f in files if f.get("hashes", {}).get("SHA-256") == child]
    assert len(parent_files) == 1
    assert len(child_files) == 1

    # Direction: this_file → parent (derived-from), child → this_file (derived-from)
    parent_id = parent_files[0]["id"]
    child_id = child_files[0]["id"]
    primary_id = next(
        f["id"] for f in files if f.get("hashes", {}).get("SHA-256") == primary
    )
    rel_to_parent = next(r for r in derived if r["target_ref"] == parent_id)
    assert rel_to_parent["source_ref"] == primary_id
    rel_from_child = next(r for r in derived if r["source_ref"] == child_id)
    assert rel_from_child["target_ref"] == primary_id


def test_signing_certificates_are_listed_in_the_note_not_as_observables():
    """Stairwell's X509Certificate carries signature bytes (base64 in JSON),
    issuer, subject, and validity, with no fingerprint or serial number, so a
    certificate has no stable STIX ID; it is reported in the summary Note."""
    signature = "MEUCIQDf3s4Yb2h0aGlzaXNub3RhcmVhbHNpZ25hdHVyZQ=="
    metadata = {
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "objectSignature": {
            "x509Certificates": [
                {
                    "signature": signature,
                    "issuer": "CN=Evil CA",
                    "subject": "CN=Bad Subject",
                    "earliestValidTime": "2024-01-01T00:00:00Z",
                    "latestValidTime": "2025-01-01T00:00:00Z",
                }
            ],
            "pkcs7VerificationResult": "PKCS7_VERIFICATION_RESULT_VALID",
        },
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": []}),
        }
    )
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber").enrich(_observable_with_sha256())
    objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
    assert not [o for o in objects if o["type"] == "x509-certificate"]
    note = next(
        o["content"]
        for o in objects
        if o["type"] == "note" and o["abstract"] == "Stairwell Enrichment Summary"
    )
    for text in ("CN=Bad Subject", "CN=Evil CA", "2024-01-01T00:00:00Z", signature):
        assert text in note


def test_detonation_data_is_not_in_bundle():
    metadata = {
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "detonation": {
            "overview": "MUST NOT APPEAR",
            "executedCommands": ["rm -rf /"],
            "mutexes": ["Global\\Evil"],
            "registryKeys": [{"registryKey": "HKLM\\bad", "action": "WRITE"}],
            "mitreAttackTtps": [{"ttp": "T1027", "signature": "Obfuscated"}],
            "signatures": ["YARA_xyz"],
            "droppedFiles": ["C:\\evil.dll"],
            "detections": [{"family": "WannaCry"}],
        },
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {"variants": []}),
        }
    )
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber")
    enricher.enrich(_observable_with_sha256())
    bundle_json = helper.send_stix2_bundle.call_args[0][0]
    # Hard guarantee: nothing detonation-flavored ever leaks into the bundle.
    for needle in (
        "MUST NOT APPEAR",
        "rm -rf /",
        "Global\\\\Evil",
        "HKLM\\\\bad",
        "T1027",
        "attack-pattern",
        "YARA_xyz",
        "evil.dll",
    ):
        assert needle not in bundle_json, f"Detonation leak: {needle!r}"


def test_no_hashes_returns_skip_message():
    client = _client({})
    helper = _helper()
    enricher = FileEnricher(helper, client, default_tlp="amber")
    msg = enricher.enrich(
        {
            "id": "stix-cyber-observable--empty",
            "standard_id": "file--empty",
            "entity_type": "StixFile",
            "hashes": [],
        }
    )
    assert "No usable hash" in msg
    helper.send_stix2_bundle.assert_not_called()


def test_untrusted_strings_are_markdown_escaped_in_notes_and_description():
    from connector.stix_builder import md_code, md_prose, md_text

    name = "x`](http://evil.example)`.exe"
    yara = "rule`[x](http://evil.example)"
    host = "www.evil.example"
    subject = "CN=a`b | c"
    path = "C:\\`x`\\"
    asset_name = "[asset](http://evil.example)"
    family = "Fam [x](http://evil.example)"
    tldr = "see [here](http://evil.example)"
    summary = "## Triage\n\n![px](http://t.example/p.png)"
    metadata = {
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "name": name,
        "yaraRuleMatches": [yara],
        "networkIndicators": {"hostnames": [host]},
        "objectSignature": {"x509Certificates": [{"subject": subject}]},
    }
    variant_sha = "b" * 64
    sightings = {
        "objectSightings": [
            {
                "sightingTime": "2025-04-29T19:42:30.5Z",
                "environment": "ENV-A",
                "asset": "assets/A",
                "assetName": asset_name,
                "filepath": path,
                "filename": "f.exe",
            }
        ],
        "nextPageToken": "",
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {"tldr": tldr, "summary": summary}),
            "get_variants": (
                200,
                {
                    "family": family,
                    "variants": [{"sha256": variant_sha, "similarity": 0.9}],
                },
            ),
            "list_object_sightings": (200, sightings),
        }
    )
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber", sightings_limit=100).enrich(
        _observable_with_sha256()
    )
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    notes = {
        o["abstract"]: o["content"] for o in payload["objects"] if o["type"] == "note"
    }

    enrichment = notes["Stairwell Enrichment Summary"]
    assert f"- **Name:** {md_code(name)}" in enrichment
    assert f"- {md_code(yara)}" in enrichment
    assert md_code(host) in enrichment
    assert f"  - Subject: {md_code(subject)}" in enrichment

    assert notes["Stairwell AI File Triage"].endswith(md_prose(summary))
    file_sco = next(
        o
        for o in payload["objects"]
        if o.get("id") == _observable_with_sha256()["standard_id"]
    )
    assert file_sco["x_opencti_description"] == md_prose(tldr)

    variants = notes["Stairwell Variants"]
    assert f"**Family:** {md_text(family)}" in variants
    assert "/dashboard/search/knowledge/" + "b" * 64 + ")" in variants

    sighting = next(o for o in payload["objects"] if o["type"] == "sighting")
    assert f"- {md_code(path + 'f.exe')}" in sighting["description"]
    identity = next(
        o
        for o in payload["objects"]
        if o["type"] == "identity" and o.get("identity_class") == "system"
    )
    assert md_text(asset_name) in identity["description"]


def _enrich_with_variant_counts(payload_count, metadata_total):
    metadata = {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}}
    if metadata_total is not None:
        metadata["variants"] = {"total": metadata_total}
    variants_payload = {
        "variants": [{"sha256": f"{i:064x}", "similarity": 0.9} for i in range(1, 4)],
    }
    if payload_count is not None:
        variants_payload["variant_count"] = payload_count
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, variants_payload),
        }
    )
    helper = _helper()
    msg = FileEnricher(helper, client, default_tlp="amber", variant_limit=2).enrich(
        _observable_with_sha256()
    )
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    note = next(
        o["content"]
        for o in payload["objects"]
        if o["type"] == "note" and o["abstract"] == "Stairwell Variants"
    )
    file_sco = next(
        o
        for o in payload["objects"]
        if o.get("id") == _observable_with_sha256()["standard_id"]
    )
    return msg, note, file_sco


@pytest.mark.parametrize(
    "payload_count, metadata_total, want_total, want_sco_count",
    [
        (42, 42, 42, 42),
        ("42", "42", 42, 42),  # proto3 JSON encodes int64 as a string
        ("lots", "n/a", 3, None),  # unparseable: fall back to the list length
        (None, None, 3, None),
        (True, True, 3, None),
        (-1, -1, 3, None),
        ("\u00b2", "\u00b3", 3, None),  # isdigit() is True for superscripts
    ],
)
def test_variant_counts_tolerate_non_numeric_api_values(
    payload_count, metadata_total, want_total, want_sco_count
):
    msg, note, file_sco = _enrich_with_variant_counts(payload_count, metadata_total)
    assert msg.startswith("Enriched file")
    assert f"**Total variants:** {want_total}\n" in note
    assert "(capped at STAIRWELL_VARIANT_LIMIT=2)" in note
    assert file_sco.get("x_stairwell_variant_count") == want_sco_count


def test_sightings_are_off_unless_configured():
    from connector.enricher import Dispatcher
    from connector.file_enricher import DEFAULT_SIGHTINGS_LIMIT

    # main.py reads this constant as the STAIRWELL_SIGHTINGS_LIMIT default.
    assert DEFAULT_SIGHTINGS_LIMIT == 0
    client = _client(
        {
            "get_object_metadata": (
                200,
                {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}},
            ),
            "summarize_file": (200, {}),
            "get_variants": (200, {}),
        }
    )
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber").enrich(_observable_with_sha256())
    Dispatcher(helper, client, "amber").file.enrich(_observable_with_sha256())
    client.list_object_sightings.assert_not_called()
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    assert not [o for o in payload["objects"] if o["type"] == "sighting"]


def test_malformed_variant_and_lineage_hashes_are_skipped():
    good_variant, good_parent = "a1" * 32, "e" * 64
    metadata = {
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "relationships": {
            "parents": [{"sha256": good_parent}, {"sha256": "p" * 64}],
            "children": [{"sha256": "c" * 63 + ")"}],
        },
    }
    variants = {
        "variants": [
            {"sha256": good_variant, "similarity": 0.9},
            {"sha256": "b" * 63 + ")", "similarity": 0.8},
            {"sha256": "not-a-hash", "similarity": 0.7},
        ]
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, variants),
        }
    )
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber").enrich(_observable_with_sha256())
    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    file_hashes = sorted(
        o["hashes"]["SHA-256"]
        for o in payload["objects"]
        if o["type"] == "file" and o["id"] != _observable_with_sha256()["standard_id"]
    )
    assert file_hashes == sorted([good_variant, good_parent])


def test_sightings_keep_paging_for_assets_already_kept():
    def event(asset, t):
        return {"asset": asset, "assetName": asset, "sightingTime": t}

    pages = [
        (
            200,
            {
                "objectSightings": [
                    event("assets/A", "2026-01-01T00:00:00Z"),
                    event("assets/B", "2026-01-02T00:00:00Z"),
                ],
                "nextPageToken": "p2",
            },
        ),
        (
            200,
            {
                # C is over the limit; A's later event must still be counted.
                "objectSightings": [
                    event("assets/C", "2026-01-03T00:00:00Z"),
                    event("assets/A", "2026-01-04T00:00:00Z"),
                ],
                "nextPageToken": "p3",
            },
        ),
        (
            200,
            {
                "objectSightings": [event("assets/A", "2026-01-05T00:00:00Z")],
                "nextPageToken": "",
            },
        ),
    ]
    client = _client(
        {
            "get_object_metadata": (
                200,
                {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}},
            ),
            "summarize_file": (200, {}),
            "get_variants": (200, {}),
        }
    )
    client.list_object_sightings = MagicMock(side_effect=pages)
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber", sightings_limit=2).enrich(
        _observable_with_sha256()
    )
    assert client.list_object_sightings.call_count == 3
    objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
    sightings = {
        s["description"].split("`")[1]: s for s in objects if s["type"] == "sighting"
    }
    assert set(sightings) == {"assets/A", "assets/B"}
    assert sightings["assets/A"]["count"] == 3
    assert sightings["assets/A"]["last_seen"] == "2026-01-05T00:00:00.000Z"
    assert any(o.get("abstract") == "Stairwell Sightings Truncation" for o in objects)
    assert not any(
        o.get("abstract") == "Stairwell Sightings Incomplete" for o in objects
    )


def test_metadata_hash_backfill_skips_malformed_values():
    metadata = {
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "sha1": "z" * 40,
        "md5": "D" * 32,
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {}),
        }
    )
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber").enrich(_observable_with_sha256())
    objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
    sco = next(
        o for o in objects if o["id"] == _observable_with_sha256()["standard_id"]
    )
    assert sco["hashes"] == {"SHA-256": SHA256, "MD5": "d" * 32}


@pytest.mark.parametrize("status", [401, 500, 0])
def test_failed_metadata_fetch_raises_instead_of_completing(status):
    client = _client({"get_object_metadata": (status, None)})
    helper = _helper()
    with pytest.raises(DataRetrievalError, match=str(status)):
        FileEnricher(helper, client, default_tlp="amber").enrich(
            _observable_with_sha256()
        )
    helper.send_stix2_bundle.assert_not_called()


def test_flat_yara_matches_become_labels_as_well_as_note_lines():
    metadata = {
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "yaraRuleMatches": ["Flat_Rule", "Nested_Rule"],
        "yara_results": {"matches": [{"rule_name": "Nested_Rule"}]},
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {}),
        }
    )
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber").enrich(_observable_with_sha256())
    objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
    file_sco = next(o for o in objects if o["type"] == "file")
    assert "stairwell:yara:Flat_Rule" in file_sco["labels"]
    assert file_sco["labels"].count("stairwell:yara:Nested_Rule") == 1
    note = next(
        o for o in objects if o.get("abstract") == "Stairwell Enrichment Summary"
    )
    assert note["content"].count("`Nested_Rule`") == 1
    assert "`Flat_Rule`" in note["content"]


def _sightings_run(pages):
    client = _client(
        {
            "get_object_metadata": (
                200,
                {"mal_eval": {"probability_bucket": "PROBABILITY_HIGH"}},
            ),
            "summarize_file": (200, {}),
            "get_variants": (200, {}),
        }
    )
    client.list_object_sightings = MagicMock(side_effect=pages)
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber", sightings_limit=1).enrich(
        _observable_with_sha256()
    )
    return client, json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]


def _page(token):
    return (
        200,
        {
            "objectSightings": [
                {
                    "asset": "assets/A",
                    "assetName": "A",
                    "sightingTime": "2026-01-01T00:00:00Z",
                }
            ],
            "nextPageToken": token,
        },
    )


def test_sightings_note_pagination_stopped_at_the_page_limit():
    client, objects = _sightings_run([_page("more")] * 60)
    assert client.list_object_sightings.call_count == 50
    abstracts = [o.get("abstract") for o in objects]
    assert "Stairwell Sightings Incomplete" in abstracts
    # Only one asset exists, so none were dropped.
    assert "Stairwell Sightings Truncation" not in abstracts
    sighting = next(o for o in objects if o["type"] == "sighting")
    assert sighting["count"] == 50


def test_sightings_note_a_later_page_failure():
    _, objects = _sightings_run([_page("p2"), (503, None)])
    note = next(
        o for o in objects if o.get("abstract") == "Stairwell Sightings Incomplete"
    )
    assert "503" in note["content"]
    assert any(o["type"] == "sighting" for o in objects)


def test_note_lists_exactly_the_network_values_that_became_observables():
    metadata = {
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "network_indicators": {
            "ip_addresses": ["8.8.8.8", "999.1.1.1", "2001:DB8::1"],
            "hostnames": ["C2.Example.com"],
            "urls": ["http://c2.example.com/x", "http://user@", "http://h:0/"],
        },
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {}),
        }
    )
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber").enrich(_observable_with_sha256())
    objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
    observed = {
        o["value"]
        for o in objects
        if o["type"] in ("ipv4-addr", "ipv6-addr", "domain-name", "url")
    }
    assert observed == {
        "8.8.8.8",
        "2001:db8::1",
        "c2.example.com",
        "http://c2.example.com/x",
    }
    note = next(
        o for o in objects if o.get("abstract") == "Stairwell Enrichment Summary"
    )
    section = note["content"].split("## Network indicators")[1].split("##")[0]
    listed = set(re.findall(r"`([^`]+)`", section))
    assert listed == observed


_MD5 = "44d88612fea8a8f36de82e1278abb02f"
_MD5_OBS = {
    "id": "stix-cyber-observable--md5only",
    "standard_id": "file--md5only-aaaa-bbbb-cccc-dddddddddddd",
    "entity_type": "StixFile",
    "hashes": [{"algorithm": "MD5", "hash": _MD5}],
}
_OTHER = "b" * 64


def _fallback_run():
    """An MD5-only observable whose metadata names its own SHA-256."""
    metadata = {
        "sha256": SHA256,
        "md5": _MD5,
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "relationships": {
            "parents": [{"sha256": SHA256}, {"sha256": _OTHER}],
            "children": [{"sha256": SHA256.upper()}],
        },
    }
    variants = {
        "variants": [
            {"sha256": SHA256, "similarity": 1.0},
            {"sha256": "c" * 64, "similarity": 0.9},
        ]
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {"tldr": "t", "summary": "Long writeup"}),
            "get_variants": (200, variants),
        }
    )
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber").enrich(dict(_MD5_OBS))
    return json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]


def test_fallback_triage_note_names_the_hash_actually_used():
    objects = _fallback_run()
    note = next(o for o in objects if o.get("abstract") == "Stairwell AI File Triage")
    assert note["content"].startswith(f"**MD5:** `{_MD5}`")
    assert "SHA-256" not in note["content"].split("\n")[0]


def test_fallback_never_links_the_file_to_itself():
    objects = _fallback_run()
    files = [o for o in objects if o["type"] == "file"]
    shas = [f.get("hashes", {}).get("SHA-256") for f in files]
    # The enriched file itself, plus one lineage parent and one variant.
    assert sorted(shas) == sorted([SHA256, _OTHER, "c" * 64])
    entity_id = _MD5_OBS["standard_id"]
    rels = [o for o in objects if o["type"] == "relationship"]
    assert all(r["source_ref"] != r["target_ref"] for r in rels)
    assert len([r for r in rels if r["relationship_type"] == "derived-from"]) == 2
    assert all(entity_id in (r["source_ref"], r["target_ref"]) for r in rels)


def test_summary_note_carries_the_values_opencti_drops_from_the_observable():
    # pycti's observable import keeps a fixed set of File fields, so custom
    # x_stairwell_* properties never reach OpenCTI; the Note must carry them.
    metadata = {
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "prevalence": 0.0123,
        "variants": {"total": 7},
        "environments": ["env-1", "env-2"],
    }
    client = _client(
        {
            "get_object_metadata": (200, metadata),
            "summarize_file": (200, {}),
            "get_variants": (200, {}),
        }
    )
    helper = _helper()
    FileEnricher(helper, client, default_tlp="amber").enrich(_observable_with_sha256())
    objects = json.loads(helper.send_stix2_bundle.call_args[0][0])["objects"]
    note = next(
        o for o in objects if o.get("abstract") == "Stairwell Enrichment Summary"
    )
    content = note["content"]
    assert "**Prevalence:** 0.0123" in content
    assert "**Variants:** 7" in content
    assert "**Environments:** `env-1`, `env-2`" in content
