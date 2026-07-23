import json
from unittest.mock import MagicMock

from connector.file_enricher import FileEnricher
from connector.stairwell import StairwellClient

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
    # Either x_opencti_score is not present (we omit when not raising),
    # or it's still the existing 80 — never the proposed 25.
    assert file_sco.get("x_opencti_score", 80) == 80


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

    # Derived-from relationships from source to each variant
    derived = [
        o
        for o in payload["objects"]
        if o["type"] == "relationship" and o["relationship_type"] == "derived-from"
    ]
    assert len(derived) == 2

    # Top by similarity: b (0.95), c (0.80)
    variant_files = [f for f in files if f.get("hashes", {}).get("SHA-256") != SHA256]
    sims = [f["x_stairwell_variant_similarity"] for f in variant_files]
    assert sims == sorted(sims, reverse=True)
    assert sims[0] == 0.95

    # All three hashes propagated to variant SCOs
    top_variant = next(
        f for f in variant_files if f["x_stairwell_variant_similarity"] == 0.95
    )
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
    variant_files = [
        f
        for f in payload["objects"]
        if f["type"] == "file" and f.get("hashes", {}).get("SHA-256") == "d" * 64
    ]
    assert variant_files[0]["x_stairwell_variant_similarity"] == 0.42


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
    enricher = FileEnricher(helper, client, default_tlp="amber")
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
    # Confidence should reflect the file's HIGH bucket
    assert riser["confidence"] == 75

    riser_identity = next(
        i for i in identities if i["id"] == riser["where_sighted_refs"][0]
    )
    assert riser_identity["name"] == "RISER"


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
    enricher = FileEnricher(helper, client, default_tlp="amber")
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
                    "signature": "SIG-1",
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
    parent = "p" * 64
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


def test_x509_certificates_emitted_with_relationship():
    metadata = {
        "mal_eval": {"probability_bucket": "PROBABILITY_HIGH"},
        "objectSignature": {
            "x509Certificates": [
                {
                    "signature": "SIG-FINGERPRINT-1",
                    "issuer": "CN=Evil CA",
                    "subject": "CN=Bad Subject",
                    "earliestValidTime": "2024-01-01T00:00:00Z",
                    "latestValidTime": "2025-01-01T00:00:00Z",
                },
                {
                    # No signature → filtered
                    "subject": "CN=Phantom",
                },
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
    enricher = FileEnricher(helper, client, default_tlp="amber")
    enricher.enrich(_observable_with_sha256())

    payload = json.loads(helper.send_stix2_bundle.call_args[0][0])
    certs = [o for o in payload["objects"] if o["type"] == "x509-certificate"]
    assert len(certs) == 1
    assert certs[0]["issuer"] == "CN=Evil CA"
    assert certs[0]["subject"] == "CN=Bad Subject"
    assert certs[0]["validity_not_before"] == "2024-01-01T00:00:00Z"
    cert_rels = [
        r
        for r in payload["objects"]
        if r["type"] == "relationship"
        and r["target_ref"] == certs[0]["id"]
        and r["relationship_type"] == "related-to"
    ]
    assert len(cert_rels) == 1


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
