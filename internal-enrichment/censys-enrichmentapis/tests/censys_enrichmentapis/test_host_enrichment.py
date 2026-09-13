import stix2
from censys_enrichmentapis.client import Client
from censys_enrichmentapis.converters.host import HostConverter
from censys_platform import HostEnrichment, HostEnrichmentService, Label, Reputation
from censys_platform.models.reputation_evidence import ReputationEvidence, ReputationEvidenceFeature


def _get_host_245_52_sample() -> dict:
    """Generate mock sample data for host 193.233.245.52 with OpenSSH vulnerabilities."""
    return {
        "ip": "193.233.245.52",
        "services": [
            {
                "port": 22,
                "protocol": "SSH",
                "scan_time": "2026-08-29T19:57:34.651481661Z",
                "labels": [],
                "vulns": [
                    {
                        "id": "CVE-2026-35385",
                        "name": "CVE-2026-35385",
                        "severity": "HIGH",
                        "metrics": {
                            "cvss_v31": {
                                "score": 7.5,
                                "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
                                "components": {
                                    "attack_vector": "NETWORK",
                                    "attack_complexity": "HIGH",
                                    "privileges_required": "NONE",
                                    "user_interaction": "REQUIRED",
                                    "scope": "UNCHANGED",
                                    "confidentiality": "HIGH",
                                    "integrity": "HIGH",
                                    "availability": "HIGH"
                                }
                            },
                            "epss": {
                                "score": 0.006,
                                "percentile": 0.466
                            }
                        },
                        "evidence": [
                            {
                                "found_value": "cpe:2.3:a:openbsd:openssh:10.2p1:*:*:*:*:*:*:*"
                            }
                        ]
                    },
                    {
                        "id": "CVE-2026-35386",
                        "name": "CVE-2026-35386",
                        "severity": "LOW",
                        "metrics": {
                            "cvss_v31": {
                                "score": 3.6,
                                "vector": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
                                "components": {
                                    "attack_vector": "LOCAL",
                                    "attack_complexity": "HIGH",
                                    "privileges_required": "LOW",
                                    "user_interaction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentiality": "LOW",
                                    "integrity": "LOW",
                                    "availability": "NONE"
                                }
                            },
                            "epss": {
                                "score": 0.003,
                                "percentile": 0.242
                            }
                        },
                        "evidence": [
                            {
                                "found_value": "cpe:2.3:a:openbsd:openssh:10.2p1:*:*:*:*:*:*:*"
                            }
                        ]
                    },
                    {
                        "id": "CVE-2026-35387",
                        "name": "CVE-2026-35387",
                        "severity": "LOW",
                        "metrics": {
                            "cvss_v31": {
                                "score": 3.1,
                                "vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N",
                                "components": {
                                    "attack_vector": "NETWORK",
                                    "attack_complexity": "HIGH",
                                    "privileges_required": "LOW",
                                    "user_interaction": "NONE",
                                    "scope": "UNCHANGED",
                                    "confidentiality": "NONE",
                                    "integrity": "LOW",
                                    "availability": "NONE"
                                }
                            },
                            "epss": {
                                "score": 0.002,
                                "percentile": 0.146
                            }
                        },
                        "evidence": [
                            {
                                "found_value": "cpe:2.3:a:openbsd:openssh:10.2p1:*:*:*:*:*:*:*"
                            }
                        ]
                    }
                ],
                "software": [
                    {
                        "cpe": "cpe:2.3:a:openbsd:openssh:10.2p1:*:*:*:*:*:*:*",
                        "product": "openssh",
                        "vendor": "openbsd",
                        "version": "10.2p1"
                    }
                ]
            }
        ]
    }


def test_converter_adds_threat_names_to_primary_observable_labels() -> None:
    """Verify that threat names are added to primary observable labels with Censys_ prefix in snake_case."""
    service = HostEnrichmentService(
        port=22,
        protocol="SSH",
        scan_time="2026-08-31T13:12:28Z",
    )
    service.__dict__["threats"] = [
        {
            "id": "THREAT-SSH",
            "name": "Exposed SSH Service",
            "source": "censys",
            "confidence": 1.0,
            "type": ["remote_access"],
            "tactic": ["initial_access"],
            "evidence": [],
            "malware": {}
        },
        {
            "id": "THREAT-WEAK-CREDS",
            "name": "Weak Credentials",
            "source": "censys",
            "confidence": 0.8,
            "type": ["credential_access"],
            "tactic": ["credential_access"],
            "evidence": [],
            "malware": {}
        }
    ]

    host = HostEnrichment(services=[service])
    converter = HostConverter()
    stix_objects = [
        octi_object.to_stix2_object()
        for octi_object in converter.to_stix(
            observable=stix2.IPv4Address(value="1.1.1.1"),
            data=host
        )
    ]

    # Verify threat names are in primary observable labels with Censys_ prefix
    assert "Censys_Exposed_SSH_Service" in converter.primary_observable_labels
    assert "Censys_Weak_Credentials" in converter.primary_observable_labels


def test_converter_host_enrichment_adds_service_labels_as_note() -> None:
    stix_objects = [
        octi_object.to_stix2_object()
        for octi_object in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="1.1.1.1"),
            data=HostEnrichment(
                services=[
                    HostEnrichmentService(
                        port=22,
                        scan_time="2025-11-03T12:35:48Z",
                        labels=[Label(value="REMOTE_ACCESS")],
                    )
                ]
            ),
        )
    ]

    notes = [stix_object for stix_object in stix_objects if stix_object.type == "note"]
    assert len(notes) == 1
    assert notes[0].abstract == "Service information on port 22 (Unknown)"
    assert "- Scan Time: 2025-11-03T12:35:48Z" in notes[0].content
    assert "- Labels" in notes[0].content
    assert " - REMOTE_ACCESS" in notes[0].content


def test_converter_adds_external_reputation_note() -> None:
    stix_objects = [
        octi_object.to_stix2_object()
        for octi_object in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="1.1.1.1"),
            data=HostEnrichment(
                reputation=Reputation(
                    score=0.42,
                    label="MEDIUM_RISK",
                    model_version="0.1.0",
                )
            ),
        )
    ]

    note = next(stix_object for stix_object in stix_objects if stix_object.type == "note")
    assert note.abstract == "Censys host reputation"
    # Check the content contains the expected parts (no evidence features since none provided)
    assert "- Score: 42" in note.content
    assert "- Label: MEDIUM_RISK" in note.content
    assert "- Model version: 0.1.0" in note.content
    # Should not have evidence features section
    assert "**Evidence Features:**" not in note.content
    assert note.labels == ["MEDIUM_RISK"]
    assert note.note_types == ["external"]


def test_converter_adds_reputation_note_with_evidence() -> None:
    """Verify that reputation note includes evidence features.

    Uses realistic reputation structure from Censys API with ReputationEvidence objects.
    """
    # Create reputation with evidence features matching Censys API structure
    host_enrichment = HostEnrichment(
        reputation=Reputation(
            score=0.704,
            label="SUSPICIOUS",
            model_version="2.0.0",
        )
    )

    # Inject evidence as ReputationEvidence objects with feature field
    # This mirrors the actual API response structure
    host_enrichment.reputation.__dict__["evidence"] = [
        ReputationEvidence(
            feature=ReputationEvidenceFeature(
                id="max_port",
                name="Max Port",
                value="49093",
                contribution=8.708259985239051,
                category="service_surface"
            )
        ),
        ReputationEvidence(
            feature=ReputationEvidenceFeature(
                id="high_port_ratio",
                name="High Port Ratio",
                value="0.875",
                contribution=5.341544169693149,
                category="service_surface"
            )
        ),
        ReputationEvidence(
            feature=ReputationEvidenceFeature(
                id="avg_epss_score",
                name="Avg EPSS Score",
                value="0.0937",
                contribution=-3.738838369305972,
                category="vulnerability_exposure"
            )
        ),
    ]

    stix_objects = [
        octi_object.to_stix2_object()
        for octi_object in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="104.168.107.43"),
            data=host_enrichment,
        )
    ]

    note = next(stix_object for stix_object in stix_objects if stix_object.type == "note")
    assert note.abstract == "Censys host reputation"

    # Verify score information
    assert "- Score: 70" in note.content
    assert "- Label: SUSPICIOUS" in note.content
    assert "- Model version: 2.0.0" in note.content

    # Verify evidence features are included with proper formatting
    assert "**Evidence Features:**" in note.content
    assert "| Feature | Value | Contribution | Category |" in note.content
    assert "| Max Port | 49093 | +8.71% | service_surface |" in note.content
    assert "| High Port Ratio | 0.875 | +5.34% | service_surface |" in note.content
    assert (
        "| Avg EPSS Score | 0.0937 | -3.74% | "
        "vulnerability_exposure |" in note.content
    )

    assert note.labels == ["SUSPICIOUS"]
    assert note.note_types == ["external"]


def test_converter_links_service_cves_through_software() -> None:
    sample = _get_host_245_52_sample()
    sample["services"][0]["vulns"] = sample["services"][0]["vulns"][:2]

    # Match the generated SDK response: it deserializes recognised fields and
    # ignores service.vulns, while Client restores those raw service fields.
    host = HostEnrichment.model_validate(sample)
    Client._restore_service_fields(host, {"result": {"result": {"resource": sample}}})
    host = HostEnrichment(services=host.services)

    stix_objects = [
        octi_object.to_stix2_object()
        for octi_object in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="193.233.245.52"), data=host
        )
    ]

    software = next(obj for obj in stix_objects if obj.type == "software")
    vulnerabilities = [obj for obj in stix_objects if obj.type == "vulnerability"]
    has_relationships = [
        obj
        for obj in stix_objects
        if obj.type == "relationship" and obj.relationship_type == "has"
    ]

    assert software.name == "openssh"
    assert software.vendor == "openbsd"
    assert software.version == "10.2p1"
    assert [vulnerability.name for vulnerability in vulnerabilities] == [
        "CVE-2026-35385",
        "CVE-2026-35386",
    ]
    assert all(relationship.source_ref == software.id for relationship in has_relationships)
    assert {relationship.target_ref for relationship in has_relationships} == {
        vulnerability.id for vulnerability in vulnerabilities
    }
    assert vulnerabilities[0].x_opencti_cvss_base_score == 7.5
    assert vulnerabilities[0].x_opencti_epss_score == 0.006


def test_converter_creates_complete_vulnerability_chain() -> None:
    """Verify the complete STIX relationship path: IP -> Software -> CVE."""
    sample = _get_host_245_52_sample()
    sample["services"][0]["vulns"] = sample["services"][0]["vulns"][:2]
    host = HostEnrichment.model_validate(sample)
    Client._restore_service_fields(host, {"result": {"result": {"resource": sample}}})
    host = HostEnrichment(services=host.services)

    observable = stix2.IPv4Address(value="193.233.245.52")
    stix_objects = [
        octi_object.to_stix2_object()
        for octi_object in HostConverter().to_stix(observable=observable, data=host)
    ]

    # Verify that relationships from IP to Software exist
    ip_to_software_relationships = [
        obj
        for obj in stix_objects
        if obj.type == "relationship"
        and obj.relationship_type == "related-to"
        and any(
            obj_id in str(obj.source_ref) and "software" in str(obj.target_ref)
            for obj_id in [observable.id]
        )
    ]

    software = next(obj for obj in stix_objects if obj.type == "software")
    vulnerabilities = [obj for obj in stix_objects if obj.type == "vulnerability"]

    # Verify complete chain: source (IP reference) -> Software
    assert any(
        rel.source_ref == observable.id and rel.target_ref == software.id
        for rel in stix_objects
        if rel.type == "relationship" and rel.relationship_type == "related-to"
    ), "No RELATED_TO relationship found from IP observable to Software"

    # Verify the CVE chain: Software -> Vulnerability
    has_relationships = [
        obj
        for obj in stix_objects
        if obj.type == "relationship" and obj.relationship_type == "has"
    ]
    assert len(has_relationships) == 2, f"Expected 2 HAS relationships, got {len(has_relationships)}"
    assert all(
        rel.source_ref == software.id for rel in has_relationships
    ), "Not all CVE relationships originate from the same Software"


def test_converter_deduplicates_software_across_multiple_cves() -> None:
    """Verify that multiple CVEs with the same CPE share a single Software object."""
    sample = _get_host_245_52_sample()
    # Use 3 CVEs - all reference the same OpenSSH CPE, ensuring deduplication
    sample["services"][0]["vulns"] = sample["services"][0]["vulns"][:3]
    host = HostEnrichment.model_validate(sample)
    Client._restore_service_fields(host, {"result": {"result": {"resource": sample}}})
    host = HostEnrichment(services=host.services)

    stix_objects = [
        octi_object.to_stix2_object()
        for octi_object in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="193.233.245.52"), data=host
        )
    ]

    # Should have exactly one Software object for all 3 CVEs
    software_objects = [obj for obj in stix_objects if obj.type == "software"]
    assert len(software_objects) == 1, f"Expected 1 Software object, got {len(software_objects)}"

    # All HAS relationships should point to the same Software
    has_relationships = [
        obj
        for obj in stix_objects
        if obj.type == "relationship" and obj.relationship_type == "has"
    ]
    assert len(has_relationships) == 3, f"Expected 3 HAS relationships, got {len(has_relationships)}"
    assert all(
        rel.source_ref == software_objects[0].id for rel in has_relationships
    ), "All CVEs should be linked to the same Software object"


def test_converter_creates_software_from_cpe_when_not_in_service() -> None:
    """Verify that Software can be created from CPE evidence when not in service.software."""
    # Create a service with CVE evidence but no pre-defined software
    service = HostEnrichmentService(
        port=443,
        protocol="HTTPS",
        scan_time="2026-01-01T00:00:00Z",
    )

    # Manually attach vulns as the client would do via _restore_service_fields
    service.__dict__["vulns"] = [
        {
            "id": "CVE-2026-12345",
            "name": "CVE-2026-12345",
            "severity": "MEDIUM",
            "evidence": [
                {
                    "found_value": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
                }
            ],
            "metrics": {
                "cvss_v31": {"score": 5.5},
                "epss": {"score": 0.05},
            },
        }
    ]
    service.__dict__["software"] = []

    host = HostEnrichment(services=[service])

    stix_objects = [
        octi_object.to_stix2_object()
        for octi_object in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="10.0.0.1"), data=host
        )
    ]

    # Should create Software from CPE evidence
    software_objects = [obj for obj in stix_objects if obj.type == "software"]
    assert len(software_objects) == 1, f"Expected 1 Software created from CPE, got {len(software_objects)}"
    assert software_objects[0].vendor == "vendor"
    assert software_objects[0].name == "product"
    assert software_objects[0].version == "1.0"

    # Verify the CVE is linked to this generated Software
    vulnerabilities = [obj for obj in stix_objects if obj.type == "vulnerability"]
    assert len(vulnerabilities) == 1
    has_relationships = [
        obj
        for obj in stix_objects
        if obj.type == "relationship" and obj.relationship_type == "has"
    ]
    assert len(has_relationships) == 1
    assert has_relationships[0].source_ref == software_objects[0].id
    assert has_relationships[0].target_ref == vulnerabilities[0].id


def test_converter_creates_malware_from_threats() -> None:
    """Verify that Malware objects are created from service threats."""
    service = HostEnrichmentService(
        port=4224,
        protocol="HTTP",
        scan_time="2026-08-31T11:11:35Z",
    )
    service.__dict__["threats"] = [
        {
            "id": "THREAT-0188",
            "name": "ShellInABox",
            "source": "censys",
            "confidence": 0.5,
            "type": ["webshell"],
            "tactic": ["persistence"],
            "evidence": [
                {
                    "data_path": "http.html_title",
                    "found_value": "Shell In A Box"
                }
            ],
            "malware": {
                "id": "MALWARE-188",
                "primary_name": "ShellInABox",
                "all_names": ["ShellInABox"],
                "last_updated_at": "2025-05-01T00:00:00Z"
            }
        }
    ]

    host = HostEnrichment(services=[service])
    stix_objects = [
        obj.to_stix2_object()
        for obj in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="37.187.119.91"), data=host
        )
    ]

    # Verify Malware object is created
    malware = [obj for obj in stix_objects if obj.type == "malware"]
    assert len(malware) == 1
    assert malware[0].name == "ShellInABox"
    assert "ShellInABox" in malware[0].aliases
    assert "webshell" in malware[0].malware_types

    # Verify relationship from IP to Malware
    malware_relationships = [
        obj
        for obj in stix_objects
        if obj.type == "relationship" and obj.target_ref == malware[0].id
    ]
    assert len(malware_relationships) == 1
    assert malware_relationships[0].relationship_type == "related-to"


def test_converter_creates_attack_patterns_from_threat_tactics() -> None:
    """Verify that Attack-Pattern objects are created for threat tactics."""
    service = HostEnrichmentService(
        port=7070,
        protocol="FRPS",
        scan_time="2026-08-31T02:32:15Z",
    )
    service.__dict__["threats"] = [
        {
            "id": "THREAT-519",
            "name": "FRP",
            "source": "censys",
            "confidence": 0.75,
            "type": ["security_tool"],
            "tactic": ["command_and_control"],
            "evidence": [
                {
                    "data_path": "protocol",
                    "found_value": "FRPS"
                }
            ],
            "malware": {}
        }
    ]

    host = HostEnrichment(services=[service])
    stix_objects = [
        obj.to_stix2_object()
        for obj in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="104.168.107.43"), data=host
        )
    ]

    # Verify Attack-Pattern object is created
    attack_patterns = [obj for obj in stix_objects if obj.type == "attack-pattern"]
    assert len(attack_patterns) == 1
    assert "COMMAND AND CONTROL" in attack_patterns[0].name

    # Verify MITRE ATT&CK reference
    assert attack_patterns[0].external_references
    assert attack_patterns[0].external_references[0].source_name == "mitre-attack"
    assert "TA0011" in attack_patterns[0].external_references[0].external_id

    # Verify relationship from IP to Attack-Pattern
    pattern_relationships = [
        obj
        for obj in stix_objects
        if obj.type == "relationship" and obj.target_ref == attack_patterns[0].id
    ]
    assert len(pattern_relationships) == 1


def test_converter_creates_threat_notes_with_evidence() -> None:
    """Verify that threat Notes are created with detailed evidence."""
    service = HostEnrichmentService(
        port=4224,
        protocol="HTTP",
        scan_time="2026-08-31T11:11:35Z",
    )
    service.__dict__["threats"] = [
        {
            "id": "THREAT-0188",
            "name": "ShellInABox",
            "source": "censys",
            "confidence": 0.5,
            "type": ["webshell"],
            "tactic": ["persistence"],
            "evidence": [
                {
                    "data_path": "http.html_title",
                    "found_value": "Shell In A Box"
                }
            ],
            "malware": {
                "primary_name": "ShellInABox",
                "all_names": ["ShellInABox"],
                "last_updated_at": "2025-05-01T00:00:00Z"
            }
        }
    ]

    host = HostEnrichment(services=[service])
    stix_objects = [
        obj.to_stix2_object()
        for obj in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="37.187.119.91"), data=host
        )
    ]

    # Verify Threat Note is created
    threat_notes = [
        obj for obj in stix_objects
        if obj.type == "note" and "Threat" in obj.abstract
    ]
    assert len(threat_notes) == 1
    note = threat_notes[0]

    # Verify threat summary is rendered as a key/value table.
    assert "| Key | Value |" in note.content
    assert "| Threat ID | THREAT-0188 |" in note.content
    assert "| Name | ShellInABox |" in note.content
    assert "| Threat Types | webshell |" in note.content
    assert "| Tactics | Persistence |" in note.content
    assert (
        "[View this host 37.187.119.91 on Censys Platform]"
        "(https://platform.censys.io/hosts/37.187.119.91)"
        in note.content
    )
    assert "| Source | censys |" not in note.content
    assert "0.5" not in note.content
    assert "Shell In A Box" in note.content
    assert "2025-05-01" in note.content

    # Verify note labels
    assert "webshell" in note.labels


def test_converter_handles_multiple_threats_per_service() -> None:
    """Verify that multiple threats on one service create multiple objects."""
    service = HostEnrichmentService(
        port=9080,
        protocol="HTTP",
        scan_time="2026-08-31T13:12:28Z",
    )
    service.__dict__["threats"] = [
        {
            "id": "THREAT-519",
            "name": "FRP",
            "source": "censys",
            "confidence": 0.75,
            "type": ["security_tool"],
            "tactic": ["command_and_control"],
            "evidence": [],
            "malware": {}
        },
        {
            "id": "THREAT-520",
            "name": "Reverse Shell Proxy",
            "source": "censys",
            "confidence": 0.8,
            "type": ["proxy"],
            "tactic": ["lateral_movement"],
            "evidence": [],
            "malware": {
                "primary_name": "Reverse Shell",
                "all_names": ["Reverse Shell", "RevShell"]
            }
        }
    ]

    host = HostEnrichment(services=[service])
    stix_objects = [
        obj.to_stix2_object()
        for obj in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="104.168.107.43"), data=host
        )
    ]

    # Verify 2 threat notes
    threat_notes = [
        obj for obj in stix_objects
        if obj.type == "note" and "Threat" in obj.abstract
    ]
    assert len(threat_notes) == 2

    # Verify 1 malware (only second threat has malware)
    malware = [obj for obj in stix_objects if obj.type == "malware"]
    assert len(malware) == 1
    assert malware[0].name == "Reverse Shell"

    # Verify 2 attack patterns
    attack_patterns = [obj for obj in stix_objects if obj.type == "attack-pattern"]
    assert len(attack_patterns) == 2
    pattern_names = {p.name for p in attack_patterns}
    assert "COMMAND AND CONTROL" in pattern_names
    assert "LATERAL MOVEMENT" in pattern_names


def test_converter_handles_service_with_both_vulns_and_threats() -> None:
    """Verify that services can have both vulnerabilities and threats."""
    sample = _get_host_245_52_sample()
    # Limit to 1 CVE and add a threat
    sample["services"][0]["vulns"] = sample["services"][0]["vulns"][:1]
    sample["services"][0]["threats"] = [
        {
            "id": "THREAT-SSH",
            "name": "Exposed SSH",
            "source": "censys",
            "confidence": 1.0,
            "type": ["remote_access"],
            "tactic": ["initial_access"],
            "evidence": [{"data_path": "protocol", "found_value": "SSH"}],
            "malware": {}
        }
    ]

    host = HostEnrichment.model_validate(sample)
    Client._restore_service_fields(host, {"result": {"result": {"resource": sample}}})

    stix_objects = [
        obj.to_stix2_object()
        for obj in HostConverter().to_stix(
            observable=stix2.IPv4Address(value="193.233.245.52"), data=host
        )
    ]

    # Verify both CVE and threat are present
    vulnerabilities = [obj for obj in stix_objects if obj.type == "vulnerability"]
    threat_notes = [
        obj for obj in stix_objects
        if obj.type == "note" and "Threat" in obj.abstract
    ]

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].name == "CVE-2026-35385"

    assert len(threat_notes) == 1
    assert "Exposed SSH" in threat_notes[0].content
