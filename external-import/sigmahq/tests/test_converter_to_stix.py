"""Regression tests for the Sigma → STIX conversion pipeline.

Pins the behavioural contracts that recent review passes added:

* ``_create_tlp_marking("clear")`` materialises ``TLP:CLEAR`` as its
  own ``MarkingDefinition`` with the canonical
  ``x_opencti_definition='TLP:CLEAR'`` extension (not an alias of the
  legacy ``stix2.TLP_WHITE``).
* ``convert_sigma_rule`` emits the matched ``AttackPattern`` /
  ``Vulnerability`` SDOs alongside the ``Indicator``, plus the
  ``indicates`` relationships. Every emitted object carries the
  configured author and TLP marking — without them OpenCTI ingests an
  unmarked / unattributed SDO that breaks marking-based access control
  downstream.
* The converter deduplicates ``AttackPattern`` / ``Vulnerability``
  SDOs by their deterministic STIX id across rules, so the same
  MITRE technique referenced by N rules emits a single SDO and N
  relationships (instead of N SDOs + N relationships). The per-rule
  ``indicates`` relationship is intentionally NOT deduped — each
  rule owns its own edge.
* Invalid / mis-shaped MITRE technique ids are silently skipped (the
  rule is still emitted as an Indicator) so a stray ``attack.foo``
  tag cannot crash the run.
"""

from unittest.mock import MagicMock

import pytest
import stix2
from connector.converter_to_stix import ConverterToStix


def _make_converter(tlp_level: str = "clear") -> ConverterToStix:
    return ConverterToStix(helper=MagicMock(), tlp_level=tlp_level)


def _build_rule(rule_yaml: str, filename: str = "rule.yml") -> dict:
    return {"filename": filename, "rule_content": rule_yaml}


_RULE_WITH_TECHNIQUE = """\
title: Suspicious whoami invocation
id: 00000000-0000-0000-0000-000000000001
description: Test rule that emits a single technique tag.
status: stable
date: 2026/01/01
author: pytest
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\whoami.exe'
  condition: selection
level: high
tags:
  - attack.t1059
"""

_RULE_WITH_CVE = """\
title: CVE detection rule
id: 00000000-0000-0000-0000-000000000002
description: Test rule that emits a single CVE tag.
status: stable
date: 2026/01/01
author: pytest
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\proc.exe'
  condition: selection
level: high
tags:
  - cve.2024-1234
"""

_RULE_WITH_BOTH = """\
title: Combined tags rule
id: 00000000-0000-0000-0000-000000000003
description: Test rule that emits a technique AND a CVE tag.
status: stable
date: 2026/01/01
author: pytest
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\proc.exe'
  condition: selection
level: high
tags:
  - attack.T1059.001
  - cve.2024-9999
"""

_RULE_WITH_INVALID_TAG = """\
title: Mis-shaped tag rule
id: 00000000-0000-0000-0000-000000000004
description: Test rule with an invalid attack tag.
status: stable
date: 2026/01/01
author: pytest
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\proc.exe'
  condition: selection
level: high
tags:
  - attack.X1059
  - attack.t999
"""


class TestCreateTlpMarking:
    """``TLP:CLEAR`` must not alias the legacy ``TLP:WHITE`` marking."""

    def test_clear_uses_opencti_specific_marking(self):
        converter = _make_converter("clear")
        assert isinstance(converter.tlp_marking, stix2.MarkingDefinition)
        custom = converter.tlp_marking.get("x_opencti_definition")
        # ``TLP:CLEAR`` is the modern label for what STIX 2.1 calls
        # ``TLP:WHITE`` — by design ``pycti.MarkingDefinition.generate_id``
        # resolves both to the **same** STIX id so OpenCTI merges them
        # on ingestion (an analyst's TLP:CLEAR document and a legacy
        # TLP:WHITE document refer to the same entity). The distinction
        # the UI renders comes from the ``x_opencti_definition`` custom
        # property — the legacy ``stix2.TLP_WHITE`` constant does NOT
        # carry that property, so the platform falls back to the
        # ``TLP:WHITE`` label. Materialising ``TLP:CLEAR`` as a custom
        # ``MarkingDefinition`` with ``x_opencti_definition='TLP:CLEAR'``
        # is therefore the only way to get the modern label rendered;
        # this test pins that contract.
        assert custom == "TLP:CLEAR"
        # Legacy ``stix2.TLP_WHITE`` MUST NOT carry the custom property,
        # otherwise the contract above would be trivially satisfied by
        # the alias the previous PR cycle removed.
        assert stix2.TLP_WHITE.get("x_opencti_definition") is None

    def test_white_is_built_in_constant(self):
        converter = _make_converter("white")
        assert converter.tlp_marking.id == stix2.TLP_WHITE.id

    def test_amber_strict_is_custom_marking(self):
        converter = _make_converter("amber+strict")
        custom = converter.tlp_marking.get("x_opencti_definition")
        # ``TLP:AMBER+STRICT`` has no STIX 2.1 equivalent (unlike
        # ``TLP:CLEAR`` ↔ ``TLP:WHITE``), so it is materialised as a
        # custom ``MarkingDefinition`` carrying the canonical
        # ``x_opencti_definition`` extension. The id is derived from
        # ``pycti.MarkingDefinition.generate_id`` and is intentionally
        # distinct from any built-in ``stix2.TLP_*`` constant.
        assert custom == "TLP:AMBER+STRICT"
        assert converter.tlp_marking.id != stix2.TLP_AMBER.id


class TestAuthorAndMarkings:
    """Every emitted SDO carries the configured author + TLP marking."""

    def test_author_carries_tlp_marking(self):
        converter = _make_converter("clear")
        assert converter.tlp_marking.id in converter.author.object_marking_refs

    def test_attack_pattern_and_indicator_share_author_and_marking(self):
        converter = _make_converter("clear")
        stix_objects = converter.convert_sigma_rule(_build_rule(_RULE_WITH_TECHNIQUE))
        kinds = {obj.type for obj in stix_objects}
        assert {"attack-pattern", "indicator", "relationship"}.issubset(kinds)
        for obj in stix_objects:
            if obj.type in {"attack-pattern", "indicator", "vulnerability"}:
                # Author + marking propagate consistently — without
                # this the bundle would mix marked and unmarked
                # entities and silently break access-control
                # propagation in OpenCTI.
                assert obj.created_by_ref == converter.author.id
                assert converter.tlp_marking.id in obj.object_marking_refs
            if obj.type == "relationship":
                assert converter.tlp_marking.id in obj.object_marking_refs


class TestRuleConversion:
    """Happy-path conversion: one rule → indicator + tagged SDO + edge."""

    def test_rule_with_attack_tag_emits_indicator_pattern_and_relationship(self):
        converter = _make_converter("clear")
        stix_objects = converter.convert_sigma_rule(_build_rule(_RULE_WITH_TECHNIQUE))
        indicators = [o for o in stix_objects if o.type == "indicator"]
        patterns = [o for o in stix_objects if o.type == "attack-pattern"]
        relationships = [o for o in stix_objects if o.type == "relationship"]
        assert len(indicators) == 1
        assert len(patterns) == 1
        assert len(relationships) == 1
        # Lower-case ``t1059`` in the YAML must round-trip to the
        # canonical upper-case ``T1059`` on the AttackPattern name /
        # ``x_mitre_id``.
        assert patterns[0].name == "T1059"
        assert relationships[0].relationship_type == "indicates"
        assert relationships[0].source_ref == indicators[0].id
        assert relationships[0].target_ref == patterns[0].id

    def test_rule_with_cve_tag_emits_indicator_vuln_and_relationship(self):
        converter = _make_converter("clear")
        stix_objects = converter.convert_sigma_rule(_build_rule(_RULE_WITH_CVE))
        indicators = [o for o in stix_objects if o.type == "indicator"]
        vulns = [o for o in stix_objects if o.type == "vulnerability"]
        relationships = [o for o in stix_objects if o.type == "relationship"]
        assert len(indicators) == 1
        assert len(vulns) == 1
        assert vulns[0].name == "CVE-2024-1234"
        assert len(relationships) == 1
        assert relationships[0].source_ref == indicators[0].id
        assert relationships[0].target_ref == vulns[0].id

    def test_rule_with_both_tags_emits_both_relationships(self):
        converter = _make_converter("clear")
        stix_objects = converter.convert_sigma_rule(_build_rule(_RULE_WITH_BOTH))
        patterns = [o for o in stix_objects if o.type == "attack-pattern"]
        vulns = [o for o in stix_objects if o.type == "vulnerability"]
        relationships = [o for o in stix_objects if o.type == "relationship"]
        assert len(patterns) == 1
        assert patterns[0].name == "T1059.001"
        assert len(vulns) == 1
        assert vulns[0].name == "CVE-2024-9999"
        # One ``indicates`` relationship per tag.
        assert len(relationships) == 2

    def test_invalid_attack_tag_is_silently_skipped(self):
        converter = _make_converter("clear")
        stix_objects = converter.convert_sigma_rule(_build_rule(_RULE_WITH_INVALID_TAG))
        # Indicator is still emitted; the bad tags produce no
        # AttackPattern (``X1059`` is not a valid MITRE id, and
        # ``t999`` is too short).
        indicators = [o for o in stix_objects if o.type == "indicator"]
        patterns = [o for o in stix_objects if o.type == "attack-pattern"]
        relationships = [o for o in stix_objects if o.type == "relationship"]
        assert len(indicators) == 1
        assert patterns == []
        assert relationships == []


class TestCrossRuleDedup:
    """The same technique/CVE across rules emits one SDO + N edges."""

    def test_shared_technique_emits_one_attack_pattern_and_two_relationships(self):
        converter = _make_converter("clear")
        rule_a = _build_rule(_RULE_WITH_TECHNIQUE, filename="rule_a.yml")
        # Different rule body (changes the Indicator id) but the same
        # ``attack.t1059`` tag — the platform dedup is by deterministic
        # STIX id, so emitting the AttackPattern twice would inflate
        # the bundle without changing semantics.
        rule_b_yaml = _RULE_WITH_TECHNIQUE.replace(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000005",
        ).replace(
            "Suspicious whoami invocation",
            "Suspicious whoami invocation (variant)",
        )
        rule_b = _build_rule(rule_b_yaml, filename="rule_b.yml")
        first = converter.convert_sigma_rule(rule_a)
        second = converter.convert_sigma_rule(rule_b)
        bundle = first + second
        patterns = [o for o in bundle if o.type == "attack-pattern"]
        relationships = [o for o in bundle if o.type == "relationship"]
        indicators = [o for o in bundle if o.type == "indicator"]
        # Two rules → two Indicators + two relationships, but only
        # ONE AttackPattern.
        assert len(indicators) == 2
        assert len(patterns) == 1
        assert len(relationships) == 2
        # Both relationships target the same AttackPattern id.
        assert {r.target_ref for r in relationships} == {patterns[0].id}

    def test_shared_cve_emits_one_vulnerability_and_two_relationships(self):
        converter = _make_converter("clear")
        rule_a = _build_rule(_RULE_WITH_CVE, filename="cve_a.yml")
        rule_b_yaml = _RULE_WITH_CVE.replace(
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000006",
        ).replace("CVE detection rule", "CVE detection rule (variant)")
        rule_b = _build_rule(rule_b_yaml, filename="cve_b.yml")
        first = converter.convert_sigma_rule(rule_a)
        second = converter.convert_sigma_rule(rule_b)
        bundle = first + second
        vulns = [o for o in bundle if o.type == "vulnerability"]
        relationships = [o for o in bundle if o.type == "relationship"]
        assert len(vulns) == 1
        assert len(relationships) == 2
        assert {r.target_ref for r in relationships} == {vulns[0].id}


@pytest.mark.parametrize("tlp_level", ["clear", "white", "green", "amber", "red"])
def test_all_supported_tlp_levels_produce_marking(tlp_level):
    converter = _make_converter(tlp_level)
    assert converter.tlp_marking is not None
