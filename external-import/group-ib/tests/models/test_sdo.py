from __future__ import annotations

from models.sdo import (
    AttackPattern,
    Identity,
    IntrusionSet,
    Malware,
    ThreatActor,
    Vulnerability,
)

# --- Identity ----------------------------------------------------------------


class TestIdentity:
    def test_organization_default(self):
        ident = Identity(name="ExampleCorp", c_type="identity")
        ident.generate_stix_objects()
        sdo = ident.stix_main_object
        assert sdo.type == "identity"
        assert sdo.name == "ExampleCorp"
        assert sdo.identity_class == "organization"

    def test_sector_class(self):
        ident = Identity(name="financial", c_type="identity", identity_class="class")
        ident.generate_stix_objects()
        assert ident.stix_main_object.identity_class == "class"

    def test_description_propagates(self):
        ident = Identity(name="ExampleCorp", c_type="identity")
        ident.set_description("Targeted org")
        ident.generate_stix_objects()
        assert ident.stix_main_object.description == "Targeted org"

    def test_labels_in_custom_properties(self):
        ident = Identity(
            name="ExampleCorp", c_type="identity", labels=["collection:Test"]
        )
        ident.generate_stix_objects()
        assert ident.stix_main_object["x_opencti_labels"] == ["collection:Test"]


# --- ThreatActor -------------------------------------------------------------


class TestThreatActor:
    def test_minimal(self):
        ta = ThreatActor(name="FIN-X", c_type="threat-actor", global_label=None)
        ta.generate_stix_objects()
        sdo = ta.stix_main_object
        assert sdo.type == "threat-actor"
        assert sdo.name == "FIN-X"
        # No global label → stix2 strips the empty ``threat_actor_types``
        # field entirely from the SDO.
        assert getattr(sdo, "threat_actor_types", []) == []

    def test_global_label_emits_threat_actor_type(self):
        ta = ThreatActor(
            name="APT-X",
            c_type="threat-actor",
            global_label="nation_state",
        )
        ta.generate_stix_objects()
        assert ta.stix_main_object.threat_actor_types == ["nation_state"]

    def test_full_metadata(self):
        ta = ThreatActor(
            name="FIN-X",
            c_type="threat-actor",
            global_label="cybercriminal",
            aliases=["FinSeven"],
            first_seen="2020-01-01T00:00:00Z",
            last_seen="2024-01-01T00:00:00Z",
            goals=["financial"],
            roles=["agent"],
            labels=["collection:Test"],
        )
        ta.generate_stix_objects()
        sdo = ta.stix_main_object
        assert sdo.aliases == ["FinSeven"]
        assert sdo.goals == ["financial"]
        assert sdo.roles == ["agent"]
        # global_label → threat_actor_types; dates pass through; labels mapped.
        assert sdo.threat_actor_types == ["cybercriminal"]
        assert str(sdo.first_seen).startswith("2020-01-01")
        assert str(sdo.last_seen).startswith("2024-01-01")
        assert sdo["x_opencti_labels"] == ["collection:Test"]


# --- IntrusionSet ------------------------------------------------------------


class TestIntrusionSet:
    def test_minimal(self):
        is_obj = IntrusionSet(name="APT-X", c_type="intrusion-set", global_label=None)
        is_obj.generate_stix_objects()
        assert is_obj.stix_main_object.type == "intrusion-set"
        assert is_obj.stix_main_object.name == "APT-X"

    def test_with_aliases_and_goals(self):
        is_obj = IntrusionSet(
            name="APT-X",
            c_type="intrusion-set",
            global_label=None,
            aliases=["Group-X"],
            goals=["espionage"],
            first_seen="2020-01-01T00:00:00Z",
        )
        is_obj.generate_stix_objects()
        sdo = is_obj.stix_main_object
        assert sdo.aliases == ["Group-X"]
        assert sdo.goals == ["espionage"]


# --- Malware -----------------------------------------------------------------


class TestMalware:
    def test_minimal_with_unknown_type(self):
        m = Malware(name="MalwareAlpha", c_type="malware", malware_types=None)
        m.generate_stix_objects()
        sdo = m.stix_main_object
        assert sdo.type == "malware"
        # ``malware_types`` defaults to ``["unknown"]`` when none provided.
        assert sdo.malware_types == ["unknown"]
        assert sdo.is_family is False

    def test_known_type_normalised(self):
        # "Ransomware" → "ransomware" via _generate_malware_type lookup.
        m = Malware(
            name="MalwareBeta",
            c_type="malware",
            malware_types=["RANSOMWARE"],
        )
        m.generate_stix_objects()
        assert m.stix_main_object.malware_types == ["ransomware"]

    def test_unknown_type_falls_through(self):
        # The lookup returns ``None`` for types outside STIX 2.1 vocab.
        m = Malware(
            name="x",
            c_type="malware",
            malware_types=["not-a-real-malware-type"],
        )
        m.generate_stix_objects()
        # stix2 coerces ``None`` inside the malware_types list to the
        # string ``"None"`` (Python repr) before serialisation. We assert
        # against the actual serialised shape.
        assert m.stix_main_object.malware_types == ["None"]

    def test_aliases_and_last_seen(self):
        m = Malware(
            name="x",
            c_type="malware",
            malware_types=None,
            aliases=["alias-y"],
            last_seen="2024-01-01T00:00:00Z",
        )
        m.generate_stix_objects()
        assert m.stix_main_object.aliases == ["alias-y"]
        assert str(m.stix_main_object.last_seen).startswith("2024-01-01")


# --- Vulnerability + CVSS bands ----------------------------------------------


class TestVulnerabilityCvssBand:
    def _vuln(self, score):
        return Vulnerability(
            name="CVE-2024-1", c_type="vulnerability", cvss_score=score
        )

    def test_low_band(self):
        assert self._vuln(0.5).cvss_severity == "LOW"
        assert self._vuln(3.9).cvss_severity == "LOW"

    def test_medium_band(self):
        assert self._vuln(4.0).cvss_severity == "MEDIUM"
        assert self._vuln(5.5).cvss_severity == "MEDIUM"
        assert self._vuln(6.9).cvss_severity == "MEDIUM"

    def test_high_band(self):
        # Lower bound is exclusive per the source (``CVSS_SEVERITY_HIGH_MIN <``).
        assert self._vuln(7.5).cvss_severity == "HIGH"
        assert self._vuln(8.9).cvss_severity == "HIGH"

    def test_critical_band(self):
        # Lower bound exclusive again.
        assert self._vuln(9.5).cvss_severity == "CRITICAL"
        assert self._vuln(10.0).cvss_severity == "CRITICAL"

    def test_no_score(self):
        assert self._vuln(None).cvss_severity is None
        assert self._vuln(0).cvss_severity is None  # 0 is falsy → branch skipped


class TestVulnerabilitySdo:
    def test_minimal(self):
        v = Vulnerability(name="CVE-2024-1", c_type="vulnerability")
        v.generate_stix_objects()
        sdo = v.stix_main_object
        assert sdo.type == "vulnerability"
        assert sdo.name == "CVE-2024-1"

    def test_cvss_v3_vector_parsed(self):
        v = Vulnerability(
            name="CVE-2024-1",
            c_type="vulnerability",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        v.generate_stix_objects()
        sdo = v.stix_main_object
        assert sdo["x_opencti_cvss_base_score"] == 9.8
        assert sdo["x_opencti_cvss_base_severity"] == "CRITICAL"
        assert sdo["x_opencti_cvss_attack_vector"] == "NETWORK"
        assert sdo["x_opencti_cvss_attack_complexity"] == "LOW"
        assert sdo["x_opencti_cvss_privileges_required"] == "NONE"
        assert sdo["x_opencti_cvss_user_interaction"] == "NONE"
        assert sdo["x_opencti_cvss_scope"] == "UNCHANGED"
        assert sdo["x_opencti_cvss_confidentiality_impact"] == "HIGH"

    def test_cvss_v2_vector_parsed(self):
        v = Vulnerability(
            name="CVE-2024-1",
            c_type="vulnerability",
            cvss_score=7.5,
            cvss_vector="AV:N/AC:L/Au:N/C:P/I:P/A:P",
        )
        v.generate_stix_objects()
        sdo = v.stix_main_object
        # v2 vector → v2 custom properties.
        assert sdo["x_opencti_cvss_v2_base_score"] == 7.5
        assert sdo["x_opencti_cvss_v2_access_vector"] == "NETWORK"
        assert sdo["x_opencti_cvss_v2_authentication"] == "NONE"
        assert sdo["x_opencti_cvss_v2_confidentiality_impact"] == "PARTIAL"

    def test_no_vector_no_cvss_properties(self):
        v = Vulnerability(name="CVE-x", c_type="vulnerability", cvss_score=5.0)
        v.generate_stix_objects()
        # Score sets cvss_severity but no v3-properties since vector is missing.
        sdo = v.stix_main_object
        assert "x_opencti_cvss_base_score" not in sdo

    def test_malformed_vector_tokens_skipped(self):
        # Tokens without ":" are silently dropped — the parser must not raise.
        v = Vulnerability(
            name="CVE-x",
            c_type="vulnerability",
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/garbage-token/AC:L",
        )
        v.generate_stix_objects()
        # The well-formed tokens survived; the bad one is just ignored.
        assert v.stix_main_object["x_opencti_cvss_attack_vector"] == "NETWORK"


# --- AttackPattern -----------------------------------------------------------


class TestAttackPattern:
    def test_minimal(self):
        ap = AttackPattern(
            name="Command Execution",
            c_type="attack-pattern",
            kill_chain_phases=None,
            mitre_id="T1059",
        )
        ap.generate_stix_objects()
        sdo = ap.stix_main_object
        assert sdo.type == "attack-pattern"
        assert sdo["x_mitre_id"] == "T1059"
        # Name preserved.
        assert sdo.name == "Command Execution"

    def test_with_kill_chain_phases(self):
        # Real STIX KillChainPhase objects could go here, but the wrapper
        # passes them through unmodified — confirm the field carries over.
        from models.location import KillChainPhase

        kcp = KillChainPhase(name="mitre-attack", c_type="execution")
        kcp.generate_stix_objects()
        ap = AttackPattern(
            name="Cmd",
            c_type="attack-pattern",
            kill_chain_phases=[kcp.stix_main_object],
            mitre_id="T1059",
        )
        ap.generate_stix_objects()
        assert len(ap.stix_main_object.kill_chain_phases) == 1

    def test_labels(self):
        ap = AttackPattern(
            name="Cmd",
            c_type="attack-pattern",
            kill_chain_phases=None,
            mitre_id="T1",
            labels=["mitre"],
        )
        ap.generate_stix_objects()
        assert ap.stix_main_object["x_opencti_labels"] == ["mitre"]
