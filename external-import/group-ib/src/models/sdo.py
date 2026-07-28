from __future__ import annotations

from typing import Any

import pycti
import stix2
from connector.settings import (
    CVSS_SEVERITY_CRITICAL_MIN,
    CVSS_SEVERITY_HIGH_MAX,
    CVSS_SEVERITY_HIGH_MIN,
    CVSS_SEVERITY_LOW_MAX,
    CVSS_SEVERITY_MEDIUM_MAX,
    CVSS_SEVERITY_MEDIUM_MIN,
)
from models._common import _BaseSDO


class Identity(_BaseSDO):
    """STIX Identity SDO (organization / sector).

    ``identity_class="organization"`` maps to an OpenCTI Organization,
    ``identity_class="class"`` maps to an OpenCTI Sector.
    """

    def __init__(
        self,
        name,
        c_type,
        identity_class="organization",
        tlp_color="white",
        labels=None,
        risk_score=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)
        self.identity_class = identity_class

    def _generate_sdo(self) -> Any:
        custom_props = {
            "x_opencti_score": self.risk_score or None,
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
        }
        self.stix_main_object = stix2.Identity(
            id=pycti.Identity.generate_id(self.name, self.identity_class),
            name=self.name,
            description=self.description,
            identity_class=self.identity_class,
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
            custom_properties=custom_props,
        )
        return self.stix_main_object


class ThreatActor(_BaseSDO):
    def __init__(
        self,
        name,
        c_type,
        global_label,
        tlp_color="white",
        labels=None,
        risk_score=None,
        aliases=None,
        first_seen=None,
        last_seen=None,
        goals=None,
        roles=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.global_label = global_label
        self.aliases = aliases
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.goals = goals
        self.roles = roles

    def _generate_sdo(self) -> Any:
        custom_props = {
            "x_opencti_score": self.risk_score or None,
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
        }
        self.stix_main_object = stix2.ThreatActor(
            id=pycti.ThreatActorGroup.generate_id(self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            goals=self.goals,
            roles=self.roles,
            created_by_ref=self.author.id,
            threat_actor_types=([self.global_label] if self.global_label else []),
            object_marking_refs=self.get_markings(),
            custom_properties=custom_props,
        )
        return self.stix_main_object


class IntrusionSet(_BaseSDO):
    def __init__(
        self,
        name,
        c_type,
        global_label,
        tlp_color="white",
        labels=None,
        risk_score=None,
        aliases=None,
        first_seen=None,
        last_seen=None,
        goals=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.global_label = global_label
        self.aliases = aliases
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.goals = goals

    def _generate_sdo(self) -> Any:
        custom_props = {
            "x_opencti_score": self.risk_score or None,
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
        }
        self.stix_main_object = stix2.IntrusionSet(
            id=pycti.IntrusionSet.generate_id(self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            goals=self.goals,
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
            custom_properties=custom_props,
        )
        return self.stix_main_object


class Malware(_BaseSDO):
    def __init__(
        self,
        name,
        c_type,
        malware_types,
        tlp_color="white",
        labels=None,
        risk_score=None,
        aliases=None,
        last_seen=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.malware_types = []
        if malware_types:
            self.malware_types = [
                self._generate_malware_type(_t) for _t in malware_types
            ]
        self.aliases = aliases
        self.last_seen = last_seen

    def _generate_sdo(self) -> Any:
        custom_props = {
            "x_opencti_score": self.risk_score or None,
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
        }
        self.stix_main_object = stix2.Malware(
            id=pycti.Malware.generate_id(self.name),
            name=self.name,
            description=self.description,
            aliases=self.aliases,
            last_seen=self.last_seen,
            malware_types=self.malware_types or ["unknown"],
            is_family=False,
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
            custom_properties=custom_props,
        )
        return self.stix_main_object


class Vulnerability(_BaseSDO):
    def __init__(
        self,
        name,
        c_type,
        tlp_color="white",
        labels=None,
        risk_score=None,
        created=None,
        modified=None,
        cvss_score=None,
        cvss_vector=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.created = created
        self.cvss_score = cvss_score
        self.cvss_vector = cvss_vector
        if self.cvss_score:
            if 0 <= self.cvss_score <= CVSS_SEVERITY_LOW_MAX:
                self.cvss_severity = "LOW"
            elif (
                CVSS_SEVERITY_MEDIUM_MIN <= self.cvss_score <= CVSS_SEVERITY_MEDIUM_MAX
            ):
                self.cvss_severity = "MEDIUM"
            elif CVSS_SEVERITY_HIGH_MIN < self.cvss_score <= CVSS_SEVERITY_HIGH_MAX:
                self.cvss_severity = "HIGH"
            elif CVSS_SEVERITY_CRITICAL_MIN < self.cvss_score <= 10.0:
                self.cvss_severity = "CRITICAL"
            else:
                self.cvss_severity = None
        else:
            self.cvss_severity = None

    def _build_cvss_properties(self) -> Any:
        props = {}
        vector = self.cvss_vector
        if not vector:
            return props

        vector_upper = str(vector).upper()
        is_v2 = ("AU:" in vector_upper) or vector_upper.startswith("CVSS:2")
        is_v3 = (
            "PR:" in vector_upper
            or "UI:" in vector_upper
            or "S:" in vector_upper
            or vector_upper.startswith("CVSS:3")
        ) and not is_v2

        tokens = [t for t in vector_upper.split("/") if ":" in t]
        kv = {}
        for token in tokens:
            try:
                k, v = token.split(":", 1)
                kv[k] = v
            except Exception:
                continue

        if is_v2 or (not is_v3 and "AU" in kv):
            av_map = {"L": "LOCAL", "A": "ADJACENT_NETWORK", "N": "NETWORK"}
            ac_map = {"L": "LOW", "M": "MEDIUM", "H": "HIGH"}
            au_map = {"N": "NONE", "S": "SINGLE", "M": "MULTIPLE"}
            imp_map = {"N": "NONE", "P": "PARTIAL", "C": "COMPLETE"}

            props.update(
                {
                    "x_opencti_cvss_v2_vector_string": vector,
                    "x_opencti_cvss_v2_base_score": self.cvss_score,
                    "x_opencti_cvss_v2_access_vector": av_map.get(
                        kv.get("AV", ""), None
                    ),
                    "x_opencti_cvss_v2_access_complexity": ac_map.get(
                        kv.get("AC", ""), None
                    ),
                    "x_opencti_cvss_v2_authentication": au_map.get(
                        kv.get("AU", ""), None
                    ),
                    "x_opencti_cvss_v2_confidentiality_impact": imp_map.get(
                        kv.get("C", ""), None
                    ),
                    "x_opencti_cvss_v2_integrity_impact": imp_map.get(
                        kv.get("I", ""), None
                    ),
                    "x_opencti_cvss_v2_availability_impact": imp_map.get(
                        kv.get("A", ""), None
                    ),
                }
            )
        else:
            av_map = {
                "N": "NETWORK",
                "A": "ADJACENT",
                "L": "LOCAL",
                "P": "PHYSICAL",
            }
            ac_map = {"L": "LOW", "H": "HIGH"}
            pr_map = {"N": "NONE", "L": "LOW", "H": "HIGH"}
            ui_map = {"N": "NONE", "R": "REQUIRED"}
            scope_map = {"U": "UNCHANGED", "C": "CHANGED"}
            imp_map = {"N": "NONE", "L": "LOW", "H": "HIGH"}

            props.update(
                {
                    "x_opencti_cvss_vector_string": vector,
                    "x_opencti_cvss_base_score": self.cvss_score,
                    "x_opencti_cvss_base_severity": self.cvss_severity,
                    "x_opencti_cvss_attack_vector": av_map.get(kv.get("AV", ""), None),
                    "x_opencti_cvss_attack_complexity": ac_map.get(
                        kv.get("AC", ""), None
                    ),
                    "x_opencti_cvss_privileges_required": pr_map.get(
                        kv.get("PR", ""), None
                    ),
                    "x_opencti_cvss_user_interaction": ui_map.get(
                        kv.get("UI", ""), None
                    ),
                    "x_opencti_cvss_scope": scope_map.get(kv.get("S", ""), None),
                    "x_opencti_cvss_confidentiality_impact": imp_map.get(
                        kv.get("C", ""), None
                    ),
                    "x_opencti_cvss_integrity_impact": imp_map.get(
                        kv.get("I", ""), None
                    ),
                    "x_opencti_cvss_availability_impact": imp_map.get(
                        kv.get("A", ""), None
                    ),
                }
            )

        return props

    def _generate_sdo(self) -> Any:
        custom_props = {
            "x_opencti_score": self.risk_score or None,
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
        }
        custom_props.update(self._build_cvss_properties())

        self.stix_main_object = stix2.Vulnerability(
            id=pycti.Vulnerability.generate_id(self.name),
            name=self.name,
            description=self.description,
            created=self.created,
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
            custom_properties=custom_props,
        )
        return self.stix_main_object


class AttackPattern(_BaseSDO):
    def __init__(
        self,
        name,
        c_type,
        kill_chain_phases,
        mitre_id,
        tlp_color="white",
        labels=None,
        risk_score=None,
    ):
        super().__init__(name, c_type, tlp_color, labels, risk_score)

        self.kill_chain_phases = kill_chain_phases
        self.mitre_id = mitre_id

    def _generate_sdo(self) -> Any:
        custom_props = {
            "x_opencti_score": self.risk_score or None,
            **self._labels_kv(),
            "x_opencti_external_references": self.external_references,
            "x_mitre_id": self.mitre_id,
        }
        self.stix_main_object = stix2.AttackPattern(
            id=pycti.AttackPattern.generate_id(self.name, self.mitre_id),
            name=self.name,
            kill_chain_phases=self.kill_chain_phases,
            description=self.description,
            created_by_ref=self.author.id,
            object_marking_refs=self.get_markings(),
            custom_properties=custom_props,
        )
        return self.stix_main_object
