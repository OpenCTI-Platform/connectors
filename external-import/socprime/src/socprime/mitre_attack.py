from itertools import chain
from typing import List, Optional, Union

import pycti
import requests
from stix2 import (AttackPattern, Filter, Malware, MemoryStore, ThreatActor,
                   Tool)


class MitreAttack:
    def __init__(self):
        self._src = self._get_data_from_branch("enterprise-attack")
        self._tools = self.get_software()

    def _get_data_from_branch(self, domain, branch="master"):
        """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
        stix_json = requests.get(
            f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json"
        ).json()
        return MemoryStore(stix_data=stix_json["objects"])

    def get_technique_by_id(self, technique_mitre_id: str) -> Optional[AttackPattern]:
        filt = [
            Filter("type", "=", "attack-pattern"),
            Filter("external_references.external_id", "=", technique_mitre_id),
        ]
        res = self._src.query(filt)
        if res:
            props = res[0]._inner
            return AttackPattern(
                type="attack-pattern",
                id=pycti.AttackPattern.generate_id(
                    name=props["name"], x_mitre_id=technique_mitre_id
                ),
                name=props["name"],
                description=props["description"],
                external_references=props["external_references"],
            )

    def get_tool_by_name(self, name: str) -> Optional[Union[Tool, Malware]]:
        for item in self._tools:
            if item.name.lower() == name.lower():
                props = item._inner
                common_props = {
                    "name": props["name"],
                    "description": props["description"],
                    "labels": props["labels"],
                    "external_references": props["external_references"],
                    "aliases": props["x_mitre_aliases"],
                }
                if props["type"] == "malware":
                    return Malware(
                        type="malware",
                        id=pycti.Malware.generate_id(name=props["name"]),
                        is_family=props["is_family"] if "is_family" in props else False,
                        **common_props,
                    )
                elif props["type"] == "tool":
                    return Tool(
                        type="tool",
                        id=pycti.Tool.generate_id(name=props["name"]),
                        **common_props,
                    )

    def get_software(self) -> List[Union[Tool, Malware]]:
        return list(
            chain.from_iterable(
                self._src.query(f)
                for f in [Filter("type", "=", "tool"), Filter("type", "=", "malware")]
            )
        )

    def get_threat_actor_by_name(self, name: str) -> Optional[ThreatActor]:
        filt = [
            Filter("type", "=", "intrusion-set"),
            Filter("name", "=", name),
        ]
        res = self._src.query(filt)
        if res:
            props = res[0]._inner
            return ThreatActor(
                type="threat-actor",
                id=pycti.ThreatActor.generate_id(name=props["name"]),
                name=props["name"],
                description=props["description"],
                external_references=props["external_references"],
                aliases=props["aliases"],
            )
