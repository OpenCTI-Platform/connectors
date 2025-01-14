from pycti import get_config_variable
from stix2 import (
    TLP_RED,
    AttackPattern,
    ExternalReference,
    Identity,
    Incident,
    Indicator,
    Note,
    Relationship,
    UserAccount,
    #utils,
)


class StixClient:
    def __init__(self, config, helper):

        source_name = (
            get_config_variable("CONNECTOR_NAME", ["connector", "name"], config)
            or "SentinelOne Incident Importer"
        )

        source_identity = Identity(
            #id=utils.generate_stix_id("identity"),
            name=source_name,
            identity_class="organization",
            description="SentinelOne Incident Connector.",
            generate_id=True
        )
        self.source = source_identity

        self.helper = helper

    def create_incident(self, incident_data, incident_id, s1_url):
        def convert_confidence(confidence):
            confidence_score = {"malicious": 80, "suspicious": 50, "N/A": 20}.get(
                confidence, "suspicious"
            )
            return confidence_score

        self.helper.log_debug("Attempting to create corresponding Stix Incident")

        machine = incident_data.get("agentRealtimeInfo", {}).get(
            "agentComputerName", "unknown"
        )
        account_name = incident_data.get("agentRealtimeInfo", {}).get(
            "accountName", "unknown"
        )
        account_id = incident_data.get("agentRealtimeInfo", {}).get(
            "accountId", "unknown"
        )
        description = (
            f"Threat detected on machine {machine} under account {account_name} (id: {account_id})."
            f"\nThreat Name: {incident_data['threatInfo']['threatName']}."
            f"\nMitigation Status: {incident_data['threatInfo']['mitigationStatusDescription']}."
        )
        labels = [
            indicator.get("category", "")
            for indicator in incident_data.get("indicators", [])
            if indicator.get("category", "") != ""
        ]

        external_s1_ref = ExternalReference(
            #id=utils.generate_stix_id("external-reference"),
            source_name="SentinelOne",
            url=f"{s1_url}/incidents/threats/{incident_id}/overview",
            description="View Incident In SentinelOne",
            generate_id=True
        )

        incident = Incident(
            #id=utils.generate_stix_id("incident"),
            type="incident",
            name=incident_data.get("threatInfo", {}).get("threatName", ""),
            description=description,
            labels=labels,
            confidence=convert_confidence(
                incident_data.get("threatInfo", {}).get("confidenceLevel", "suspicious")
            ),
            created=incident_data["threatInfo"]["identifiedAt"],
            external_references=[external_s1_ref] if external_s1_ref else None,
            object_marking_refs=[TLP_RED.id],
            created_by_ref=self.source.id,
            custom_properties={"source": self.source.name},
            generate_id=True
        )

        return [incident, self.source]

    def create_endpoint_observable(self, s1_incident, cti_incident_id):

        self.helper.log_debug("Attempting to create Endpoint Observable")

        endpoint_name = s1_incident.get("agentRealtimeInfo", {}).get(
            "agentComputerName", ""
        )
        if not endpoint_name:
            return None

        account_name = s1_incident.get("agentRealtimeInfo", {}).get(
            "accountName", "unknown"
        )
        account_id = s1_incident.get("agentRealtimeInfo", {}).get(
            "accountId", "unknown"
        )
        desc = f"Affected Host on SentinelOne Account {account_name} (with id: {account_id})"

        endpoint_observable = UserAccount(
            #id=utils.generate_stix_id("user-account"),
            account_type="hostname",
            user_id="BWPC-PC1-RED",
            object_marking_refs=[TLP_RED.id],
            custom_properties={"description": desc},
            generate_id=True
        )

        endpoint_relationship = self.create_relationship(
            endpoint_observable["id"], cti_incident_id, "related-to"
        )

        return [endpoint_observable, endpoint_relationship]

    def create_attack_patterns(self, incident_data, cti_incident_id):

        def create_mitre_reference(technique):
            mitre_ref = ExternalReference(
                #id=utils.generate_stix_id("external-reference"),
                source_name="MITRE ATT&CK",
                url=technique.get("link"),
                external_id=technique.get("name"),
                generate_id=True
            )
            return mitre_ref

        self.helper.log_debug("Attempting to create Stix Attack Patterns")

        attack_patterns = []

        for pattern in incident_data.get("indicators", []):
            pattern_name = (
                pattern.get("category", "")
                + ": "
                + ", ".join(
                    [
                        tactic.get("name", "")
                        for tactic in pattern.get("tactics", [])
                        if tactic.get("name", "") != ""
                    ]
                )
            )

            attack_pattern = AttackPattern(
                #id=utils.generate_stix_id("attack-pattern"),
                name=pattern_name,
                description=pattern.get("description", ""),
                object_marking_refs=[TLP_RED.id],
                generate_id=True
            )

            for tactic in pattern.get("tactics", []):
                sub_desc = ", ".join(
                    [
                        technique.get("name", "")
                        for technique in tactic.get("techniques", [])
                        if technique.get("name", "") != ""
                    ]
                )

                sub_pattern = AttackPattern(
                    #id=utils.generate_stix_id("attack-pattern"),
                    name="[sub] " + tactic.get("name", ""),
                    description=sub_desc,
                    external_references=[
                        create_mitre_reference(technique)
                        for technique in tactic.get("techniques", [])
                    ],
                    object_marking_refs=[TLP_RED.id],
                    generate_id=True
                )

                attack_patterns.append(sub_pattern)
                attack_patterns.append(
                    self.create_relationship(cti_incident_id, sub_pattern["id"], "uses")
                )

            attack_patterns.append(attack_pattern)
            attack_patterns.append(
                self.create_relationship(cti_incident_id, attack_pattern["id"], "uses")
            )

        return attack_patterns

    def create_notes(self, s1_notes, cti_incident_id):

        self.helper.log_debug("Attempting to create Stix Notes")

        incident_notes = []
        for note in s1_notes:
            incident_note = Note(
                #id=utils.generate_stix_id("note"),
                content=note.get("text", "")
                + "\ncreated by: "
                + note.get("creator", ""),
                object_refs=[cti_incident_id],
                object_marking_refs=[TLP_RED.id],
                generate_id=True
            )
            incident_notes.append(incident_note)

        return incident_notes

    def create_hash_indicators(self, s1_incident, cti_incident_id):

        self.helper.log_debug("Attempting to create Indicators")

        available_patterns = []
        hash_types = {"sha256": "SHA-256", "sha1": "SHA-1", "md5": "MD5"}
        threat_info = s1_incident.get("threatInfo", {})

        for hash_key, hash_label in hash_types.items():
            if threat_info.get(hash_key):
                available_patterns.append(
                    f"[file:hashes.'{hash_label}'='{threat_info[hash_key]}']"
                )

        indicators = []
        for pattern in available_patterns:
            indicator = Indicator(
                #id=utils.generate_stix_id("indicator"),
                pattern=pattern,
                name="Malicious File Hash Indicator",
                pattern_type="stix",
                object_marking_refs=[TLP_RED.id],
                generate_id=True
            )
            indicators.append(
                self.create_relationship(cti_incident_id, indicator["id"], "related-to")
            )
            indicators.append(indicator)

        return indicators

    def create_relationship(self, parent_id, child_id, relationship_type):

        relationship = Relationship(
            #id=utils.generate_stix_id("relationship"),
            relationship_type=relationship_type,
            source_ref=parent_id,
            target_ref=child_id,
            object_marking_refs=[TLP_RED.id],
            generate_id=True
        )
        return relationship
