from urllib.parse import urljoin

import stix2
from pycti import (
    AttackPattern,
    Identity,
    Incident,
    Indicator,
    Note,
    StixCoreRelationship,
)


class ConverterToStix:

    def __init__(self, helper):
        self.helper = helper
        self.author = self._create_author()
        # Expose the connector-wide TLP marking so the caller in
        # ``connector.py`` can append it to every per-incident bundle
        # alongside the author Identity. ``send_stix2_bundle`` is
        # called with ``cleanup_inconsistent_bundle=True`` which strips
        # any reference whose target SDO is not also in the bundle —
        # the previous shape included the author but not the
        # MarkingDefinition, so every ``object_marking_refs=[stix2.TLP_RED.id]``
        # referenced from the Incident / UserAccount / AttackPattern /
        # Note / Indicator / Relationship SDOs would be silently
        # stripped at cleanup time and the resulting OpenCTI objects
        # would land unmarked. Matches the pattern used by
        # ``elastic-security-incidents`` (the closest sibling
        # connector), where ``tlp_marking`` is prepended to every
        # bundle alongside the author.
        self.tlp_marking = stix2.TLP_RED

    def _create_author(self) -> dict:
        """
        Creates an author for the connector
        """
        author = stix2.Identity(
            id=Identity.generate_id(
                name="SentinelOne Incident Connector", identity_class="organization"
            ),
            name="SentinelOne Incident Connector",
            identity_class="organization",
            description="The SentinelOne Incident Connector",
        )
        return author

    def create_incident(
        self, incident_data: dict, incident_id: str, s1_url: str
    ) -> list[stix2.Incident]:
        """
        Creates a Stix Incident from a SentinelOne incident alongside
        an external reference with a link to accessing it.
        """
        self.helper.connector_logger.debug(
            "Attempting to create corresponding Stix Incident"
        )

        machine = incident_data.get("agentRealtimeInfo", {}).get(
            "agentComputerName", "unknown"
        )
        account_name = incident_data.get("agentRealtimeInfo", {}).get(
            "accountName", "unknown"
        )
        account_id = incident_data.get("agentRealtimeInfo", {}).get(
            "accountId", "unknown"
        )
        # Use ``.get(...)`` chains rather than direct ``[...]``
        # indexing: every other field on ``incident_data`` is read
        # defensively, and a single SentinelOne payload missing
        # ``threatInfo.threatName`` or
        # ``threatInfo.mitigationStatusDescription`` (both are
        # documented as optional in some signal shapes) would
        # otherwise raise ``KeyError`` here and abort the whole batch
        # via the outer ``except Exception`` in ``connector.py`` —
        # silently dropping every later incident in the same cycle
        # along with this one.
        threat_info = incident_data.get("threatInfo", {})
        threat_name = threat_info.get("threatName", "unknown")
        mitigation_status = threat_info.get("mitigationStatusDescription", "unknown")
        description = (
            f"Threat detected on machine {machine} under account {account_name} (id: {account_id})."
            f"\nThreat Name: {threat_name}."
            f"\nMitigation Status: {mitigation_status}."
        )
        labels = [
            indicator.get("category", "")
            for indicator in incident_data.get("indicators", [])
            if indicator.get("category", "") != ""
        ]

        # ``ConfigConnector`` strips the trailing ``/`` from
        # ``s1_url``, so concatenating ``{s1_url}incidents/...``
        # used to produce a broken URL of the form
        # ``https://<tenant>.sentinelone.netincidents/threats/...``.
        # Compose with ``urljoin`` so the host and the incident path
        # are always separated by exactly one ``/``, regardless of
        # whether the operator stored ``s1_url`` with or without a
        # trailing slash.
        external_s1_ref = stix2.ExternalReference(
            source_name="SentinelOne",
            url=urljoin(f"{s1_url}/", f"incidents/threats/{incident_id}/overview"),
            description="View Incident In SentinelOne",
        )

        name = f"{threat_name} - {incident_id}"
        created = threat_info.get("identifiedAt", "")

        incident = stix2.Incident(
            id=Incident.generate_id(name, created),
            created_by_ref=self.author,
            type="incident",
            name=name,
            description=description,
            labels=labels,
            created=created,
            external_references=[external_s1_ref],
            object_marking_refs=[stix2.TLP_RED.id],
            custom_properties={"source": self.author.name},
        )

        return [incident]

    def create_user_account_observable(
        self, s1_incident: dict, cti_incident_id: str
    ) -> list:
        """
        Creates a Stix UserAccount Observable from a SentinelOne incident
        alongside a relationship to the incident.

        Returns an empty list when the incident carries no usable
        ``agentComputerName`` — the caller in ``connector.py`` extends
        a single ``stix_objects`` list with the return value and used
        to crash with ``TypeError: 'NoneType' is not iterable`` when
        this function returned ``None`` instead.
        """

        self.helper.connector_logger.debug(
            "Attempting to create UserAccount Observable"
        )

        endpoint_name = s1_incident.get("agentRealtimeInfo", {}).get(
            "agentComputerName", ""
        )
        if not endpoint_name:
            return []

        account_name = s1_incident.get("agentRealtimeInfo", {}).get(
            "accountName", "unknown"
        )
        account_id = s1_incident.get("agentRealtimeInfo", {}).get(
            "accountId", "unknown"
        )
        desc = f"Affected Host on SentinelOne Account {account_name} (with id: {account_id})"

        endpoint_observable = stix2.UserAccount(
            account_type="hostname",
            user_id=f"{endpoint_name} - {account_id}",
            object_marking_refs=[stix2.TLP_RED.id],
            custom_properties={"description": desc},
        )

        endpoint_relationship = self.create_relationship(
            endpoint_observable["id"], cti_incident_id, "related-to"
        )

        return [endpoint_observable, endpoint_relationship]

    def create_attack_patterns(self, incident_data: dict, cti_incident_id: str) -> list:
        """
        Creates a Stix Attack Pattern from a SentinelOne incident
        alongside a relationship to the incident.
        """

        def create_mitre_reference(technique):
            mitre_ref = stix2.ExternalReference(
                source_name="MITRE ATT&CK",
                url=technique.get("link"),
                external_id=technique.get("name"),
            )
            return mitre_ref

        self.helper.connector_logger.debug("Attempting to create Stix Attack Patterns")

        attack_patterns = []

        for indicator in incident_data.get("indicators", []):
            for tactic in indicator.get("tactics", []):
                for technique in tactic.get("techniques", []):
                    # Skip techniques without a usable name —
                    # ``AttackPattern.generate_id("")`` would otherwise
                    # produce a single constant deterministic id for
                    # every nameless technique, silently collapsing
                    # them into one empty-name SDO that collides with
                    # every other nameless technique across all
                    # incidents.
                    technique_name = (technique.get("name") or "").strip()
                    if not technique_name:
                        self.helper.connector_logger.debug(
                            "Skipping technique with empty name",
                            meta={"technique": technique},
                        )
                        continue
                    attack_pattern = stix2.AttackPattern(
                        id=AttackPattern.generate_id(technique_name),
                        created_by_ref=self.author,
                        name=technique_name,
                        description=indicator.get("description", ""),
                        external_references=[create_mitre_reference(technique)],
                        object_marking_refs=[stix2.TLP_RED.id],
                    )
                    attack_patterns.append(attack_pattern)
                    attack_patterns.append(
                        self.create_relationship(
                            cti_incident_id, attack_pattern["id"], "uses"
                        )
                    )

        return attack_patterns

    def create_notes(self, s1_notes: list, cti_incident_id: str) -> list:
        """
        Creates a Stix Note from a SentinelOne incident
        alongside a relationship to the incident.
        """

        self.helper.connector_logger.debug("Attempting to create Stix Notes")

        incident_notes = []
        for note in s1_notes:
            # Convert None values to empty strings before concatenation
            note_text = str(note.get("text", "") or "")
            note_creator = str(note.get("creator", "") or "")
            content = note_text + "\ncreated by: " + note_creator
            created = note.get("createdAt", "")
            incident_note = stix2.Note(
                id=Note.generate_id(content=content, created=created),
                created_by_ref=self.author,
                content=content,
                object_refs=[cti_incident_id],
                object_marking_refs=[stix2.TLP_RED.id],
            )
            incident_notes.append(incident_note)

        return incident_notes

    def create_hash_indicators(self, s1_incident: dict, cti_incident_id: str) -> list:
        """
        Creates a Stix Indicator from a SentinelOne incident
        alongside a relationship to the incident.
        """

        self.helper.connector_logger.debug("Attempting to create Indicators")

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
            indicator = stix2.Indicator(
                id=Indicator.generate_id(pattern),
                created_by_ref=self.author,
                pattern=pattern,
                name="Malicious File Hash Indicator",
                pattern_type="stix",
                object_marking_refs=[stix2.TLP_RED.id],
            )
            indicators.append(
                self.create_relationship(cti_incident_id, indicator["id"], "related-to")
            )
            indicators.append(indicator)

        return indicators

    def create_relationship(
        self, parent_id: str, child_id: str, relationship_type: str
    ) -> stix2.Relationship:
        """
        Creates a Stix Relationship between two objects
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(relationship_type, parent_id, child_id),
            created_by_ref=self.author,
            relationship_type=relationship_type,
            source_ref=parent_id,
            target_ref=child_id,
            object_marking_refs=[stix2.TLP_RED.id],
        )
        return relationship
