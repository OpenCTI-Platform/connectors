from __future__ import annotations

from datetime import datetime
from typing import Any

import stix2
from connector.settings import AssetnoteImportConfig
from connectors_sdk.models import (
    CourseOfAction,
    ExternalReference,
    Infrastructure,
    Note,
    OrganizationAuthor,
    Relationship,
    Software,
    TLPMarking,
    Vulnerability,
)
from pycti import CaseIncident, CustomObjectCaseIncident, OpenCTIConnectorHelper


class ConverterToStix:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: AssetnoteImportConfig,
        status_mapping: dict[str, str],
    ):
        self.helper = helper
        self.author = OrganizationAuthor(name="Assetnote")
        self.tlp_marking = TLPMarking(level=config.tlp_level.lower())
        self.api_base_url = str(config.api_base_url).rstrip("/")
        self.status_mapping = status_mapping

    def base_stix_objects(self) -> list:
        return [self.author.to_stix2_object(), self.tlp_marking.to_stix2_object()]

    def convert_asset(self, asset: dict[str, Any]) -> list:
        asset_type = asset["assetType"].upper()
        created = datetime.fromisoformat(asset["created"])
        last_seen_value = asset.get("onlineLastUpdated")

        infrastructure = Infrastructure(
            name=asset["host"],
            description=f"Assetnote asset of type {asset_type}",
            labels=[f"assetnote:{asset_type.lower()}"],
            author=self.author,
            markings=[self.tlp_marking],
            created=created,
            first_seen=created,
            last_seen=(
                datetime.fromisoformat(last_seen_value) if last_seen_value else None
            ),
            external_references=[
                ExternalReference(
                    source_name=f"Assetnote Asset: {asset['host']}",
                    external_id=asset["id"],
                    url=asset.get("platformUrl"),
                )
            ],
        )
        return [infrastructure.to_stix2_object()]

    def convert_exposure(self, exposure: dict[str, Any]) -> list:
        # Create an Infrastructure object for the affected Asset
        asset = dict(exposure["asset"])
        asset["created"] = exposure["created"]

        # Create the core objects encompassing the components fo the Exposure
        infrastructure_object = self.convert_asset(asset)[0]
        vulnerability_object = self._map_vulnerability(exposure)
        course_of_action_object = self._map_course_of_action(exposure)
        relationships = [
            self._map_relationship("has", infrastructure_object, vulnerability_object),
            self._map_relationship(
                "mitigates", course_of_action_object, vulnerability_object
            ),
        ]

        # Optionally, create a Software object when the Exposure cites a software exploitation
        software_object = self._map_software(exposure)
        if software_object:
            relationships.append(
                self._map_relationship("hosts", infrastructure_object, software_object)
            )
            relationships.append(
                self._map_relationship("has", software_object, vulnerability_object)
            )

        # convert all SDK created objects into their stix2 form and append their ids for referencing
        stix_objects = [infrastructure_object, course_of_action_object]
        object_refs = [infrastructure_object.id, course_of_action_object.id]
        wrapped_entities = [vulnerability_object, *relationships]
        if software_object:
            wrapped_entities.append(software_object)
        for entity in wrapped_entities:
            stix_objects.append(entity.to_stix2_object())
            object_refs.append(entity.id)

        # Create the incident response, parsing references to all objects
        incident_response_object = self._map_incident_response(exposure, object_refs)
        stix_objects.append(incident_response_object)

        # Notes are created last so they can be attached directly to the Incident Response
        for note_object in self._map_notes(exposure, incident_response_object):
            stix_objects.append(note_object.to_stix2_object())

        return stix_objects

    def _map_vulnerability(self, exposure: dict[str, Any]) -> Vulnerability:
        signature = exposure["signature"]
        return Vulnerability(
            # If the CVE field is populated it gives a valid CVE name, else the signature name is used for
            # Exposures that don't reflect a CVE
            name=signature.get("cve") or signature["name"],
            description=signature["description"],
            author=self.author,
            markings=[self.tlp_marking],
            created=exposure["created"],
        )

    def _map_software(self, exposure: dict[str, Any]) -> Software | None:
        """Returns None if the exposure has no knownExploitation.product (no specific software identified)."""
        known_exploitation = exposure.get("knownExploitation") or {}
        product = known_exploitation.get("product")
        if not product:
            return None
        return Software(
            name=product,
            vendor=known_exploitation.get("vendorProject"),
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _map_relationship(
        self, relationship_type: str, source: Any, target: Any
    ) -> Relationship:
        return Relationship(
            type=relationship_type,
            source=source,
            target=target,
            author=self.author,
            markings=[self.tlp_marking],
        )

    def _map_notes(
        self,
        exposure: dict[str, Any],
        incident_response_object: CustomObjectCaseIncident,
    ) -> list[Note]:
        exposure_data = exposure.get("exposureData") or {}
        interactions = exposure_data.get("edges", [])
        notes = []
        for index, edge in enumerate(interactions, start=1):
            interaction = edge["node"]
            lines = []
            for field, value in interaction.items():
                if field != "created" and value:
                    lines.append(f"{field}:\n{value}")
            # Compile the content from the interaction into a single string
            content = "\n\n".join(lines)

            # Where present append the timestamp of the interaction
            abstract = f"Interaction {index}"
            if interaction.get("created"):
                created_at = datetime.fromisoformat(interaction["created"])
                abstract += f" at {created_at.strftime('%Y-%m-%d %H:%M UTC')}"

            notes.append(
                Note(
                    abstract=abstract,
                    content=content,
                    created=exposure["created"],
                    author=self.author,
                    markings=[self.tlp_marking],
                    objects=[incident_response_object],
                )
            )
        return notes

    def _map_course_of_action(self, exposure: dict[str, Any]) -> stix2.CourseOfAction:
        signature = exposure["signature"]
        name = signature["name"]
        return CourseOfAction(
            name=name,
            description=signature["recommendations"],
            created=datetime.fromisoformat(exposure["created"]),
            author=self.author,
            markings=[self.tlp_marking],
        ).to_stix2_object()

    def _map_incident_response(
        self, exposure: dict[str, Any], object_refs: list[str]
    ) -> CustomObjectCaseIncident:
        signature = exposure["signature"]
        incident_name = signature["name"]
        exposure_id = str(exposure["id"])
        workflow_id = self.status_mapping.get(exposure.get("triageState"))

        # NB: connectors-sdk appears to have no Incident Response / Case Incident object
        return CustomObjectCaseIncident(
            id=CaseIncident.generate_id(
                f"{incident_name} [{exposure_id}]", exposure["created"]
            ),
            name=f"{incident_name}: {exposure['asset']['host']}",
            description=signature["description"],
            severity=self._map_severity(exposure["severityString"]),
            labels=[self._incident_label(exposure)],
            # Append an External Reference back to the Exposure in the AssetNote platform
            external_references=[
                ExternalReference(
                    source_name="Assetnote",
                    external_id=exposure_id,
                    url=f"{self.api_base_url}/exposures/{exposure_id}/overview",
                ).to_stix2_object()
            ],
            object_refs=object_refs,
            created=datetime.fromisoformat(exposure["created"]),
            created_by_ref=self.author.id,
            object_marking_refs=[self.tlp_marking.id],
            # Assign the appropriate status template
            x_opencti_workflow_id=workflow_id,
        )

    @staticmethod
    def _incident_label(exposure: dict[str, Any]) -> str:
        """Return the Assetnote category label for a Case-Incident."""

        # if exposureType is INDICATOR, this is an indicator
        exposure_type = exposure["exposureType"].upper()
        if exposure_type == "INDICATOR":
            return "assetnote:indicator"

        # if signature class exists, it is one of these three types but falls under vulnerability
        signature_class = (
            (exposure.get("signature") or {}).get("signatureClass", "").upper()
        )
        signature_class_labels = {
            "TPPE": "assetnote:third-party-platform",
            "IOC": "assetnote:indicator-of-compromise",
            "HYGIENE": "assetnote:security-hygiene",
        }
        # else it is a vulnerability
        return signature_class_labels.get(signature_class, "assetnote:vulnerability")

    @staticmethod
    def _map_severity(severity_string: str) -> str:
        SEVERITY_MAPPINGS = {
            "informational": "low",
            "info": "low",
            "none": "low",
            "low": "low",
            "medium": "medium",
            "high": "high",
            "critical": "critical",
        }
        return SEVERITY_MAPPINGS[severity_string.lower()]
