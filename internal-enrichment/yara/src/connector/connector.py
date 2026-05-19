import stix2
import yara
from connector.settings import ConnectorSettings
from pycti import (
    Identity,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from stix2 import Relationship


class YaraConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.octi_api_url = str(self.config.opencti.url).rstrip("/")
        self.tlp_level = self.config.yara.tlp_level
        self.author = stix2.Identity(
            id=Identity.generate_id("YARA", "organization"),
            name="YARA",
            identity_class="organization",
            description="YARA connector for OpenCTI",
        )

    def _get_artifact_contents(self, artifact) -> list[bytes]:
        """
        Retrieves the content associated with the artefact from OpenCTI, extracts the files and downloads their
        contents in binary format for further processing.

        :param artifact: Dictionary containing all the information in the OpenCTI artefact, potentially with an
                         'importFiles' key and a list of files to be retrieved.
        :return: List of the binary contents of the files associated with the artefact, returns an empty list `[]`
                 if no files are associated.
        """
        self.helper.connector_logger.debug(
            "Getting Artifact contents (bytes) from OpenCTI"
        )

        artifact_files_contents = artifact.get("importFiles", [])

        files_contents = []
        if artifact_files_contents:
            for artifact_file_content in artifact_files_contents:
                file_name = artifact_file_content.get("name")
                file_id = artifact_file_content.get("id")
                file_url = self.octi_api_url + "/storage/get/" + file_id
                file_content = self.helper.api.fetch_opencti_file(file_url, binary=True)
                files_contents.append(file_content)
                self.helper.connector_logger.debug(
                    f"Associated file found in Artifact with file_name :{file_name}"
                )
        else:
            self.helper.connector_logger.debug("No associated files found in Artifact")
        return files_contents

    def _get_yara_indicators(self) -> list:
        self.helper.connector_logger.debug("Getting all YARA Indicators in OpenCTI")

        data = {"pagination": {"hasNextPage": True, "endCursor": None}}
        all_entities = []
        customAttributes = """
        id
        name
        standard_id
        pattern
        pattern_type
        valid_from
        objectMarking {
            standard_id
        }
        """
        while data["pagination"]["hasNextPage"]:
            after = data["pagination"]["endCursor"]
            data = self.helper.api.indicator.list(
                first=1000,
                after=after,
                filters={
                    "mode": "and",
                    "filters": [{"key": "pattern_type", "values": ["yara"]}],
                    "filterGroups": [],
                },
                orderBy="created_at",
                orderMode="asc",
                withPagination=True,
                customAttributes=customAttributes,
            )
            all_entities += data["entities"]
        return all_entities

    def _collect_marking_refs(self, artifact, indicator):
        """Collect unique marking definition refs from both entities, falling back to default marking."""
        marking_refs = set()
        for marking in artifact.get("objectMarking", []):
            std_id = marking.get("standard_id")
            if std_id:
                marking_refs.add(std_id)
        for marking in indicator.get("objectMarking", []):
            std_id = marking.get("standard_id")
            if std_id:
                marking_refs.add(std_id)
        if not marking_refs and self.tlp_level:
            tlp_value = "TLP:" + self.tlp_level.upper()
            marking_refs.add(MarkingDefinition.generate_id("TLP", tlp_value))
        return list(marking_refs) if marking_refs else None

    def _scan_artifact(self, artifact, yara_indicators) -> tuple[list, list[str]]:
        self.helper.connector_logger.debug("Scanning Artifact contents with YARA")

        artifact_contents = self._get_artifact_contents(artifact)

        bundle_objects = []
        matched_indicators = {}
        errors = []
        for artifact_content in artifact_contents:
            for indicator in yara_indicators:
                try:
                    rule_content = indicator["pattern"]
                    rule = yara.compile(source=rule_content)
                except yara.SyntaxError as e:
                    msg = f"YARA syntax error in rule '{indicator['name']}': {e}"
                    self.helper.connector_logger.error(msg)
                    errors.append(msg)
                    continue

                results = rule.match(data=artifact_content, timeout=60)
                if results:
                    marking_refs = self._collect_marking_refs(artifact, indicator)
                    relationship = Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to",
                            artifact["standard_id"],
                            indicator["standard_id"],
                        ),
                        relationship_type="related-to",
                        created_by_ref=self.author["id"],
                        source_ref=artifact["standard_id"],
                        target_ref=indicator["standard_id"],
                        description="YARA rule matched for this Artifact",
                    )
                    if marking_refs:
                        relationship = relationship.new_version(
                            object_marking_refs=marking_refs
                        )
                    bundle_objects.append(relationship)
                    # Include matched indicator in bundle so cleanup_inconsistent_bundle
                    # does not remove the relationship referencing it
                    if indicator["standard_id"] not in matched_indicators:
                        matched_indicators[indicator["standard_id"]] = stix2.Indicator(
                            id=indicator["standard_id"],
                            name=indicator["name"],
                            pattern=indicator["pattern"],
                            pattern_type=indicator["pattern_type"],
                            valid_from=indicator["valid_from"],
                        )
                    self.helper.connector_logger.debug(
                        f"Created Relationship from Artifact to YARA Indicator {indicator['name']}"
                    )

        return bundle_objects + list(matched_indicators.values()), errors

    def _process_message(self, data: dict) -> str:
        entity_id = data["entity_id"]
        stix_objects = data.get("stix_objects", [])

        # Preserve original file name to avoid artifact.bin fallback in pycti
        # Artifact naming relies on the presence of `x_opencti_additional_names`
        # but this field is not provided in the enrichment message from OpenCTI.
        if data.get("entity_type") == "Artifact":
            stix_entity = data.get("stix_entity", {})
            x_opencti_files = stix_entity.get("x_opencti_files", [])
            if x_opencti_files:
                file_name = x_opencti_files[0].get("name")
                if file_name:
                    for obj in stix_objects:
                        if isinstance(obj, dict) and obj.get("id") == entity_id:
                            self.helper.connector_logger.info(
                                f"Setting x_opencti_additional_names for Artifact {entity_id} to preserve original file name: {file_name}"
                            )
                            obj.setdefault("x_opencti_additional_names", [file_name])
                            break

        # Check scope — forward original bundle if entity type is out of scope
        entity_type = data.get("entity_type")
        if entity_type not in self.config.connector.scope:
            self.helper.connector_logger.info(
                "Entity type not in connector scope, forwarding original bundle",
                {"entity_id": entity_id, "entity_type": entity_type},
            )
            bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)
            return "Entity type not in scope"

        self.helper.connector_logger.info(f"Enriching {entity_id}")
        artifact = data["enrichment_entity"]
        self.helper.connector_logger.info(f"Artifact to enrich: {artifact}")

        yara_indicators = self._get_yara_indicators()
        if not yara_indicators:
            self.helper.connector_logger.debug("No YARA Indicators to match")
            bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)
            return "No YARA Indicators to match"

        rule_count = len(yara_indicators)
        self.helper.connector_logger.debug(
            f"Scanning an Artifact with {rule_count} rules"
        )
        new_objects, errors = self._scan_artifact(artifact, yara_indicators)

        if new_objects:
            all_objects = stix_objects + [self.author] + new_objects
        else:
            all_objects = stix_objects
        self.helper.connector_logger.debug(
            f"Sending {len(all_objects)} new relationships to OpenCTI"
        )
        bundle = self.helper.stix2_create_bundle(all_objects)
        self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)

        if errors:
            return f"Completed with {len(errors)} YARA error(s): {'; '.join(errors)}"

        return "Done"

    # Start the main loop
    def start(self) -> None:
        self.helper.connector_logger.info("YARA connector started")
        self.helper.listen(message_callback=self._process_message)
