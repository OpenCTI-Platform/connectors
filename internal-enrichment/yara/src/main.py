import os
import traceback

import stix2
import yaml
import yara
from pycti import (
    Identity,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)
from stix2 import Bundle, Relationship


class YaraConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
        )
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
                         ‘importFiles’ key and a list of files to be retrieved.
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

    @staticmethod
    def _collect_marking_refs(artifact, indicator):
        """Collect unique marking definition refs from both entities."""
        marking_refs = set()
        for marking in artifact.get("objectMarking", []):
            std_id = marking.get("standard_id")
            if std_id:
                marking_refs.add(std_id)
        for marking in indicator.get("objectMarking", []):
            std_id = marking.get("standard_id")
            if std_id:
                marking_refs.add(std_id)
        return list(marking_refs) if marking_refs else None

    def _scan_artifact(self, artifact, yara_indicators) -> tuple[list, list[str]]:
        self.helper.connector_logger.debug("Scanning Artifact contents with YARA")

        artifact_contents = self._get_artifact_contents(artifact)

        bundle_objects = []
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
                    relationship_kwargs = dict(
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
                        relationship_kwargs["object_marking_refs"] = marking_refs
                    relationship = Relationship(**relationship_kwargs)
                    bundle_objects.append(relationship)
                    self.helper.connector_logger.debug(
                        f"Created Relationship from Artifact to YARA Indicator {indicator['name']}"
                    )

        return bundle_objects, errors

    def _process_message(self, data: dict) -> str:
        entity_id = data["entity_id"]
        stix_objects = data.get("stix_objects", [])

        # Check scope — forward original bundle if entity type is out of scope
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        entity_type = entity_id.split("--")[0].lower()
        if entity_type not in scopes:
            self.helper.connector_logger.info(
                "Entity type not in connector scope, forwarding original bundle",
                {"entity_id": entity_id, "entity_type": entity_type},
            )
            if stix_objects:
                bundle = Bundle(objects=stix_objects).serialize()
                self.helper.send_stix2_bundle(bundle)
            return "Entity type not in scope"

        self.helper.connector_logger.info(f"Enriching {entity_id}")
        artifact = data["enrichment_entity"]

        yara_indicators = self._get_yara_indicators()
        if not yara_indicators:
            self.helper.connector_logger.debug("No YARA Indicators to match")
            return "No YARA Indicators to match"

        rule_count = len(yara_indicators)
        self.helper.connector_logger.debug(
            f"Scanning an Artifact with {rule_count} rules"
        )
        new_objects, errors = self._scan_artifact(artifact, yara_indicators)

        if new_objects:
            all_objects = stix_objects + [self.author] + new_objects
            bundle = Bundle(objects=all_objects).serialize()
            self.helper.send_stix2_bundle(bundle)
        elif stix_objects:
            bundle = Bundle(objects=stix_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

        if errors:
            return f"Completed with {len(errors)} YARA error(s): {'; '.join(errors)}"

        return "Done"

    # Start the main loop
    def start(self) -> None:
        self.helper.connector_logger.info("YARA connector started")
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        connector = YaraConnector()
        connector.start()
    except Exception:
        traceback.print_exc()
        exit(1)
