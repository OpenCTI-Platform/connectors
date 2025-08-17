import os
import sys
import time

import yaml
import yara
from pycti import (
    OpenCTIApiClient,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
    get_config_variable,
)
from stix2 import TLP_WHITE, Bundle, Relationship


class YaraConnector:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        self.client = OpenCTIApiClient(
            url=self.helper.get_opencti_url(), token=self.helper.get_opencti_token()
        )
        self.octi_api_url = get_config_variable(
            "OPENCTI_URL", ["opencti", "url"], config
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
        self.helper.log_debug("Getting Artifact contents (bytes) from OpenCTI")

        artifact_files_contents = artifact.get("importFiles", [])

        files_contents = []
        if artifact_files_contents:
            for artifact_file_content in artifact_files_contents:
                file_name = artifact_file_content.get("name")
                file_id = artifact_file_content.get("id")
                file_url = self.octi_api_url + "/storage/get/" + file_id
                file_content = self.helper.api.fetch_opencti_file(file_url, binary=True)
                files_contents.append(file_content)
                self.helper.log_debug(
                    f"Associated file found in Artifact with file_name :{file_name}"
                )
        else:
            self.helper.log_debug("No associated files found in Artifact")
        return files_contents

    def _get_yara_indicators(self) -> list:
        self.helper.log_debug("Getting all YARA Indicators in OpenCTI")

        data = {"pagination": {"hasNextPage": True, "endCursor": None}}
        customAttributes = """
        id
        name
        standard_id
        pattern
        pattern_type
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
        return data["entities"]

    def _scan_artifact(self, artifact, yara_indicators) -> None:
        self.helper.log_debug("Scanning Artifact contents with YARA")

        artifact_contents = self._get_artifact_contents(artifact)

        bundle_objects = []
        for artifact_content in artifact_contents:
            for indicator in yara_indicators:
                try:
                    rule_content = indicator["pattern"]
                    rule = yara.compile(source=rule_content)
                except yara.SyntaxError:
                    self.helper.log_error(
                        f"Encountered YARA syntax error {indicator['name']}"
                    )
                    continue

                results = rule.match(data=artifact_content, timeout=60)
                if results:
                    relationship = Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to",
                            artifact["standard_id"],
                            indicator["standard_id"],
                        ),
                        relationship_type="related-to",
                        object_marking_refs=[TLP_WHITE],
                        source_ref=artifact["standard_id"],
                        target_ref=indicator["standard_id"],
                        description="YARA rule matched for this Artifact",
                    )
                    bundle_objects.append(relationship)
                    self.helper.log_debug(
                        f"Created Relationship from Artifact to YARA Indicator {indicator['name']}"
                    )

        if any(bundle_objects):
            bundle = Bundle(objects=bundle_objects).serialize()
            self.helper.send_stix2_bundle(bundle)

    def _process_message(self, data: dict) -> str:
        entity_id = data["entity_id"]
        self.helper.log_info(f"Enriching {entity_id}")
        artifact = data["enrichment_entity"]

        response = "Done"
        yara_indicators = self._get_yara_indicators()
        if any(yara_indicators):
            rule_count = len(yara_indicators)
            self.helper.log_debug(f"Scanning an Artifact with {rule_count} rules")
            self._scan_artifact(artifact, yara_indicators)
        else:
            self.helper.log_debug("No YARA Indicators to match")
            response = "No YARA Indicators to match"

        return response

    # Start the main loop
    def start(self) -> None:
        self.helper.log_info("YARA connector started")
        self.helper.listen(message_callback=self._process_message)


if __name__ == "__main__":
    try:
        connector = YaraConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
