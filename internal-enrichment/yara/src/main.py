import os
import sys
import time

import yaml
import yara
from pycti import OpenCTIConnectorHelper, StixCoreRelationship, get_config_variable
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

    def _get_artifact(self, entity_id):
        self.helper.log_debug("Getting Artifact from OpenCTI")

        customAttributes = """
        id
        standard_id
        observable_value
        ... on Artifact {
                importFiles {
                        edges {
                                node {
                                    id
                                    name
                                }
                            }
                        }
        }
        """
        observable = self.helper.api.stix_cyber_observable.read(
            id=entity_id, customAttributes=customAttributes
        )
        return observable

    def _get_artifact_contents(self, artifact) -> bytes:
        self.helper.log_debug("Getting Artifact contents (bytes) from OpenCTI")

        file_id = artifact["importFiles"][0]["id"]
        file_url = self.octi_api_url + "/storage/get/" + file_id
        file_content = self.helper.api.fetch_opencti_file(file_url, binary=True)
        return file_content

    def _get_yara_indicators(self) -> list:
        self.helper.log_debug("Getting all YARA Indicators in OpenCTI")

        data = {"pagination": {"hasNextPage": True, "endCursor": None}}
        while data["pagination"]["hasNextPage"]:
            after = data["pagination"]["endCursor"]
            data = self.helper.api.indicator.list(
                first=1000,
                after=after,
                filters=[{"key": "pattern_type", "values": ["yara"]}],
                orderBy="created_at",
                orderMode="asc",
                withPagination=True,
            )
        return data["entities"]

    def _scan_artifact(self, artifact, yara_indicators) -> None:
        self.helper.log_debug("Scanning Artifact contents with YARA")

        artifact_contents = self._get_artifact_contents(artifact)

        bundle_objects = []

        for indicator in yara_indicators:
            try:
                rule_content = indicator["pattern"]
                rule = yara.compile(source=rule_content)
            except yara.SyntaxError:
                self.helper.log_debug(
                    f"Encountered YARA syntax error {indicator['name']}"
                )
                continue

            results = rule.match(data=artifact_contents, timeout=60)
            if results:
                relationship = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to", artifact["standard_id"], indicator["standard_id"]
                    ),
                    relationship_type="related-to",
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

        response = "Done"

        artifact = self._get_artifact(entity_id)

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
        self.helper.listen(self._process_message)


if __name__ == "__main__":
    try:
        connector = YaraConnector()
        connector.start()
    except Exception as e:
        print(e)
        time.sleep(10)
        sys.exit(0)
