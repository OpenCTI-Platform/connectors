from typing import Dict

from pycti import OpenCTIConnectorHelper
from settings import ConfigLoader

CONTAINER_TYPE_LIST = ["report", "grouping", "case-incident", "case-rfi", "case-rft"]


class TaggerConnector:
    def __init__(self):
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(config=self.config.to_helper_config())

    def start(self):
        self.helper.listen(message_callback=self._process_message)

    def _process_message(self, data: Dict) -> str:
        enrichment_entity = data["enrichment_entity"]

        for definition in self.config.tagger.definitions:
            for scope in definition.scopes:
                entity_type = scope.lower()

                #  Check if enrichment entity is supported
                if enrichment_entity["entity_type"].lower() != entity_type:
                    continue

                for rule in definition.rules:
                    for attribute in rule.attributes:
                        if attribute.lower() in ["objects-type", "objects-name"]:
                            attr = enrichment_entity.get("objects")
                        else:
                            attr = enrichment_entity.get(attribute)
                        if attr is None:
                            continue

                        # Handles the case where the attribute is the list of labels
                        if attribute.lower() == "objectlabel":
                            for obj in attr:
                                if not rule.pattern.search(obj["value"]):
                                    continue

                                self.add_label(
                                    enrichment_entity["standard_id"], rule.label
                                )
                                break

                            continue

                        # Checks that the entity is a container
                        if (
                            enrichment_entity["entity_type"].lower()
                            in CONTAINER_TYPE_LIST
                        ):

                            # Handles the case where the attribute is the list of objects
                            if attribute.lower() == "objects-type":
                                for obj in attr:
                                    if not rule.pattern.search(obj["entity_type"]):
                                        continue

                                    self.add_label(
                                        enrichment_entity["standard_id"], rule.label
                                    )
                                    break

                                continue

                            elif attribute.lower() == "objects-name":
                                for obj in attr:

                                    name = obj.get(
                                        "name", obj.get("observable_value", None)
                                    )
                                    if name is None:
                                        continue

                                    if not rule.pattern.search(name):
                                        continue

                                    self.add_label(
                                        enrichment_entity["standard_id"], rule.label
                                    )
                                    break

                                continue

                        if not rule.pattern.search(attr):
                            continue

                        self.add_label(enrichment_entity["standard_id"], rule.label)
                        break

    def add_label(self, entity, label):
        """Send the API call to apply the label on the entity."""

        self.helper.api.stix_domain_object.add_label(
            id=entity,
            label_name=label,
        )


if __name__ == "__main__":
    connector = TaggerConnector()
    connector.start()
