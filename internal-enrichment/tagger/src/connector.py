import json
import re
from typing import Dict

from pycti import OpenCTIConnectorHelper, get_config_variable

CONTAINER_TYPE_LIST = ["report", "grouping", "case-incident", "case-rfi", "case-rft"]


def load_re_flags(rule):
    """Load the regular expression flags from a rule definition."""

    config = rule.get("flags") or []

    flags = 0
    for flag in config:
        flag = getattr(re, flag)
        flags |= flag

    return flags


class TaggerConnector:
    def __init__(self):
        self.helper = OpenCTIConnectorHelper({})
        self.definitions = json.loads(get_config_variable("TAGGER_DEFINITIONS", []))

    def start(self):
        self.helper.listen(message_callback=self._process_message)

    def _process_message(self, data: Dict) -> str:
        enrichment_entity = data["enrichment_entity"]

        for definition in self.definitions:
            for scope in definition["scopes"]:
                entity_type = scope.lower()

                #  Check if enrichment entity is supported
                if enrichment_entity["entity_type"].lower() != entity_type:
                    continue

                for rule in definition["rules"]:
                    flags = load_re_flags(rule)

                    for attribute in rule["attributes"]:
                        if (attribute.lower() == "objects-type") or (
                            attribute.lower() == "objects-name"
                        ):
                            attr = enrichment_entity.get("objects")
                        else:
                            attr = enrichment_entity.get(attribute)
                        if attr is None:
                            continue

                        # Handles the case where the attribute is the list of labels
                        if attribute.lower() == "objectlabel":
                            for obj in attr:
                                if not re.search(
                                    rule["search"], obj["value"], flags=flags
                                ):
                                    continue

                                self.add_label(
                                    enrichment_entity["standard_id"], rule["label"]
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
                                    if not re.search(
                                        rule["search"], obj["entity_type"], flags=flags
                                    ):
                                        continue

                                    self.add_label(
                                        enrichment_entity["standard_id"], rule["label"]
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

                                    if not re.search(rule["search"], name, flags=flags):
                                        continue

                                    self.add_label(
                                        enrichment_entity["standard_id"], rule["label"]
                                    )
                                    break

                                continue

                        if not re.search(rule["search"], attr, flags=flags):
                            continue

                        self.add_label(enrichment_entity["standard_id"], rule["label"])
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
