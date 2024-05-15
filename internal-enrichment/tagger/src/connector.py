import json
import re
from typing import Dict

from pycti import OpenCTIConnectorHelper, get_config_variable


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
                if enrichment_entity["entity_type"] != entity_type:
                    continue

                for rule in definition["rules"]:
                    flags = load_re_flags(rule)

                    for attribute in rule["attributes"]:
                        self.helper.log_debug(enrichment_entity)
                        attr = enrichment_entity[attribute]
                        if attribute.lower() == "objectlabel":
                            for el in attr:
                                if not re.search(
                                    rule["search"], el["value"], flags=flags
                                ):
                                    continue

                                self.helper.api.stix_domain_object.add_label(
                                    id=enrichment_entity["standard_id"],
                                    label_name=rule["label"],
                                )
                                break

                            continue

                        if not re.search(rule["search"], attr, flags=flags):
                            continue

                        self.helper.api.stix_domain_object.add_label(
                            id=enrichment_entity["standard_id"],
                            label_name=rule["label"],
                        )
                        break


if __name__ == "__main__":
    connector = TaggerConnector()
    connector.start()
