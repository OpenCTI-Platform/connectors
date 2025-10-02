import pycti
import stix2
import stix2.exceptions
from api_client.models import TagItem
from connector.threats_guesser import ThreatsGuesser

from .common import (
    PAP_AMBER,
    PAP_CLEAR,
    PAP_GREEN,
    PAP_RED,
    TLP_AMBER_STRICT,
    TLP_CLEAR,
    ConverterConfig,
    ConverterError,
)
from .utils import is_uuid


class TagConverterError(ConverterError):
    """Custom exception for event's tags conversion errors."""


class TagConverter:
    def __init__(self, config: ConverterConfig, threats_guesser: ThreatsGuesser = None):
        self.config = config
        self.threats_guesser = threats_guesser

    def create_author(self, tag: TagItem) -> stix2.Identity | None:
        if tag.name.startswith("creator") and "=" in tag.name:
            author_name = tag.name.split("=")[1]
            return stix2.Identity(
                id=pycti.Identity.generate_id(
                    name=author_name,
                    identity_class="organization",
                ),
                name=author_name,
                identity_class="organization",
            )

    def create_label(self, tag: TagItem) -> str | None:
        # If no tags are configured to be kept as labels, keep all tags as labels
        # This is a bug that existed on master before the ConfigLoader was added
        # For the sake of backward compatibility, we keep this behavior for now (no breaking change)
        # An issue has been opened: https://github.com/OpenCTI-Platform/connectors/issues/4886
        if not self.config.original_tags_to_keep_as_labels:
            self.config.original_tags_to_keep_as_labels = [""]

        if tag.name.startswith(tuple(self.config.original_tags_to_keep_as_labels)):
            return tag.name

        marking_tag_names = [
            "tlp:white",
            "tlp:clear",
            "tlp:green",
            "tlp:amber",
            "tlp:amber+strict",
            "tlp:red",
            "pap:clear",
            "pap:green",
            "pap:amber",
            "pap:red",
        ]
        entity_tag_names = (
            "misp-galaxy:threat-actor",
            "misp-galaxy:mitre-threat-actor",
            "misp-galaxy:microsoft-activity-group",
            "misp-galaxy:mitre-enterprise-attack-threat-actor",
            "misp-galaxy:mitre-mobile-attack-intrusion-set",
            "misp-galaxy:mitre-intrusion-set",
            "misp-galaxy:mitre-enterprise-attack-intrusion-set",
            "misp-galaxy:mitre-malware",
            "misp-galaxy:mitre-enterprise-attack-malware",
            "misp-galaxy:mitre-attack-pattern",
            "misp-galaxy:mitre-enterprise-attack-attack-pattern",
            "misp-galaxy:mitre-tool",
            "misp-galaxy:tool",
            "misp-galaxy:ransomware",
            "misp-galaxy:malpedia",
            "misp-galaxy:sector",
            "misp-galaxy:country",
            "misp-galaxy:region",
            "marking",
            "creator",
            "intrusion-set",
            "malware",
            "tool",
            "mitre",
        )

        if tag.name.lower() not in marking_tag_names and not tag.name.startswith(
            entity_tag_names
        ):
            tag_value = tag.name
            if '="' in tag.name:
                tag_value_split = tag.name.split('="')
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    tag_value = tag_value_split[1][:-1].strip()
            elif ":" in tag.name:
                tag_value_split = tag.name.split(":")
                if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                    tag_value = tag_value_split[1].strip()
            if tag_value.isdigit():
                if ":" in tag.name:
                    tag_value_split = tag.name.split(":")
                    if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
                        tag_value = tag_value_split[1].strip()
                else:
                    tag_value = tag.name
            if '="' in tag_value:
                if len(tag_value) > 0:
                    tag_value = tag_value.replace('="', "-")[:-1]
            return tag_value

    def create_marking(self, tag: TagItem) -> stix2.MarkingDefinition | None:
        match tag.name.lower():
            case "tlp:clear":
                return TLP_CLEAR
            case "tlp:white":
                return TLP_CLEAR
            case "tlp:green":
                return stix2.TLP_GREEN
            case "tlp:amber":
                return stix2.TLP_AMBER
            case "tlp:amber+strict":
                return TLP_AMBER_STRICT
            case "tlp:red":
                return stix2.TLP_RED
            # handle PAP markings
            case "pap:clear":
                return PAP_CLEAR
            case "pap:green":
                return PAP_GREEN
            case "pap:amber":
                return PAP_AMBER
            case "pap:red":
                return PAP_RED

    def create_custom_marking(self, tag: TagItem) -> stix2.MarkingDefinition | None:
        if not tag.name.lower().startswith("marking"):
            return None

        marking_definition_split = tag.name.split(":")
        # Check if second part also contains ":"
        if len(marking_definition_split) > 2:
            # Example: marking:PAP=PAP:RED
            # "PAP=PAP" + "RED"
            marking_definition = (
                marking_definition_split[1] + ":" + marking_definition_split[2]
            )
        else:
            # Example: marking:CLASSIFICATION=DIFFUSION RESTREINTE
            # CLASSIFICATION=DIFFUSION RESTREINTE
            marking_definition = marking_definition_split[1]

        # Split on the equal
        marking_definition_split2 = marking_definition.split("=")

        # PAP
        # CLASSIFICATION
        marking_type = marking_definition_split2[0]

        # PAP:RED
        # DIFFUSION RESTREINTE
        marking_name = marking_definition_split2[1]

        return stix2.MarkingDefinition(
            id=pycti.MarkingDefinition.generate_id(marking_type, marking_name),
            definition_type="statement",
            definition={"statement": "custom"},
            allow_custom=True,
            x_opencti_definition_type=marking_type,
            x_opencti_definition=marking_name,
        )

    def create_intrusion_set(
        self,
        tag: TagItem,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> stix2.IntrusionSet | None:
        if "=" in tag.name:
            tag_value_split = tag.name.split('="')
        else:
            tag_value_split = tag.name.split(":")
        if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
            if "=" in tag.name:
                tag_value = tag_value_split[1][:-1].strip()
            else:
                tag_value = tag_value_split[1].strip()
            if " - G" in tag_value:
                name = tag_value.split(" - G")[0]
            elif "APT " in tag_value:
                name = tag_value.replace("APT ", "APT")
            else:
                name = tag_value

            if not is_uuid(name):
                return stix2.IntrusionSet(
                    id=pycti.IntrusionSet.generate_id(name=name),
                    name=name,
                    created_by_ref=author["id"],
                    object_marking_refs=markings,
                    allow_custom=True,
                )

    def create_tool(
        self,
        tag: TagItem,
        author: stix2.Identity,
        markings=list[stix2.MarkingDefinition],
    ) -> stix2.Tool | None:
        if "=" in tag.name:
            tag_value_split = tag.name.split('="')
        else:
            tag_value_split = tag.name.split(":")
        if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
            if "=" in tag.name:
                tag_value = tag_value_split[1][:-1].strip()
            else:
                tag_value = tag_value_split[1].strip()
            if " - S" in tag_value:
                name = tag_value.split(" - S")[0]
            else:
                name = tag_value

            return stix2.Tool(
                id=pycti.Tool.generate_id(name=name),
                name=name,
                created_by_ref=author["id"],
                object_marking_refs=markings,
                allow_custom=True,
            )

    def create_malware(
        self,
        tag: TagItem,
        author: stix2.Identity,
        markings=list[stix2.MarkingDefinition],
    ) -> stix2.Malware | None:
        if "=" in tag.name:
            tag_value_split = tag.name.split('="')
        else:
            tag_value_split = tag.name.split(":")
        if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
            if "=" in tag.name:
                tag_value = tag_value_split[1][:-1].strip()
            else:
                tag_value = tag_value_split[1].strip()
            if " - S" in tag_value:
                name = tag_value.split(" - S")[0]
            else:
                name = tag_value
            return stix2.Malware(
                id=pycti.Malware.generate_id(name=name),
                name=name,
                is_family=True,
                created_by_ref=author["id"],
                object_marking_refs=markings,
                allow_custom=True,
            )

    def create_attack_pattern(
        self,
        tag: TagItem,
        author: stix2.Identity,
        markings=list[stix2.MarkingDefinition],
    ) -> stix2.AttackPattern | None:
        if "=" in tag.name:
            tag_value_split = tag.name.split('="')
        else:
            tag_value_split = tag.name.split(":")
        if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
            if "=" in tag.name:
                tag_value = tag_value_split[1][:-1].strip()
            else:
                tag_value = tag_value_split[1].strip()
            if " - T" in tag_value:
                name = tag_value.split(" - T")[0]
            else:
                name = tag_value
            return stix2.AttackPattern(
                id=pycti.AttackPattern.generate_id(name=name),
                name=name,
                created_by_ref=author["id"],
                object_marking_refs=markings,
                allow_custom=True,
            )

    def create_sector(
        self,
        tag: TagItem,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> stix2.Identity | None:
        tag_value_split = tag.name.split('="')
        if len(tag_value_split) > 1 and len(tag_value_split[1]) > 0:
            name = tag_value_split[1][:-1].strip()
            return stix2.Identity(
                id=pycti.Identity.generate_id(name=name, identity_class="class"),
                name=name,
                identity_class="class",
                created_by_ref=author["id"],
                object_marking_refs=markings,
                allow_custom=True,
            )

    def guess_threats(
        self,
        tag: TagItem,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> list[stix2.v21._STIXBase21]:
        domain_objects = []
        added_names = []

        tag_value_split = tag.name.split("=")
        if len(tag_value_split) == 1:
            tag_value = tag_value_split[0]
        else:
            tag_value = tag_value_split[1].replace('"', "")
        tag_value_split = tag_value.split(":")
        if len(tag_value_split) == 1:
            tag_value = tag_value_split[0]
        else:
            tag_value = tag_value_split[1].replace('"', "")
        if not tag_value:
            return domain_objects

        threats = self.threats_guesser.search_by_name_or_id(tag_value)
        if not threats:
            return domain_objects

        threat = threats[0]
        threat_name = threat["name"]
        if threat_name not in added_names and not is_uuid(threat_name):
            if threat["entity_type"] == "Intrusion-Set":
                domain_objects.append(
                    stix2.IntrusionSet(
                        id=pycti.IntrusionSet.generate_id(name=threat_name),
                        name=threat_name,
                        created_by_ref=author["id"],
                        object_marking_refs=markings,
                        allow_custom=True,
                    )
                )
                added_names.append(threat_name)
            if threat["entity_type"] == "Malware":
                domain_objects.append(
                    stix2.Malware(
                        id=pycti.Malware.generate_id(name=threat_name),
                        name=threat_name,
                        is_family=True,
                        created_by_ref=author["id"],
                        object_marking_refs=markings,
                        allow_custom=True,
                    )
                )
                added_names.append(threat_name)
            if threat["entity_type"] == "Tool":
                domain_objects.append(
                    stix2.Tool(
                        id=pycti.Tool.generate_id(name=threat_name),
                        name=threat_name,
                        created_by_ref=author["id"],
                        object_marking_refs=markings,
                        allow_custom=True,
                    )
                )
                added_names.append(threat_name)
            if threat["entity_type"] == "Attack-Pattern":
                domain_objects.append(
                    stix2.AttackPattern(
                        id=pycti.AttackPattern.generate_id(name=threat_name),
                        name=threat_name,
                        created_by_ref=author["id"],
                        object_marking_refs=markings,
                        allow_custom=True,
                    )
                )
                added_names.append(threat_name)

        return domain_objects

    def process(
        self,
        tag: TagItem,
        author: stix2.Identity,
        markings: list[stix2.MarkingDefinition],
    ) -> list[stix2.v21._STIXBase21]:
        stix_objects = []

        # Keep track of created objects names to avoid duplicates
        stix_objects_names = []

        try:
            # Try to guess from tags
            if self.config.guess_threats_from_tags:
                stix_objects.extend(
                    self.guess_threats(tag, author=author, markings=markings)
                )
                stix_objects_names.extend(
                    [stix_object["name"] for stix_object in stix_objects]
                )

            # Get the linked intrusion sets
            intrusion_set_tag_names = (
                "misp-galaxy:threat-actor",
                "misp-galaxy:mitre-mobile-attack-intrusion-set",
                "misp-galaxy:microsoft-activity-group",
                "misp-galaxy:mitre-threat-actor",
                "misp-galaxy:mitre-enterprise-attack-threat-actor",
                "misp-galaxy:mitre-intrusion-set",
                "misp-galaxy:mitre-enterprise-attack-intrusion-set",
                "intrusion-set",
            )
            if tag.name.startswith(intrusion_set_tag_names):
                intrusion_set = self.create_intrusion_set(tag, author, markings)
                if intrusion_set and intrusion_set["name"] not in stix_objects_names:
                    stix_objects.append(intrusion_set)
                    stix_objects_names.append(intrusion_set["name"])

            # Get the linked tools
            tool_tag_names = (
                "misp-galaxy:mitre-tool",
                "misp-galaxy:mitre-enterprise-attack-tool",
                "tool",
            )
            if tag.name.startswith(tool_tag_names):
                tool = self.create_tool(tag, author, markings)
                if tool and tool["name"] not in stix_objects_names:
                    stix_objects.append(tool)
                    stix_objects_names.append(tool["name"])

            # Get the linked malwares
            malware_tag_names = (
                "misp-galaxy:mitre-malware",
                "misp-galaxy:mitre-enterprise-attack-malware",
                "misp-galaxy:misp-ransomware",
                "misp-galaxy:misp-tool",
                "misp-galaxy:misp-android",
                "misp-galaxy:misp-malpedia",
                "malware",
            )
            if tag.name.startswith(malware_tag_names):
                malware = self.create_malware(tag, author, markings)
                if malware and malware["name"] not in stix_objects_names:
                    stix_objects.append(malware)
                    stix_objects_names.append(malware["name"])

            # Get the linked attack_patterns
            attack_pattern_tag_names = (
                "misp-galaxy:mitre-attack-pattern",
                "misp-galaxy:attack-pattern",
                "mitre-attack:attack-pattern",
                "mitre:",
            )
            if tag.name.startswith(attack_pattern_tag_names):
                attack_pattern = self.create_attack_pattern(tag, author, markings)
                if attack_pattern and attack_pattern["name"] not in stix_objects_names:
                    stix_objects.append(attack_pattern)
                    stix_objects_names.append(attack_pattern["name"])

            # Get the linked sectors
            if tag.name.startswith("misp-galaxy:sector"):
                sector = self.create_sector(tag, author, markings)
                if sector and sector["name"] not in stix_objects_names:
                    stix_objects.append(sector)
                    stix_objects_names.append(sector["name"])

        except stix2.exceptions.STIXError as err:
            raise TagConverterError("Error while converting event's tag") from err

        return stix_objects
