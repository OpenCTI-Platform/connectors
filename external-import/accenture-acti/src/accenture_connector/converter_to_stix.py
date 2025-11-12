import stix2
from pycti import AttackPattern, Identity, Location, MarkingDefinition


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.

    REQUIREMENTS:
    - generate_id() for each entity from OpenCTI pycti library except observables to create
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self.create_author()

    @staticmethod
    def create_author() -> stix2.v21.Identity:
        """
        Create Author
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="Accenture", identity_class="organization"),
            name="Accenture",
            identity_class="organization",
        )
        return author

    @staticmethod
    def create_tlp_marking(level):
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "amber+strict": stix2.MarkingDefinition(
                id=MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"),
                definition_type="statement",
                definition={"statement": "custom"},
                custom_properties={
                    "x_opencti_definition_type": "TLP",
                    "x_opencti_definition": "TLP:AMBER+STRICT",
                },
            ),
            "red": stix2.TLP_RED,
        }
        return mapping[level]

    def generate_entities(self, labels):
        entities = []
        processed_labels = set()
        labels = [label.strip() for label in labels]
        for label in labels:
            if label in self.config.mapping:
                mapping = self.config.mapping[label]
                appended = False

                # Locations: Country
                if mapping["opencti_country"] is not None:
                    entities.append(
                        stix2.Location(
                            id=Location.generate_id(
                                mapping["opencti_country"], "Country"
                            ),
                            name=mapping["opencti_country"],
                            country=mapping["opencti_country"],
                            custom_properties={
                                "x_opencti_aliases": [label],
                                "x_opencti_location_type": "Country",
                            },
                        )
                    )
                    appended = True

                # Locations: Region
                elif mapping["opencti_region"] is not None:
                    aliases = []
                    if mapping["region"] is not None:
                        aliases.append(mapping["region"])
                    entities.append(
                        stix2.Location(
                            id=Location.generate_id(
                                mapping["opencti_region"], "Region"
                            ),
                            name=mapping["opencti_region"],
                            region=mapping["opencti_region"],
                            custom_properties={
                                "x_opencti_aliases": aliases,
                                "x_opencti_location_type": "Region",
                            },
                        )
                    )
                    appended = True

                # Sectors
                if mapping["opencti_industry"] is not None:
                    aliases = []
                    if mapping["industry"] is not None:
                        aliases.append(mapping["industry"])
                    elif mapping["industry-group"] is not None:
                        aliases.append(mapping["industry-group"])
                    elif mapping["vertical"] is not None:
                        aliases.append(mapping["vertical"])
                    entities.append(
                        stix2.Identity(
                            id=Identity.generate_id(
                                mapping["opencti_industry"], "class"
                            ),
                            name=mapping["opencti_industry"],
                            identity_class="class",
                            custom_properties={
                                "x_opencti_aliases": aliases,
                            },
                        )
                    )
                    appended = True

                # Attack Patterns
                if mapping["opencti_attack_pattern"] is not None:
                    entities.append(
                        stix2.AttackPattern(
                            id=AttackPattern.generate_id(
                                mapping["opencti_attack_pattern"]
                            ),
                            name=mapping["opencti_attack_pattern"],
                            aliases=[label],
                            custom_properties={
                                "x_mitre_id": mapping["opencti_attack_pattern"],
                            },
                        )
                    )
                    appended = True

                if appended:
                    processed_labels.add(label)

        # Remove processed labels from input list
        for label in processed_labels:
            labels.remove(label)

        return {"labels": labels, "entities": entities}
