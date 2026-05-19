from connector.converter_to_stix import ConverterToStix


class BaseUseCases:
    def __init__(
        self,
        converter_to_stix: ConverterToStix,
    ):
        self.converter_to_stix = converter_to_stix

    def generate_author_and_tlp_markings(self):
        """
        Create author and TLP
        """
        common_objects = []
        # Author
        author = self.converter_to_stix.create_author()
        common_objects.append(author.to_stix2_object())

        # TLPMarkings
        tlp_clear = self.converter_to_stix.create_tlp_marking("clear")
        common_objects.append(tlp_clear.to_stix2_object())
        tlp_amber = self.converter_to_stix.create_tlp_marking("amber")
        common_objects.append(tlp_amber.to_stix2_object())

        return common_objects
