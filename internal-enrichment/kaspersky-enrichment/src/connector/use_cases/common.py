from connector.converter_to_stix import ConverterToStix
from connector.utils import is_quota_exceeded
from connectors_sdk.models import Reference
from pycti import STIX_EXT_OCTI_SCO, OpenCTIConnectorHelper, OpenCTIStix2


class BaseUseCases:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        converter_to_stix: ConverterToStix,
    ):
        self.helper = helper
        self.converter_to_stix = converter_to_stix

    def check_quota(self, license_info: dict) -> None:
        """
        Send a log warning if quota is exceeded
        """
        if is_quota_exceeded(license_info):
            self.helper.connector_logger.warning(
                "[CONNECTOR] The daily quota has been exceeded",
                {
                    "day_requests": license_info["DayRequests"],
                    "day_quota": license_info["DayQuota"],
                },
            )

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

    def update_observable_score(self, zone: str, observable: dict):
        """
        Update score in observable
        """
        score = self.zone_octi_score_mapping[zone.lower()]
        return OpenCTIStix2.put_attribute_in_extension(
            observable, STIX_EXT_OCTI_SCO, "score", score
        )

    def manage_industries(self, observable_to_ref: Reference, industries: list) -> list:
        """
        Create sector and relation for each item in industries
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Process enrichment from Industries data..."
        )

        industry_objects = []
        for industry in industries:
            industry_object = self.converter_to_stix.create_sector(industry)

            if industry_object:
                industry_objects.append(industry_object.to_stix2_object())
                industry_relation = self.converter_to_stix.create_relationship(
                    relationship_type="related-to",
                    source_obj=observable_to_ref,
                    target_obj=industry_object,
                )
                industry_objects.append(industry_relation.to_stix2_object())
        return industry_objects
