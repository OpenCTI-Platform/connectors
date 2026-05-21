import stix2
from pycti import Identity, Indicator, Location, MarkingDefinition, StixCoreRelationship

from .mapping import (
    BUSINESS_TYPE,
    CONTENT_TYPE,
    HASH_ALGORITHMS,
    INDUSTRY_OBJ,
    OBSERVABLE_TYPES,
    THREAT_TYPE,
)
from .utils import get_hash_name, get_obs_value


class ConverterToStix:
    """
    Provides methods for converting various types of input data into STIX 2.1 objects.
    """

    def __init__(self, helper, config):
        self.helper = helper
        self.config = config
        self.author = self.create_author()
        self.tlp_marking = self._create_tlp_marking(level=self.config.tlp_level)

    @staticmethod
    def create_author() -> dict:
        """
        Create Author.
        :return: Author in Stix2 object
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="NTI", identity_class="organization"),
            name="NTI",
            identity_class="organization",
            description="NSFOCUS Threat Intelligence (NTI) is a specialized threat intelligence cloud platform established by NSFOCUS Technology to promote the construction of a cybersecurity ecosystem and the application of threat intelligence, enhancing customers' offensive and defensive capabilities. Leveraging the company’s professional security team and strong research capabilities, NTI continuously observes and analyzes global cybersecurity threats and trends. With a focus on the production, operation, and application of threat intelligence, as well as key technologies, NTI provides users with enterprise-level services such as basic intelligence queries, advanced intelligence queries, intelligence subscriptions, and visual correlation analysis, helping users better understand and respond to various cyber threats.",
            contact_information="nti-services@nsfocus.com",
            custom_properties={
                "x_opencti_organization_type": "vendor",
                "x_opencti_reliability": "A - Completely reliable",
            },
        )
        return author

    @staticmethod
    def _create_tlp_marking(level: str):
        """
        Create TLP marking.
        :param level: TLP level from env variable
        :return:
        """
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

    def create_relationship(
        self,
        source_id: str,
        relationship_type: str,
        target_id: str,
        start_time: str = None,
        stop_time: str = None,
        description: str = None,
    ) -> dict:
        """
        Creates Relationship object
        :param stop_time: Relationship stop time
        :param start_time: Relationship start time
        :param description: Relationship description
        :param source_id: ID of source in string
        :param relationship_type: Relationship type in string
        :param target_id: ID of target in string
        :return: Relationship STIX2 object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_id, target_id
            ),
            relationship_type=relationship_type,
            description=description,
            start_time=start_time,
            stop_time=stop_time,
            source_ref=source_id,
            target_ref=target_id,
            created_by_ref=self.author["id"],
            object_marking_refs=[self.tlp_marking.id],
        )
        return relationship

    def create_obs(self, entity) -> dict:
        """
        Create observable.
        :param entity: observable entity
        :return: Stix object for IPV4, IPV6, Domain, File or URL
        """
        indicator_type = self.determine_indicator_type(entity)
        if indicator_type == "IPv6-Addr":
            value = get_obs_value(self.helper, entity)
            return stix2.IPv6Address(
                value=value,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
        elif indicator_type == "IPv4-Addr":
            value = get_obs_value(self.helper, entity)
            return stix2.IPv4Address(
                value=value,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
        elif indicator_type == "Domain-Name":
            value = get_obs_value(self.helper, entity)
            return stix2.DomainName(
                value=value,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
        elif indicator_type == "Url":
            value = get_obs_value(self.helper, entity)
            return stix2.URL(
                value=value,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                    "x_opencti_labels": self.get_url_content(entity.get("contents", []))
                    + self.get_url_industry(entity.get("industries", []))
                    + self.get_url_business(entity.get("businesses", [])),
                },
            )

        elif indicator_type == "File":
            metadata = entity.get("metadata")
            if metadata:
                hashes = entity.get("metadata", {}).get("hashes")
                file_size = metadata.get("size")
                mime_type = metadata.get("mime_type")
            else:
                hashes = entity.get("observables", [{}])[0].get("hashes")
                file_size = None
                mime_type = None
            if "1KHASH" in hashes:
                hashes.pop("1KHASH", None)
            file_hash = get_hash_name(hashes)
            return stix2.File(
                hashes=hashes,
                name=entity.get("names")[0] if entity.get("names") else file_hash,
                ctime=entity.get("modified"),
                mtime=entity.get("modified"),
                size=file_size,
                mime_type=mime_type,
                object_marking_refs=[self.tlp_marking.id],
                custom_properties={
                    "x_opencti_created_by_ref": self.author["id"],
                },
            )
        else:
            self.helper.connector_logger.error(
                "This observable value is not a valid IPv4 or IPv6 address nor DomainName: ",
                {"entity": entity},
            )

    @staticmethod
    def get_url_content(contents: list) -> list:
        """
        Get content info from url data
        :param contents: contents from URL
        :return: Readable content list for URL
        """
        content_translate = []
        for content in contents:
            for cont in content.get("contents", []):
                content_translate.append(CONTENT_TYPE.get(cont))
        return content_translate

    @staticmethod
    def get_url_industry(industries: list) -> list:
        """
        Get industry info from url data
        :param industries: industries from URL
        :return: Readable industry list for URL
        """
        industry_translate = []
        for industry in industries:
            for indus in industry.get("industries", []):
                industry_translate.append(INDUSTRY_OBJ.get(indus))
        return industry_translate

    @staticmethod
    def get_url_business(businesses: list) -> list:
        """
        Get industry info from url data
        :param businesses: businesses from URL
        :return: Readable business list for URL
        """
        business_translate = []
        for business in businesses:
            for bus in business.get("businesses", []):
                business_translate.append(BUSINESS_TYPE.get(bus))
        return business_translate

    def create_location(self, locations):
        """
        Create Location object for IP
        :param locations: locations from IP data
        :return: list of stix2 location objects
        """
        location_object = []
        for location in locations:
            name, location_type = self.obtain_location_name(location)
            if not name or not location_type:
                continue
            location_object.append(
                stix2.Location(
                    id=Location.generate_id(name, location_type),
                    name=name,
                    latitude=location.get("latitude") or None,
                    longitude=location.get("longitude") or None,
                    region=location.get("region") or None,
                    country=location.get("country") or None,
                    city=location.get("city") or None,
                    street_address=location.get("street_address") or None,
                    postal_code=location.get("postal_code"),
                    object_marking_refs=[self.tlp_marking.id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                    },
                )
            )
        return location_object

    @staticmethod
    def obtain_location_name(location) -> tuple:
        """
        Obtain name and location type from location object. They are used to generate location id.
        :param location: one location object from IP data
        :return: location name and corresponding location type
        """
        name = ""
        location_type = ""
        if location.get("street_address"):
            name = location.get("street_address")
            location_type = "Position"
        elif location.get("city"):
            name = location.get("city")
            location_type = "City"
        elif location.get("region"):
            name = location.get("region")
            location_type = "Administrative-Area"
        elif location.get("country"):
            name = location.get("country")
            location_type = "Country"
        return name, location_type

    def create_autonomous_system(self, autonomous: list) -> list:
        """
        Create AutonomousSystem for IP
        :param autonomous: AutonomousSystem from IP data
        :return: list of stix2 AutonomousSystem objects
        """
        autonomous_object = []
        for asn in autonomous:
            description = []
            if asn.get("country_code"):
                description.append(
                    f"is registered with the code {asn.get('country_code')}"
                )
            if asn.get("registered"):
                description.append(f"is registered on {asn.get('registered')[0]}")
            if asn.get("first_seen"):
                description.append(f"first observed on {asn.get('first_seen')}")
            if asn.get("last_seen"):
                description.append(f"last seen on {asn.get('last_seen')}")
            if description:
                description = "This Autonomous System " + ", ".join(description) + "."
            else:
                description = (
                    "No detailed information available for this Autonomous System."
                )
            autonomous_object.append(
                stix2.AutonomousSystem(
                    number=int(asn.get("number").replace("AS", "")),
                    name=asn.get("name"),
                    rir=asn.get("rir"),
                    object_marking_refs=[self.tlp_marking.id],
                    custom_properties={
                        "x_opencti_created_by_ref": self.author["id"],
                        "x_opencti_description": description,
                        "last_seen": asn.get("last_seen"),
                    },
                )
            )
        return autonomous_object

    def determine_indicator_type(self, entity):
        """
        Used to determine indicator type.
        :param entity: entire object
        :return: string of indicator type
        """
        if entity.get("observables"):
            obs = entity.get("observables", [{}])[0]
            if obs.get("address"):
                return OBSERVABLE_TYPES.get(
                    entity.get("observables", [{}])[0].get("address").get("type")
                )
            else:
                return OBSERVABLE_TYPES.get(obs.get("type"))
        elif entity.get("object", {}).get("type"):
            return OBSERVABLE_TYPES.get(entity.get("object", {}).get("type"))
        elif entity.get("type") == "sample":
            return "File"
        else:
            self.helper.connector_logger.error(
                "[CONNECTOR] determine_indicator_type error...",
                entity,
            )
            return None

    @staticmethod
    def create_ext_references(ext_refs) -> list:
        """
        Used to create external references for File observables.
        :param ext_refs: external refs from File data
        :return: list of stix2.1 external ref objects
        """
        ref_objects = []
        for ext_ref in ext_refs:
            ref_objects.append(
                stix2.ExternalReference(
                    source_name=ext_ref.get("source_name"), url=ext_ref.get("url")
                )
            )
        return ref_objects

    @staticmethod
    def calculate_score(threat_level: int, confidence: int) -> int:
        """
        Used to calculate OpenCTI score for indicators. Base formula: threat_level * 20 * （confidence/100）
        :param: threat_level and confidence from indicator
        :return: score
        """
        if not threat_level or not confidence:
            return 50
        return int(threat_level * 20 * (confidence / 100))

    @staticmethod
    def construct_file_pattern(hashes: dict) -> str:
        """
        Used to construct file pattern from ioc entity hashes
        :param: hashes
        :return: file pattern str
        """
        pattern = []
        for hash_algo, file_hash in hashes.items():
            hash_type = HASH_ALGORITHMS.get(hash_algo)
            if hash_type:
                condition = f"file:hashes.'{hash_type}' = '{file_hash}'"
                pattern.append(condition)
        return "[" + " OR ".join(pattern) + "]"

    def create_indicator(self, entity):
        """
        Create a stix2 indicator.
        :param entity: indicator data object
        :return: stix2 indicator
        """
        # IOC package create indicators
        indicator_type = self.determine_indicator_type(entity)
        name = get_obs_value(self.helper, entity)
        tags = []
        for tag in entity.get("tags", []):
            tag_type = tag.get("tag_type")
            tag_values = tag.get("tag_values")
            if tag_values and tag_type:
                if tag_type == "direction":
                    for t in tag_values:
                        tags.append(f"{tag_type}: {t}")
                else:
                    tags.append(f"{tag_type}: {', '.join(tag_values)}")
        try:
            return stix2.Indicator(
                id=Indicator.generate_id(entity.get("pattern")),
                name=name,
                pattern=entity.get("pattern"),
                pattern_type="stix",
                valid_from=entity.get("modified"),
                valid_until=entity.get("valid_until"),
                confidence=entity.get("confidence"),
                revoked=bool(entity.get("revoked")),
                labels=tags,
                created_by_ref=self.author["id"],
                indicator_types=[
                    THREAT_TYPE.get(i) for i in entity.get("threat_types")
                ],
                object_marking_refs=[self.tlp_marking.id],
                custom_properties=dict(
                    x_opencti_score=self.calculate_score(
                        entity.get("threat_level"), entity.get("confidence")
                    ),
                    x_opencti_main_observable_type=indicator_type,
                    x_opencti_detection=True,
                ),
            )
        except Exception:
            return None
