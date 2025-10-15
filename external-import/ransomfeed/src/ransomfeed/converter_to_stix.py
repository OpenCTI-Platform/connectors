"""
Converter to STIX
Converts RansomFeed data into STIX 2.1 objects
"""
import stix2
from datetime import datetime
from pycti import Identity, IntrusionSet, Location, Report, StixCoreRelationship


class ConverterToStix:
    """
    Provides methods for converting RansomFeed data into STIX 2.1 objects
    """

    def __init__(self, helper, config):
        """
        Initialize the converter
        
        Args:
            helper: OpenCTI connector helper
            config: Connector configuration
        """
        self.helper = helper
        self.config = config
        self.marking = self._create_tlp_marking(config.tlp_level.lower())
        self.author = self.create_author()

    @staticmethod
    def _create_tlp_marking(level: str):
        """
        Create TLP marking based on level
        
        Args:
            level: TLP level (white, clear, green, amber, red)
            
        Returns:
            STIX TLP marking object
        """
        mapping = {
            "white": stix2.TLP_WHITE,
            "clear": stix2.TLP_WHITE,
            "green": stix2.TLP_GREEN,
            "amber": stix2.TLP_AMBER,
            "red": stix2.TLP_RED,
        }
        return mapping.get(level, stix2.TLP_WHITE)

    def create_author(self) -> dict:
        """
        Create STIX 2.1 Identity object representing the author
        
        Returns:
            Author Identity in STIX 2.1 format
        """
        author = stix2.Identity(
            id=Identity.generate_id(name="RansomFeed", identity_class="organization"),
            name="RansomFeed",
            identity_class="organization",
            type="identity",
            description="RansomFeed - Ransomware Intelligence Platform",
            object_marking_refs=[self.marking.get("id")],
            contact_information=self.config.api_url,
            allow_custom=True,
        )
        return author

    def create_identity(self, name: str, identity_class: str = "organization") -> dict:
        """
        Create a STIX Identity object
        
        Args:
            name: Name of the identity
            identity_class: Class of identity (organization or individual)
            
        Returns:
            STIX Identity object
        """
        identity = stix2.Identity(
            id=Identity.generate_id(name, identity_class),
            name=name,
            identity_class=identity_class,
            type="identity",
            created_by_ref=self.author.get("id"),
            object_marking_refs=[self.marking.get("id")],
        )
        return identity

    def create_intrusion_set(self, name: str, description: str = None) -> dict:
        """
        Create a STIX IntrusionSet object
        
        Args:
            name: Name of the intrusion set (ransomware group)
            description: Optional description
            
        Returns:
            STIX IntrusionSet object
        """
        if not description:
            description = f"Ransomware group: {name}"
            
        intrusion_set = stix2.IntrusionSet(
            id=IntrusionSet.generate_id(name),
            name=name,
            labels=["ransomware"],
            created_by_ref=self.author.get("id"),
            description=description,
            object_marking_refs=[self.marking.get("id")],
        )
        return intrusion_set

    def create_location(self, country_code: str) -> dict:
        """
        Create a STIX Location object for a country
        
        Args:
            country_code: ISO country code
            
        Returns:
            STIX Location object
        """
        location = stix2.Location(
            id=Location.generate_id(country_code, "Country"),
            name=country_code,
            country=country_code,
            type="location",
            created_by_ref=self.author.get("id"),
            object_marking_refs=[self.marking.get("id")],
        )
        return location

    def create_relationship(
        self,
        source_ref: str,
        target_ref: str,
        relationship_type: str,
        start_time: datetime = None,
        created: datetime = None,
    ) -> dict:
        """
        Create a STIX Relationship object
        
        Args:
            source_ref: Source object ID
            target_ref: Target object ID
            relationship_type: Type of relationship
            start_time: Optional start time
            created: Optional created time
            
        Returns:
            STIX Relationship object
        """
        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                relationship_type, source_ref, target_ref, start_time
            ),
            relationship_type=relationship_type,
            source_ref=source_ref,
            target_ref=target_ref,
            start_time=start_time,
            created=created,
            created_by_ref=self.author.get("id"),
            object_marking_refs=[self.marking.get("id")],
        )
        return relationship

    def create_report(
        self,
        name: str,
        description: str,
        published: datetime,
        object_refs: list,
        external_references: list = None,
    ) -> dict:
        """
        Create a STIX Report object
        
        Args:
            name: Name of the report
            description: Description of the report
            published: Published date
            object_refs: List of STIX object IDs referenced in the report
            external_references: Optional list of external references
            
        Returns:
            STIX Report object
        """
        report = stix2.Report(
            id=Report.generate_id(name, published),
            report_types=["threat-report"],
            name=name,
            description=description,
            published=published,
            created_by_ref=self.author.get("id"),
            object_refs=object_refs,
            object_marking_refs=[self.marking.get("id")],
            external_references=external_references if external_references else [],
        )
        return report

    def create_domain(self, domain_name: str) -> dict:
        """
        Create a STIX DomainName object
        
        Args:
            domain_name: Domain name
            
        Returns:
            STIX DomainName object
        """
        domain = stix2.DomainName(
            value=domain_name,
            type="domain-name",
            object_marking_refs=[self.marking.get("id")],
            custom_properties={
                "x_opencti_created_by_ref": self.author.get("id"),
            },
        )
        return domain

    def create_indicator(self, pattern: str, name: str, description: str = None) -> dict:
        """
        Create a STIX Indicator object
        
        Args:
            pattern: STIX pattern
            name: Name of the indicator
            description: Optional description
            
        Returns:
            STIX Indicator object
        """
        indicator = stix2.Indicator(
            name=name,
            description=description if description else name,
            pattern_type="stix",
            pattern=pattern,
            created_by_ref=self.author.get("id"),
            object_marking_refs=[self.marking.get("id")],
        )
        return indicator

