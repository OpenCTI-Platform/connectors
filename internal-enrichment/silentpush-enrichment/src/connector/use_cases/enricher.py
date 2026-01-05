from datetime import datetime

from connectors_sdk.models import (
    BaseIdentifiedEntity,
    BaseObservableEntity,
    ExternalReference,
    File,
    OrganizationAuthor,
    Relationship,
    X509Certificate,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType
from pycti import OpenCTIConnectorHelper
from silentpush_client import SilentpushClient


class Enricher:
    """
    Parent class for all enrichers
    """

    API_TYPE = None  # e.g. "ipv4", "ipv6" or "domain"
    OCTI_CLASS = None  # e.g. IPV4Address, IPV6Address or DomainName

    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        client: SilentpushClient,
        stix_entity: dict,
    ):
        """
        Initialize the Enricher

        :param helper: The OpenCTI connector helper
        :param stix_entity: The STIX entity to be enriched
        """
        self.helper = helper
        self.stix_entity = stix_entity
        self.octi_observables = []
        self.client = client
        self.enriched_data = dict()
        self.source = None
        self.helper.connector_logger.debug(f"init stix_entity: {self.stix_entity}")

    def build_author(self) -> OrganizationAuthor:
        """
        Return Silent Push as author.
        """
        external_references = [
            ExternalReference(
                source_name="Home Page",
                url="https://www.silentpush.com/",
                description="""
                    Our home page and blog latest news.\n
                    Sign up today!
                """,
            ),
            ExternalReference(
                source_name="Community Free Edition",
                url="https://explore.silentpush.com/",
                description="""
                    Our Community free edition app.\n
                    Sign up today!
                """,
            ),
            ExternalReference(
                source_name="Enterprise Edition",
                url="https://app.silentpush.com/",
                description="""
                    Our Enterprise edition app.\n
                    Sign up today!
                """,
            ),
        ]
        author = OrganizationAuthor(
            name="Silent Push",
            external_references=external_references,
            description="""
                Silent Push takes a unique approach to identifying developing cyber threats by creating Indicators of Future Attacks (IOFA)
                that are more useful, and more valuable than industry-standard IOCs. We apply unique behavioral fingerprints to attacker
                activity and search across our proprietary DNS database.\n
                "We know first"
                """,
            contact_information="help@silentpush.com",
        )
        return author

    def create_relationship(
        self,
        relationship_type: str,
        target: BaseIdentifiedEntity,
        description: str,
        source: BaseObservableEntity | None = None,
    ) -> Relationship:
        """
        Create Relationship object
        :param relationship_type: Relationship type in string
        :param target: Target OpenCTI object
        :param description: Description of the relationship
        :param source: Source OpenCTI object
        :return: Relationship OpenCTI object
        """
        if not source:
            source = self.source
        relationship = Relationship(
            type=relationship_type,
            source=source,
            target=target,
            description=description,
        )
        return relationship

    def add_target_and_relationship(
        self,
        target: BaseIdentifiedEntity,
        relationship_type: str,
        description: str,
        source: BaseObservableEntity | None = None,
    ) -> None:
        """
        Add target object and relationship to the octi bundle
        :param target: Target OpenCTI object
        :param relationship_type: Relationship type in string
        :param description: Description of the relationship
        :param source: Source OpenCTI object
        """
        self.octi_observables.append(target)
        relationship = self.create_relationship(
            relationship_type=relationship_type,
            target=target,
            description=description,
            source=source,
        )
        self.octi_observables.append(relationship)

    def build_certificates(self) -> None:
        """
        Add certificates enrichment data to the octi bundle
        """
        certificates = self.enriched_data.get("scan_data", {}).get("certificates")
        if not certificates:
            return
        for certificate in certificates:
            serial_number = certificate.get("serial_number")
            if not serial_number:
                continue
            self.helper.connector_logger.debug(
                f"building certificate '{serial_number}'"
            )
            certificate = X509Certificate(
                hashes={HashAlgorithm.SHA1: certificate.get("fingerprint_sha1")},
                serial_number=serial_number,
                signature_algorithm="sha1",
                issuer=certificate.get("issuer_organization"),
                validity_not_before=datetime.fromisoformat(
                    certificate.get("not_before")
                ),
                validity_not_after=datetime.fromisoformat(certificate.get("not_after")),
            )
            self.add_target_and_relationship(
                certificate, RelationshipType.RELATED_TO, "Certificate"
            )

    def build_favicon(self) -> None:
        """
        Add favicon enrichment data to the octi bundle
        """
        favicon = self.enriched_data.get("scan_data", {}).get("favicon")
        if not favicon:
            return
        for k, v in favicon[0].items():
            if k.startswith("favicon") and v:
                favicon = File(name=f"{k}: {v}", hashes={HashAlgorithm.MD5: v})
                self.add_target_and_relationship(
                    favicon, RelationshipType.RELATED_TO, "Favicon"
                )

    def extract_labels(self) -> dict:
        """
        Extract labels from the json response.
        """
        raise NotImplementedError(
            f"`{__class__.__name__}.extract_labels` method not implemented"
        )

    def build_labels(self) -> None:
        """
        Add Silent Push flags as labels to the octi entity
        """
        labels = self.extract_labels()
        if not self.source.labels:
            self.source.labels = []
        for name, _tuple in labels.items():
            value, color = _tuple
            if not value:
                self.helper.connector_logger.debug(f"skipping label {name}")
                continue
            self.helper.connector_logger.debug(f"building label {name}")
            label = self.helper.api.label.read_or_create_unchecked(
                value=name, color=color
            )
            self.source.labels.append(label["value"])

    def enrich(self) -> None:
        """
        Enrich the IOC
        """
        raise NotImplementedError(
            f"`{__class__.__name__}.enrich` method not implemented"
        )

    def set_author_to_octi_observables(self) -> None:
        """
        Sets the author to all stix objects
        """
        author = self.build_author()
        for stix_object in self.octi_observables:
            stix_object.author = author
        self.octi_observables.append(author)

    def process(self) -> list:
        """
        Process the enrichment and returns the enriched STIX objects

        :return: the stix objects list
        """
        self.enrich()
        self.set_author_to_octi_observables()
        return self.octi_observables
