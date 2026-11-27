from datetime import datetime

from connectors_sdk.models import (
    URL,
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
from stix2.exceptions import InvalidValueError


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
        self.webscan_data = list()
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
        if not self.webscan_data:
            return
        for webscan_data in self.webscan_data:
            ssl_data = {k: v for k, v in webscan_data.items() if k.startswith("ssl.")}
            self.helper.connector_logger.debug(f"ssl_data '{ssl_data}'")
            serial_number = ssl_data.get("ssl.serial_number")
            if not serial_number:
                continue
            self.helper.connector_logger.debug(
                f"building certificate '{serial_number}'"
            )
            raw_hash = ssl_data.get("ssl.SHA1")
            normalized_hash = (
                raw_hash.replace(":", "").replace(" ", "").strip().lower()
                if raw_hash is not None
                else None
            )
            not_before = ssl_data.get("ssl.not_before")
            not_after = ssl_data.get("ssl.not_after")
            try:
                certificate = X509Certificate(
                    hashes=(
                         {HashAlgorithm.SHA1: normalized_hash}
                         if normalized_hash
                         else None
                    ),
                    serial_number=serial_number,
                    signature_algorithm="sha1",
                    issuer=ssl_data.get("ssl.issuer.organization"),
                    validity_not_before=(
                         datetime.fromisoformat(not_before)
                         if not_before is not None
                         else None
                     ),
                    validity_not_after=(
                         datetime.fromisoformat(not_after)
                         if not_after is not None
                         else None
                     ),
                )
            except (InvalidValueError, ValueError, TypeError, AttributeError) as err:
                self.helper.connector_logger.warning(
                     "Skipping invalid certificate",
                     meta={"serial_number": serial_number, "error": str(err)},
                )
                continue
            self.add_target_and_relationship(
                certificate, RelationshipType.RELATED_TO, "Certificate"
            )

    def build_favicon(self) -> None:
        """
        Add favicon enrichment data to the octi bundle
        """

        for webscan_data in self.webscan_data:
            if not webscan_data.get("favicon_md5"):
                continue
            favicon_file = File(
                name="favicon",
                hashes={HashAlgorithm.MD5: webscan_data.get("favicon_md5")},
            )
            for favicon_url_path in webscan_data.get("favicon_urls", []) or []:
                if not favicon_url_path:
                    continue
                favicon_url = URL(value=favicon_url_path)
                self.add_target_and_relationship(
                    favicon_url,
                    RelationshipType.RELATED_TO,
                    "Favicon URLs",
                    favicon_file,
                )
            self.add_target_and_relationship(
                favicon_file, RelationshipType.RELATED_TO, "Favicon"
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
