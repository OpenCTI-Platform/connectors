from abc import ABC, abstractmethod

import pycti
import stix2
from pycti import (
    STIX_EXT_OCTI_SCO,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
    StixCoreRelationship,
)
from settings import SILENTPUSH_SIGNATURE
from stix2 import (
    Artifact,
    ExternalReference,
    File,
    HTTPRequestExt,
    Relationship,
    X509Certificate,
)
from stix2.v20.vocab import INDUSTRY_SECTOR_TECHNOLOGY


class Enricher(ABC):
    """
    Base class for all enrichment classes

    :param helper: the OpenCTIConnectorHelper instance
    :param stix_entity: the dictionary stix entity data
    """

    _helper: OpenCTIConnectorHelper = None
    _stix_objects = list()
    _stix_entity: dict = None
    _response = None
    _enriched_data = None
    _observed_data_refs = list()
    _author = None

    @abstractmethod
    def enrich(self) -> list:
        raise NotImplementedError(
            f"`{__class__.__name__}.enrich` method not implemented"
        )

    def __init__(self, helper, stix_entity):
        self._helper = helper
        self._stix_entity = stix_entity
        self._stix_objects = list()
        self._observed_data_refs = list()
        self._helper.log_debug(f"init _stix_objects: {self._stix_objects}")
        self.__set_author()
        OpenCTIStix2.put_attribute_in_extension(
            self._stix_entity,
            STIX_EXT_OCTI_SCO,
            "external_references",
            {
                "source_name": SILENTPUSH_SIGNATURE,
                "url": "https://api.silentpush.com",
                "description": f"Observable enriched by {SILENTPUSH_SIGNATURE}",
            },
            True,
        )
        self._helper.log_debug(f"self._stix_entity: {self._stix_entity}")

    def __set_author(self):
        """
        Adds Silent Push as author in the stix bundle including references to our app and home page
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
        self._author = stix2.Identity(
            id=pycti.Identity.generate_id(SILENTPUSH_SIGNATURE, "organization"),
            type="identity",
            name=SILENTPUSH_SIGNATURE,
            description=f"""
                {SILENTPUSH_SIGNATURE} takes a unique approach to identifying developing cyber threats by creating Indicators of Future Attacks (IOFA)
                that are more useful, and more valuable than industry-standard IOCs. We apply unique behavioral fingerprints to attacker
                activity and search across our proprietary DNS database.\n
                "We know first"
                """,
            identity_class="organization",
            sectors=[
                INDUSTRY_SECTOR_TECHNOLOGY,
            ],
            contact_information="help@silentpush.com",
            external_references=external_references,
        )
        self._stix_objects.append(self._author)
        self._helper.log_debug(f"author _stix_objects: {self._stix_objects}")

    def _build_certificates(self, source):
        """
        Adds certificates enrichment data to the stix bundle

        :param source: the IP or Domain to be added as relationship
        """
        from datetime import datetime

        certificates = (self._enriched_data.get("scan_data", {}) or {}).get(
            "certificates", []
        ) or []
        self._helper.log_debug(f"certificates: {certificates}")
        for _certificate in certificates:
            self._helper.log_debug(
                f"building certificate '{_certificate.get('serial_number')}'"
            )
            if not _certificate.get("serial_number"):
                continue
            certificate = X509Certificate(
                type="x509-certificate",
                hashes={"SHA-1": _certificate.get("fingerprint_sha1")},
                serial_number=_certificate.get("serial_number"),
                signature_algorithm="sha1",
                issuer=_certificate.get("issuer_organization"),
                validity_not_before=datetime.fromisoformat(
                    _certificate.get("not_before")
                ),
                validity_not_after=datetime.fromisoformat(
                    _certificate.get("not_after")
                ),
            )
            self._stix_objects.append(certificate)
            relationship = Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", source.value, certificate.id
                ),
                relationship_type="related-to",
                target_ref=certificate.id,
                description="Certificate",
                source_ref=source.id,
                created_by_ref=self._author["id"],
            )
            self._stix_objects.append(relationship)
        self._helper.log_debug(f"certs _stix_objects: {self._stix_objects}")

    def _build_favicon(self, source):
        """
        Adds favicon enrichment data to the stix bundle

        :param source: the IP or Domain to be added as relationship
        """
        _favicon = (self._enriched_data.get("scan_data", {}) or {}).get(
            "favicon", []
        ) or []
        if not _favicon:
            return {}
        try:
            for k, v in _favicon[0].items():
                if k.startswith("favicon") and v:
                    favicon = File(
                        type="file",
                        name=f"{k}: {v}",
                        # created_by_ref=self._author["id"],
                        # can't use MD5, validation fails
                        # hashes={"MD5": v}
                    )
                    self._stix_objects.append(favicon)
                    relationship = Relationship(
                        id=StixCoreRelationship.generate_id(
                            "related-to", source.value, favicon.id
                        ),
                        relationship_type="related-to",
                        target_ref=favicon.id,
                        description="Favicon",
                        source_ref=source.id,
                        allow_custom=True,
                        created_by_ref=self._author["id"],
                    )
                    self._stix_objects.append(relationship)
        except (IndexError, AttributeError) as e:
            self._helper.log_warning(f"build favicon error {e}")
            return {}
        self._helper.log_debug(f"favicon _stix_objects: {self._stix_objects}")

    def _build_html_and_headers(self, scan_data):
        """
        Adds HTML and Headers enrichment data to the stix bundle

        :param scan_data: the scan_data enrichment dictionary
        """
        if not scan_data:
            return {}
        _headers = scan_data.get("headers", [])
        _html = scan_data.get("html", [])
        self._helper.log_debug(f"_html: {_html}")
        try:
            if not _html or not _headers or not _html[0].get("html_body_ssdeep"):
                return {}
            self._helper.log_debug("building html")
            html_body = Artifact(
                type="artifact",
                url="/",
                mime_type=_html[0].get("content-type"),
                hashes={"SSDEEP": _html[0].get("html_body_ssdeep")},
            )
            return HTTPRequestExt(
                request_method="OPTIONS",
                request_value="/",
                request_header=_headers[0].get("headers"),
                message_body_length=_html[0].get("content-length"),
                message_body_data_ref=html_body,
            )
        except (IndexError, AttributeError) as e:
            self._helper.log_warning(f"build html error {e}")
            return {}

    def _build_extensions(self):
        """
        Builds a http-request-ext extension to be used by the Domain or IP object
        """

        html_and_headers = self._build_html_and_headers(
            self._enriched_data.get("scan_data")
        )
        http_request_ext = (
            {"http-request-ext": html_and_headers} if html_and_headers else {}
        )
        extra_args = {"extensions": {**http_request_ext}} if http_request_ext else {}
        self._helper.log_debug(f"extra args: {extra_args}")
        return extra_args

    def _build_flags(self):
        """
        Adds Silent Push flags as labels to the stix entity
        """

        flags = self._extract_flags()
        for name, value in flags.items():
            _value, color = value
            self._helper.log_debug(f"name, value: {name, _value}")
            if not _value:
                self._helper.log_debug(f"skipping flag {name}")
                continue
            self._helper.log_debug(f"building flag {name}")
            label = self._helper.api.label.read_or_create_unchecked(
                value=name, color=color
            )
            OpenCTIStix2.put_attribute_in_extension(
                self._stix_entity,
                STIX_EXT_OCTI_SCO,
                "labels",
                label["value"],
                True,
            )

    def _score(self):
        """
        Add Silent Push risk score to the stix entity
        """

        OpenCTIStix2.put_attribute_in_extension(
            self._stix_entity,
            STIX_EXT_OCTI_SCO,
            "score",
            self._enriched_data.get("sp_risk_score"),
        )

    def process(self):
        self.enrich()
        self._score()
        return self._stix_objects
