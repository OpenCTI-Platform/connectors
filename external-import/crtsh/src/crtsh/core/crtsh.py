# crt_sh/api.py
import requests
from pycti import StixCoreRelationship
from stix2 import (
    Identity,
    DomainName,
    EmailAddress,
    Relationship,
    X509Certificate,
    X509V3ExtensionsType,
)
from stix2.exceptions import AtLeastOnePropertyError
from validators import ValidationError
from validators import domain as domain_validator
from validators import email as email_validator

from .crtsh_utils import (
    TLP_MAP,
    configure_logger,
    convert_to_datetime,
    is_valid_stix_id,
)

LOGGER = configure_logger(__name__)
DEFAULT_URL = "https://crt.sh/?q={search}&output=json"


class CrtSHClient:
    def __init__(
        self,
        domain,
        labels="crtsh",
        marking_refs="TLP:WHITE",
        is_expired=False,
        is_wildcard=False,
    ):
        self.marking_refs = TLP_MAP.get(marking_refs)
        self.labels = labels.split(",")
        self.domain = self._transform_domain(domain, is_wildcard)
        self.url = DEFAULT_URL.format(search=domain)
        if is_expired:
            self.url += "&exclude=expired"
        self._response = self._request_data()
        self.author = Identity(
            name="crtsh",
            description="CRTSH external import connector",
            identity_class="organization",
        )

    def _transform_domain(self, domain, is_wildcard):
        try:
            if domain_validator(domain):
                if is_wildcard:
                    return f"%.{domain}"
                else:
                    return domain
            else:
                raise ValueError(f"Domain provided failed validation: {domain}")
        except ValidationError as e:
            LOGGER.error(f"Domain provided failed validation: {domain}:\n{e}")
            raise ValueError(f"Domain provided failed validation: {domain}")
        except Exception as e:
            LOGGER.error(f"Domain provided failed validation: {domain}:\n{e}")
            raise ValueError(f"Invalid domain ({domain}): {e}")

    def _request_data(self):
        """Internal method to handle API requests."""
        try:
            LOGGER.info(f"Requesting data from: {self.url}")
            response = requests.get(
                url=self.url,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            LOGGER.error(f"Error while fetching data from {self.url}: {str(e)}")
            return None

    def get_response(self):
        """Return the response from the API."""
        return self._response

    def process_certificate(self, item, stix_objects):
        """Return a STIX X509Certificate object."""
        x509_v3_extensions = None
        if hasattr(item, "name_value") and item.get("name_value"):
            x509_v3_extensions = X509V3ExtensionsType(
                subject_alternative_name=item.get("name_value"),
            )
        try:
            cert = X509Certificate(
                type="x509-certificate",
                issuer=item.get("issuer_name"),
                validity_not_before=convert_to_datetime(item.get("not_before")),
                validity_not_after=convert_to_datetime(item.get("not_after")),
                subject=item.get("common_name"),
                serial_number=item.get("serial_number"),
                object_marking_refs=self.marking_refs,
                x509_v3_extensions=x509_v3_extensions,
                custom_properties={
                    "labels": self.labels,
                    "x_opencti_created_by_ref": self.author.id,
                },
            )
            stix_objects.append(cert)
            return cert.id
        except AtLeastOnePropertyError as e:
            LOGGER.error(f"Failed to process certificate: {e}")
            return None
        except TypeError as e:
            LOGGER.error(f"Failed to process certificate: {e}")
            return None
        except ValueError as e:
            LOGGER.error(f"Failed to process certificate: {e}")
            return None
        except KeyError as e:
            LOGGER.error(f"Failed to process certificate: {e}")
            return None
        except AttributeError as e:
            LOGGER.error(f"Failed to process certificate: {e}")
            return None
        except Exception as e:
            raise ValueError(f"Failed to process certificate: {e}")

    def process_domain_name(self, domain: str):
        """Return a STIX DomainName object."""
        try:
            if domain_validator(domain):
                return DomainName(
                    type="domain-name",
                    value=domain.lower(),
                    object_marking_refs=self.marking_refs,
                    custom_properties={
                        "labels": self.labels,
                        "x_opencti_created_by_ref": self.author.id,
                    },
                )
            elif isinstance(domain, str) and domain.startswith("*."):
                domain = domain[2:]
                return self.process_domain_name(domain)
            else:
                return None
        except ValidationError as e:
            LOGGER.error(f"Domain provided failed validation: {domain}:\n{e}")
            raise ValueError(f"Domain provided failed validation: {domain}")
        except Exception as e:
            LOGGER.error(f"Domain provided failed validation: {domain}:\n{e}")
            raise ValueError(f"Invalid domain ({domain}): {e}")

    def process_name_value(self, item, stix_objects, certificate_id):
        """Return a STIX DomainName object."""
        try:
            if not is_valid_stix_id(certificate_id):
                raise ValueError(f"Invalid STIX ID: {certificate_id}")
            if item.get("name_value") and isinstance(item.get("name_value"), str):
                for name in item.get("name_value").split("\n"):
                    try:
                        if email_validator(name):
                            stix_obj = self.process_email_address(name)
                            stix_objects.append(stix_obj)
                        else:
                            stix_obj = self.process_domain_name(name)
                            stix_objects.append(stix_obj)
                        if hasattr(stix_obj, "id"):
                            relationship = self.stix_relationship(
                                certificate_id, stix_obj.id
                            )
                            if relationship:
                                stix_objects.append(relationship)
                    except ValidationError as e:
                        LOGGER.error(f"Validation error: {name}\n{e}")
                        raise ValueError(f"Validation error: {name}")
                    except Exception as e:
                        LOGGER.error(f"Error for process_name_value: {name}\n{e}")
                        raise ValueError(f"Failed to process name_value ({name}): {e}")
            else:
                LOGGER.error(f"Error for process_name_value: {item}")
        except AttributeError as e:
            LOGGER.error(f"AttributeError for process_name_value: {item}, {e}")
        except TypeError as e:
            LOGGER.error(f"TypeError for process_name_value: {item}, {e}")
        except ValueError as e:
            LOGGER.error(f"ValueError for process_name_value: {item}, {e}")
        except Exception as e:
            LOGGER.info(f"Error process_name_value: {e}")

    def process_email_address(self, email):
        """Return a STIX EmailAddress object."""
        try:
            if email_validator(email):
                return EmailAddress(
                    type="email-addr",
                    value=email.lower(),
                    object_marking_refs=self.marking_refs,
                    custom_properties={
                        "labels": self.labels,
                        "x_opencti_created_by_ref": self.author.id,
                    },
                )
            else:
                return None
        except ValidationError as e:
            LOGGER.error(f"Email Validation Error: {email}\n{e}")
            raise ValueError(f"Email Validation Error: {email}")
        except Exception as e:
            LOGGER.error(f"Error for process_name_value: {email}\n{e}")
            raise ValueError(f"Failed to process name_value ({email}): {e}")

    def process_common_name(self, item, stix_objects, certificate_id):
        """Return a STIX DomainName object."""
        if hasattr(item, "common_name"):
            domain = self.process_domain_name(item.get("common_name"))
            relationship = self.stix_relationship(certificate_id, domain.id)
            if relationship:
                stix_objects.append(relationship)
            stix_objects.append(domain)

    def stix_relationship(self, source_ref, target_ref):
        """Return a STIX Relationship object."""
        if not source_ref or not target_ref:
            return None
        elif source_ref == target_ref:
            return None
        elif len(source_ref) == 0 or len(target_ref) == 0:
            return None
        else:
            return Relationship(
                id=StixCoreRelationship.generate_id(
                    "related-to", source_ref, target_ref
                ),
                relationship_type="related-to",
                source_ref=source_ref,
                target_ref=target_ref,
                object_marking_refs=self.marking_refs,
                created_by_ref=self.author.id,
                custom_properties={
                    "labels": self.labels,
                },
            )

    def get_stix_objects(self):
        """Return a list of STIX objects."""
        stix_objects = []
        for item in self._response:
            LOGGER.debug(f"Processing item: {item}")
            certificate_id = self.process_certificate(item, stix_objects)
            if "common_name" in item:
                LOGGER.debug(f"Processing common_name: {item.get('common_name')}")
                self.process_common_name(item, stix_objects, certificate_id)
            if "name_value" in item:
                LOGGER.debug(f"Processing name_value: {item.get('name_value')}")
                self.process_name_value(item, stix_objects, certificate_id)
        uniq_stix_objects = []
        for item in stix_objects:
            if item not in uniq_stix_objects:
                uniq_stix_objects.append(item)
        return uniq_stix_objects
