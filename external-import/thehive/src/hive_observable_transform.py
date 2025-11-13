import pycti
from pycti import CustomObservableText, CustomObservableUserAgent
from stix2 import (
    URL,
    AutonomousSystem,
    DomainName,
    EmailAddress,
    EmailMessage,
    File,
    Identity,
    IPv4Address,
    IPv6Address,
    Vulnerability,
    WindowsRegistryKey,
)

from utils import check_hash_type, is_ipv4, is_ipv6  # isort: skip


class UnsupportedIndicatorTypeError(Exception):
    """Exception raised for unsupported indicator types."""

    def __init__(self, indicator_type):
        self.indicator_type = indicator_type
        super().__init__(f"Unsupported indicator type: {self.indicator_type}")


class HiveObservableTransform:
    """Class to support the transformation of Hive Observables to STIX observables."""

    def __init__(self, observable, markings, created_by_ref):
        self.markings = markings
        self.created_by_ref = created_by_ref
        self.observable = observable
        self.data_type = None

        self.data_type = self.standardize_data_type()
        self.stix_observable = self.create_stix_observable()

    def standardize_data_type(self):
        """Standardize a set of observables like hash, file, and ip."""
        data_type = None
        if self.observable.get("dataType") in ["hash"]:
            data_type = f'file_{check_hash_type(self.observable.get("data")).replace("-","").lower()}'
        if self.observable.get("dataType") in ["ip", "ipv4"] and is_ipv4(
            self.observable.get("data")
        ):
            data_type = "ipv4"
        if self.observable.get("dataType") in ["ip", "ipv6"] and is_ipv6(
            self.observable.get("data")
        ):
            data_type = "ipv6"
        if data_type is None:
            data_type = self.observable.get("dataType")
        return data_type

    def create_custom_properties(self, default_desc="Imported from TheHive"):
        """Create standard custom properties as it's repeated."""
        return {
            "description": self.observable.get("message", default_desc),
            "labels": self.observable.get("tags"),
            "x_opencti_score": 80 if self.observable.get("ioc") else 50,
            "created_by_ref": self.created_by_ref,
            "x_opencti_create_indicator": self.observable.get("ioc"),
        }

    def create_stix_observable(self):
        """Create stix observable if it exists in the provided map, if not, return the default observable."""
        data_type_to_observable_map = {
            "autonomous-system": self.create_autonomous_system,
            "cve": self.create_vulnerability,
            "fqdn": self.create_domain_name,
            "domain": self.create_domain_name,
            "email_address": self.create_email_address,
            "hash": self.create_file_hash,
            "file": self.create_file,
            "file_md5": self.create_file_hash,
            "file_sha1": self.create_file_hash,
            "file_sha256": self.create_file_hash,
            "filename": self.create_filename,
            "risk_object_identity": self.create_identity,
            "identity": self.create_identity,
            "ipv4": self.create_ipv4_address,
            "ipv6": self.create_ipv6_address,
            "mail": self.create_email_address,
            "mail_subject": self.create_email_message_subject,
            "email_subject": self.create_email_message_subject,
            "mail-subject": self.create_email_message_subject,
            "supplier": self.create_organization,
            "vendor": self.create_organization,
            "organisation": self.create_organization,
            "organization": self.create_organization,
            "other": self.create_custom_observable_text,
            "regexp": self.create_custom_observable_text,
            "registry": self.create_registry,
            "registry_key": self.create_registry,
            "risk_object_asset": self.create_identity_system,
            "asset": self.create_identity_system,
            "system": self.create_identity_system,
            "hostname": self.create_identity_system,
            "uri_path": self.create_url,
            "url": self.create_url,
            "user-agent": self.create_custom_observable_user_agent,
            "user_agent": self.create_custom_observable_user_agent,
        }

        # Return the results from the function in the MAP, if it's not in the MAP return the default_observable
        return data_type_to_observable_map.get(
            self.data_type, self.default_observable
        )()

    def create_autonomous_system(self):
        return AutonomousSystem(
            number=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_vulnerability(self):
        return Vulnerability(
            id=pycti.Vulnerability.generate_id(self.observable.get("data")),
            type="vulnerability",
            name=self.observable.get("data").lower(),
            object_marking_refs=self.markings,
            custom_properties={
                "description": self.observable.get("message"),
                "labels": self.observable.get("tags"),
                "created_by_ref": self.created_by_ref,
            },
        )

    def create_domain_name(self):
        return DomainName(
            value=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_email_address(self):
        return EmailAddress(
            type="email-addr",
            value=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_file_hash(self):
        hash_type = check_hash_type(self.observable.get("data"))
        return File(
            hashes={hash_type: self.observable.get("data")},
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_file(self):
        _hash = self.observable.get("attachment", {}).get("hashes", [""])[0]
        hash_type = check_hash_type(_hash)
        return File(
            hashes={hash_type: _hash},
            object_marking_refs=self.markings,
            name=self.observable.get("attachment", {}).get("names"),
            custom_properties=self.create_custom_properties(),
        )

    def create_filename(self):
        return File(
            name=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_identity(self):
        return Identity(
            id=pycti.Identity.generate_id(self.observable.get("data"), "individual"),
            type="identity",
            name=self.observable.get("data").lower(),
            object_marking_refs=self.markings,
            identity_class="individual",
            custom_properties={
                "description": (
                    self.observable.get("message")
                    if self.observable.get("message")
                    else "Imported from TheHive"
                ),
                "labels": self.observable.get("tags"),
                "created_by_ref": self.created_by_ref,
            },
        )

    def create_identity_system(self):
        return Identity(
            id=pycti.Identity.generate_id(self.observable.get("data"), "system"),
            type="identity",
            name=self.observable.get("data").lower(),
            object_marking_refs=self.markings,
            identity_class="system",
            custom_properties={
                "description": (
                    self.observable.get("message")
                    if self.observable.get("message")
                    else "Imported from TheHive"
                ),
                "labels": self.observable.get("tags"),
                "created_by_ref": self.created_by_ref,
            },
        )

    def create_ipv4_address(self):
        return IPv4Address(
            value=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_ipv6_address(self):
        return IPv6Address(
            value=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_email_message(self):
        return EmailMessage(
            body=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_email_message_subject(self):
        return EmailMessage(
            type="email-message",
            is_multipart=False,
            subject=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_organization(self):
        return Identity(
            id=pycti.Identity.generate_id(
                self.observable.get("data").title(), "organization"
            ),
            type="identity",
            name=self.observable.get("data").title(),
            object_marking_refs=self.markings,
            identity_class="organization",
            custom_properties={
                "description": (
                    self.observable.get("message")
                    if self.observable.get("message")
                    else "Imported from TheHive"
                ),
                "labels": self.observable.get("tags"),
                "created_by_ref": self.created_by_ref,
            },
        )

    def create_custom_observable_text(self):
        return CustomObservableText(
            value=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_custom_observable_user_agent(self):
        return CustomObservableUserAgent(
            value=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_registry(self):
        return WindowsRegistryKey(
            key=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_url(self):
        return URL(
            value=self.observable.get("data"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def default_observable(self):
        raise UnsupportedIndicatorTypeError(self.data_type)
