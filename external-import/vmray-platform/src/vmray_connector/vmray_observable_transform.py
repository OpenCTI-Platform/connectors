from pycti import StixCoreRelationship
from stix2 import (
    URL,
    DomainName,
    EmailAddress,
    File,
    IPv4Address,
    IPv6Address,
    Mutex,
    Process,
    Relationship,
    WindowsRegistryKey,
)

from .utils import is_ipv4, is_ipv6


class VMRayObservableTransform:
    """Class to support the transformation of VMRay Observables to STIX observables."""

    def __init__(
        self,
        observable_type,
        observable_value,
        labels,
        created_by_ref,
        score,
        create_indicator=False,
        observable=None,
        description=None,
        markings=None,
    ):
        self.created_by_ref = created_by_ref
        self.observable_type = observable_type
        self.observable_value = observable_value
        self.labels = labels
        self.score = score
        self.create_indicator = create_indicator
        self.observable = observable
        self.description = description
        self.markings = markings or []

        # self.data_type = self.standardize_data_type()
        if self.observable_type == "ip":
            self.observable_type = self.standardize_data_type()
        self.stix_observable = self.create_stix_observable()

    def standardize_data_type(self):
        """Standardize a set of observables like hash, file, and ip."""
        data_type = None

        if self.observable_type in ["ip", "ipv4"] and is_ipv4(self.observable_value):
            data_type = "ipv4"
        if self.observable_type in ["ip", "ipv6"] and is_ipv6(self.observable_value):
            data_type = "ipv6"
        return data_type

    def create_custom_properties(self, default_desc="Imported from VMRay"):
        """Create standard custom properties as it's repeated."""
        desc = self.description if self.description else default_desc
        return {
            "description": desc,
            "labels": self.labels,
            "x_opencti_score": self.score,
            "created_by_ref": self.created_by_ref,
            "x_opencti_create_indicator": self.create_indicator,
        }

    def create_stix_observable(self):
        """
        Create stix observable if it exists in the provided map,
        if not, return the default observable.
        """
        data_type_to_observable_map = {
            "domain": self.create_domain_name,
            "email_address": self.create_email_address,
            "file": self.create_file_by_hashes,
            "ipv4": self.create_ipv4_address,
            "ipv6": self.create_ipv6_address,
            "url": self.create_url,
            "process": self.create_process,
            "mutex": self.create_mutex,
            "registry": self.create_registry,
        }

        # Return the results from the function in the MAP, if it's not in the MAP return the default_observable
        return data_type_to_observable_map.get(self.observable_type)()

    def create_domain_name(self):
        """Create a STIX DomainName observable."""
        return DomainName(
            value=self.observable_value,
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_email_address(self):
        """Create a STIX EmailAddress observable."""
        return EmailAddress(
            value=self.observable_value,
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_file_by_hashes(self):
        """Create a STIX File observable using provided hashes."""
        return File(
            hashes=self.observable.get("hashes", {}),
            name=self.observable.get("filename", ""),
            size=self.observable.get("size"),
            mime_type=self.observable.get("mime_type"),
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_ipv4_address(self):
        """Create a STIX IPv4Address observable."""
        return IPv4Address(
            value=self.observable_value,
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_ipv6_address(self):
        """Create a STIX IPv6Address observable."""
        return IPv6Address(
            value=self.observable_value,
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_registry(self):
        """Create a STIX WindowsRegistryKey observable."""
        return WindowsRegistryKey(
            key=self.observable_value,
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_url(self):
        """Create a STIX URL observable."""
        return URL(
            value=self.observable_value,
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_process(self):
        """Create a STIX Process observable."""
        return Process(
            command_line=self.observable_value,
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_mutex(self):
        """Create a STIX Mutex observable."""
        return Mutex(
            name=self.observable_value,
            object_marking_refs=self.markings,
            custom_properties=self.create_custom_properties(),
        )

    def create_relationship(
        self,
        src_id,
        tgt_id,
        markings,
        rel_type="related-to",
        description="Imported from VMRay",
    ):
        """Create a STIX Relationship between two STIX objects."""
        return Relationship(
            id=StixCoreRelationship.generate_id(
                rel_type,
                src_id,
                tgt_id,
            ),
            relationship_type=rel_type,
            created_by_ref=self.created_by_ref,
            source_ref=src_id,
            target_ref=tgt_id,
            description=description,
            object_marking_refs=markings,
            allow_custom=True,
        )
