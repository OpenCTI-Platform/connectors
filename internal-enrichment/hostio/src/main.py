from os import environ

from stix2 import Note

from hostio import HostIODomain, HostIOIPtoDomain, IPInfo
from hostio.hostio_utils import (
    can_be_int,
    format_labels,
    get_tlp_marking,
    is_ipv4,
    is_ipv6,
    is_valid_token,
    validate_labels,
    validate_tlp_marking,
)
from lib.internal_enrichment import InternalEnrichmentConnector


class HostIOConnector(InternalEnrichmentConnector):
    def __init__(self):
        """Initialization of the connector"""
        super().__init__()
        self._get_config_variables()

    def _get_config_variables(self):
        """Get config variables from the environment"""
        # Get HOSTIO_TOKEN environment variable and validate it is valid.
        self.hostio_token = environ.get("HOSTIO_TOKEN", None)
        if not is_valid_token(self.hostio_token):
            msg = "Error when grabbing HOSTIO_TOKEN environment variable. It SHOULD be a valid hostio token."
            self.helper.log_error(msg)
            raise ValueError(msg)
        # Get HOSTIO_LIMIT environment variable and validate it is valid. Defaults to 5 if not set.
        self.hostio_limit = environ.get("HOSTIO_LIMIT", 5)
        if isinstance(self.hostio_limit, str) and can_be_int(self.hostio_limit):
            self.hostio_limit = int(self.hostio_limit)
        if not isinstance(self.hostio_limit, int):
            msg = f"Error when grabbing HOSTIO_LIMIT environment variable: '{self.hostio_limit}'. It SHOULD be an integer. "
            self.helper.log_error(msg)
            raise ValueError(msg)
        # Get HOSTIO_LABELS environment variable and validate it is valid. Defaults to TLP:WHITE if not set.
        self.hostio_labels = environ.get("HOSTIO_LABELS", None)
        if not validate_labels(self.hostio_labels):
            msg = "Error when grabbing HOSTIO_LABELS environment variable."
            self.helper.log_error(msg)
            raise ValueError(msg)
        self.hostio_marking_refs = environ.get("HOSTIO_MARKING_REFS", None)
        if not validate_tlp_marking(self.hostio_marking_refs):
            msg = "Error when grabbing HOSTIO_MARKING_REFS environment variable. It SHOULD be a valid TLP marking."
            self.helper.log_error(msg)
            raise ValueError(msg)

    def _add_external_reference(self, source_name, url, entity_id):
        self.helper.log_info(
            f"Adding external reference to {entity_id} with source_name: {source_name} and url: {url}"
        )
        external_reference = self.helper.api.external_reference.create(
            source_name=source_name,
            url=url,
        )
        self.helper.api.stix_cyber_observable.add_external_reference(
            id=entity_id, external_reference_id=external_reference.get("id")
        )

    def _process_addr(self, stix_objects, entity_id, opencti_entity):
        """Processing the enrichment request for an IPv4-Addr"""
        self.helper.log_info(f"Processing IPv4-Addr with ID: {entity_id}")
        ip = opencti_entity.get("value")

        # Validate the IP address
        if ip is None and (is_ipv4(ip) or is_ipv6(ip)):
            raise ValueError(f"IPvX-Address does not have a value attribute: {ip}")

        # Add External Reference for the IP
        source_name = "IPinfo"
        url = f"https://ipinfo.io/{ip}"

        # TODO: Consolidate into class.
        self.helper.log_info(f"IPvX-Address value: {ip}")
        hostio = HostIOIPtoDomain(
            token=self.hostio_token,
            ip=ip,
            limit=self.hostio_limit,
            entity_id=entity_id,
            marking_refs=self.hostio_marking_refs,
        )
        while hostio.has_next:
            hostio.request_ip_to_domain()
            stix_objects.extend(hostio.get_stix_objects())
        ipinfo_object = IPInfo(
            token=self.hostio_token,
            ip=ip,
            entity_id=entity_id,
            marking_refs=self.hostio_marking_refs,
        )
        if len(ipinfo_object.get_details()) > 0:
            stix_objects.extend(ipinfo_object.get_stix_objects())
            self._create_labels(
                opencti_entity=opencti_entity,
                ipinfo_object=ipinfo_object,
                entity_id=entity_id,
            )

        self._create_ipinfo_enrichment_notes(
            stix_objects,
            source_name=source_name,
            url=url,
            ipinfo_object=ipinfo_object,
            entity_id=entity_id,
        )

        # Add External Reference for the IP
        self._add_external_reference(
            source_name=source_name, url=url, entity_id=entity_id
        )

    def _create_labels(self, opencti_entity=None, ipinfo_object=None, entity_id=None):
        """Create labels for the IP."""
        # update labels for the IP
        if hasattr(opencti_entity, "labels"):
            existing_labels = opencti_entity.get("labels")
        else:
            existing_labels = []
        existing_labels.extend(ipinfo_object.get_labels())
        existing_labels.extend(format_labels(self.hostio_labels))
        self.helper.log_info(f"Updating labels for {entity_id}")
        self.helper.api.stix_cyber_observable.update_field(
            id=entity_id,
            input={
                "key": "labels",
                "value": format_labels(existing_labels),
            },
        )

    def _create_ipinfo_enrichment_notes(
        self,
        stix_objects,
        source_name=None,
        url=None,
        ipinfo_object=None,
        entity_id=None,
    ):
        """Create IPInfo enrichment notes."""
        # Update Indicator Description with results from IPInfo.
        note_content = ipinfo_object.get_note_content()
        # Update Indicator Description with results from IPInfo.
        if len(note_content) > 0:
            stix_objects.append(
                Note(
                    type="note",
                    abstract=f"IPInfo enrichment content for {ipinfo_object.ip}",
                    content=note_content,
                    object_refs=[entity_id],
                    labels=format_labels(self.hostio_labels),
                    object_marking_refs=[get_tlp_marking(self.hostio_marking_refs)],
                    external_references=[
                        {
                            "source_name": source_name,
                            "url": url,
                        }
                    ],
                )
            )

    def _process_domain_name(self, stix_objects, entity_id, opencti_entity):
        """Processing the enrichment request for a Domain-Name"""
        domain = opencti_entity.get("value")
        if not isinstance(domain, str) or domain is None:
            raise ValueError("Domain-Name does not have a value attribute")

        self.helper.log_info(f"Domain-Name value: {domain}")

        source_name = "Host IO Domain"
        url = f"https://host.io/{domain}"

        self.helper.log_info(f"Processing Domain-Name with ID: {entity_id}")

        # Get Host IO Domain
        domain_object = HostIODomain(
            token=self.hostio_token,
            domain=domain,
            entity_id=entity_id,
            marking_refs=self.hostio_marking_refs,
        )
        stix_objects.extend(domain_object.get_stix_objects())

        # Add External Reference
        self.helper.log_info(f"Adding external reference to {entity_id}")
        self._add_external_reference(
            source_name=source_name, url=url, entity_id=entity_id
        )

        # Create Host IO enrichment notes.
        self._create_hostio_enrichment_notes(
            stix_objects=stix_objects,
            domain_object=domain_object,
            entity_id=entity_id,
            source_name=source_name,
            url=url,
        )

    def _create_hostio_enrichment_notes(
        self,
        stix_objects,
        source_name=None,
        url=None,
        domain_object=None,
        entity_id=None,
    ):
        """Create Host IO enrichment notes."""
        # Validate parameters
        if domain_object is None:
            raise ValueError("domain_object is None")
        if entity_id is None:
            raise ValueError("entity_id is None")
        if not isinstance(source_name, str) or source_name is None:
            raise ValueError("source_name is None")
        if not isinstance(source_name, str) or url is None:
            raise ValueError("url is None")

        # Add Indicator Notes with results from Host IO.
        note_content = domain_object.get_note_content()
        if len(note_content) > 0:
            stix_objects.append(
                Note(
                    type="note",
                    abstract=f"Host IO enrichment content for {domain_object.domain}",
                    content=note_content,
                    object_refs=[entity_id],
                    labels=format_labels(self.hostio_labels),
                    object_marking_refs=[get_tlp_marking(self.hostio_marking_refs)],
                    external_references=[
                        {
                            "source_name": source_name,
                            "url": url,
                        }
                    ],
                )
            )

    def _process_message(self, data):
        """Processing the enrichment request."""

        # ===========================
        # === Add your code below ===
        # ===========================
        entity_id = data.get("entity_id", None)
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the enrichment of entity ID {entity_id}: {data}"
        )
        opencti_entity = self.helper.api.stix_cyber_observable.read(id=entity_id)
        self.helper.log_info(
            f"OpenCTI entity: {opencti_entity.keys()}"
        )  # TODO: Remove this line
        if opencti_entity is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, check the group of the connector user)"
            )

        # Get entity_type from the opencti_entity, and initialize stix_objects.
        if "entity_type" in opencti_entity:
            self.helper.log_info(
                f"Observable is a {opencti_entity.get('entity_type')}: {opencti_entity}"
            )
            entity_type = opencti_entity.get("entity_type")
            stix_objects = []
        else:
            self.helper.log_error(
                f"Observable does not have an entity_type attribute: {opencti_entity}"
            )
            raise ValueError("Observable does not have an entity_type attribute")
        if entity_type in ["IPv4-Addr", "IPv6-Addr"]:
            self.helper.log_info(f"Observable is an {entity_type}: {opencti_entity}")
            self._process_addr(
                stix_objects, entity_id=entity_id, opencti_entity=opencti_entity
            )
        elif entity_type == "Domain-Name":
            self.helper.log_info(f"Observable is a Domain-Name: {opencti_entity}")
            self._process_domain_name(
                stix_objects=stix_objects,
                entity_id=entity_id,
                opencti_entity=opencti_entity,
            )
        else:
            self.helper.log_warn(
                f"Observable is not a supported type ({entity_type}):\n{opencti_entity}"
            )

        # If there are not objects to process, return.
        if len(stix_objects) == 0:
            self.helper.log_info("No stix objects generated for worker import")
            return
        # Create the bundle and send it to OpenCTI.
        bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(bundle)
        self.helper.log_info(
            f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
        )
        # ===========================
        # === Add your code above ===
        # ===========================


if __name__ == "__main__":
    connector = HostIOConnector()
    connector.start()
