from os import environ

from hostio import HostIOIPtoDomainStixTransform, HostIOIPtoDomain
from hostio.hostio_utils import (
    can_be_int,
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

    def _process_ipv4_addr(self, stix_objects, entity_id, opencti_entity):
        """Processing the enrichment request for an IPv4-Addr"""
        self.helper.log_info(f"Processing IPv4-Addr with ID: {entity_id}")
        ip = opencti_entity.get("value")
        if ip is None:
            raise ValueError("IPv4-Addr does not have a value attribute")
        self.helper.log_info(f"IPv4-Addr value: {ip}")
        hostio = HostIOIPtoDomain(
            token=self.hostio_token, ip=ip, limit=self.hostio_limit
        )
        while hostio.has_next:
            hostio.request_ip_to_domain()
            for domain in hostio.domains:
                stix_objects.extend(
                    HostIOIPtoDomainStixTransform(
                        domain=domain, entity_id=entity_id
                    ).get_stix_objects(),
                    marking_refs=self.hostio_marking_refs,
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
        if entity_type == "IPv4-Addr":
            self.helper.log_info(f"Observable is an IPv4-Addr: {opencti_entity}")
            self._process_ipv4_addr(
                stix_objects, entity_id=entity_id, opencti_entity=opencti_entity
            )
        elif entity_type == "Domain-Name":
            self.helper.log_info(f"Observable is a Domain-Name: {opencti_entity}")
            # self._process_domain_name(entity_id, opencti_entity)
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
        # # Update a field
        # self.helper.log_debug("Updating OpenCTI score...")
        # self.helper.api.stix_cyber_observable.update_field(
        #     id=entity_id,
        #     input={
        #         "key": "x_opencti_score",
        #         "value": "100",
        #     },
        # )

        # # Add labels
        # self.helper.log_debug("Adding labels to the cyberobservable...")
        # self.helper.api.stix_cyber_observable.add_label(id=entity_id, label_name="test")
        # self.helper.api.stix_cyber_observable.add_label(
        #     id=entity_id, label_name="tutorial"
        # )

        # # Add an external reference using OpenCTI API
        # self.helper.log_debug("Adding external reference...")
        # external_reference = self.helper.api.external_reference.create(
        #     source_name="Félix Brezo (@febrezo)",
        #     url="https://github.com/OpenCTI-Platform/connectors",
        #     description="A sample external reference used by the connector.",
        # )

        # self.helper.api.stix_cyber_observable.add_external_reference(
        #     id=entity_id, external_reference_id=external_reference["id"]
        # )
        # ===========================
        # === Add your code above ===
        # ===========================


if __name__ == "__main__":
    connector = HostIOConnector()
    connector.start()
