import requests
import stix2
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from connector.utils import ModatUtils
from modat_client import ModatClient, ModatHost
from pycti import (
    STIX_EXT_OCTI_SCO,
    Identity,
    Note,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
)
from pydantic import ValidationError


class ModatConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        modat = config.modat
        self.api_base_url = str(modat.api_base_url)
        self.api_key = modat.api_key.get_secret_value()
        self.max_tlp = modat.max_tlp
        self.default_score = int(modat.default_score)
        self.create_note = bool(modat.create_note)
        self.include_cves = bool(modat.include_cves)
        self.max_services_in_summary = int(modat.max_services_in_summary)

        self.client = ModatClient(
            helper=helper,
            base_url=self.api_base_url,
            api_key=self.api_key,
        )
        self.utils = ModatUtils(helper=helper)

        self.author = stix2.Identity(
            id=Identity.generate_id(name="Modat", identity_class="organization"),
            name="Modat",
            identity_class="organization",
            description="Modat Magnify enrichment source",
        )
        self.converter = ConverterToStix(
            author=self.author,
            default_score=self.default_score,
            include_cves=self.include_cves,
        )

    def _extract_and_check_markings(self, entity: dict) -> None:
        tlp = "TLP:CLEAR"
        for marking_definition in entity.get("objectMarking", []):
            if marking_definition.get("definition_type") == "TLP":
                tlp = marking_definition.get("definition", tlp)

        is_valid_max_tlp = OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp)
        if not is_valid_max_tlp:
            self.helper.connector_logger.warning(
                "[MODAT] Skipping enrichment: observable TLP exceeds MAX TLP",
                {"observable_tlp": tlp, "max_tlp": self.max_tlp},
            )
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP"
            )

    def _send_bundle(self, stix_objects: list) -> str:
        # OpenCTI upserts by STIX id on import, so duplicate objects/relationships
        # (e.g. an FQDN that is also a certificate SAN) are merged platform-side.
        stix_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(stix_bundle)
        return f"Sending {len(bundles_sent)} STIX bundle(s) for worker import"

    def _is_entity_in_scope(self, entity_type: str) -> bool:
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        return entity_type.lower() in scopes

    def process_message(self, data: dict) -> str:
        opencti_entity = data["enrichment_entity"]
        self._extract_and_check_markings(opencti_entity)

        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        observable_value = stix_entity.get("value")
        observable_markings = stix_entity.get("object_marking_refs", [])
        self.helper.connector_logger.info(
            "[MODAT] Received enrichment request",
            {
                "entity_type": opencti_entity.get("entity_type"),
                "stix_type": stix_entity.get("type"),
                "value": observable_value,
            },
        )

        if not self._is_entity_in_scope(opencti_entity["entity_type"]):
            if data.get("event_type"):
                raise ValueError(
                    f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type"
                )
            return self._send_bundle(stix_objects)

        if stix_entity.get("type") != "ipv4-addr":
            if data.get("event_type"):
                raise ValueError(
                    f"Unsupported entity type for Modat connector: {stix_entity.get('type')}"
                )
            return self._send_bundle(stix_objects)

        if not isinstance(observable_value, str) or not observable_value:
            self.helper.connector_logger.warning(
                "[MODAT] Observable has no value; skipping enrichment",
                {"id": stix_entity.get("id")},
            )
            return self._send_bundle(stix_objects)

        try:
            payload = self.client.get_host_details(observable_value)
        except ValueError as err:
            # ModatClient raises ValueError for non-IPv4 inputs (defense-in-depth).
            self.helper.connector_logger.warning(
                "[MODAT] Refused to query Modat for invalid value",
                {"value": observable_value, "error": str(err)},
            )
            return self._send_bundle(stix_objects)
        except requests.HTTPError as err:
            status = err.response.status_code if err.response is not None else None
            if status == 404:
                self.helper.connector_logger.info(
                    "[MODAT] No host details found", {"ip": observable_value}
                )
                return self._send_bundle(stix_objects)
            self.helper.connector_logger.error(
                "[MODAT] Modat API returned HTTP error",
                {"ip": observable_value, "status": status},
            )
            raise
        except requests.RequestException as err:
            self.helper.connector_logger.error(
                "[MODAT] Network error while contacting Modat",
                {"ip": observable_value, "error": str(err)},
            )
            raise

        if not isinstance(payload, dict):
            self.helper.connector_logger.warning(
                "[MODAT] Modat response was not a JSON object", {"ip": observable_value}
            )
            return self._send_bundle(stix_objects)

        record = payload.get("data")
        if not isinstance(record, dict):
            self.helper.connector_logger.info(
                "[MODAT] Empty host details payload", {"ip": observable_value}
            )
            return self._send_bundle(stix_objects)

        try:
            host = ModatHost.model_validate(record)
        except ValidationError as err:
            self.helper.connector_logger.warning(
                "[MODAT] Could not parse Modat host record; skipping enrichment",
                {"ip": observable_value, "error": str(err)},
            )
            return self._send_bundle(stix_objects)

        self.helper.connector_logger.info(
            "[MODAT] Host details parsed",
            {
                "services_count": len(host.services),
                "fqdns_count": len(host.fqdns),
                "cves_count": len(host.cves),
            },
        )

        summary = self.utils.build_summary(
            observable_value,
            host,
            include_cves=self.include_cves,
            max_services=self.max_services_in_summary,
        )

        external_reference = stix2.ExternalReference(
            source_name=f"Modat ({observable_value})",
            url=f"https://magnify.modat.io/hosts/{observable_value}",
            description=f"Modat Magnify host page for {observable_value}",
            external_id=observable_value,
        )

        stix_objects.append(self.author)
        stix_plan = self.converter.plan_structured_knowledge(host)
        self.converter.apply_structured_knowledge(
            stix_objects, stix_entity, stix_plan, observable_markings
        )

        OpenCTIStix2.put_attribute_in_extension(
            stix_entity, STIX_EXT_OCTI_SCO, "score", self.default_score
        )
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity,
            STIX_EXT_OCTI_SCO,
            "external_references",
            {
                "source_name": external_reference.source_name,
                "description": external_reference.description,
                "url": external_reference.url,
            },
            True,
        )
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity, STIX_EXT_OCTI_SCO, "labels", "modat", True
        )
        OpenCTIStix2.put_attribute_in_extension(
            stix_entity, STIX_EXT_OCTI_SCO, "labels", "modat-enriched", True
        )
        for tag in host.tags:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity,
                STIX_EXT_OCTI_SCO,
                "labels",
                f"modat:{tag.lower().replace(' ', '-')}",
                True,
            )

        if self.create_note:
            # Stable, per-observable note id so re-enriching the same IP updates the
            # existing Modat note instead of piling up duplicates. We key on the
            # observable value rather than the rendered summary because the summary
            # embeds volatile per-service scan timestamps, which would otherwise mint
            # a brand-new note on every re-scan.
            stix_note = stix2.Note(
                id=Note.generate_id(
                    None, f"Modat Magnify enrichment of {observable_value}"
                ),
                abstract=f"Modat Results for {observable_value}",
                content=summary,
                created_by_ref=self.author["id"],
                object_refs=[stix_entity["id"]],
                object_marking_refs=observable_markings,
                custom_properties={"note_types": ["external"]},
            )
            stix_objects.append(stix_note)

        return self._send_bundle(stix_objects)

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
