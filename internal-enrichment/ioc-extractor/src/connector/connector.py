from connector.extractor import ExtractedIOC, extract_iocs
from connector.settings import ConnectorSettings
from connectors_sdk.models import (
    URL,
    DomainName,
    File,
    IPV4Address,
    IPV6Address,
    OrganizationAuthor,
    Relationship,
)
from connectors_sdk.models.enums import HashAlgorithm, RelationshipType
from connectors_sdk.models.reference import Reference
from pycti import OpenCTIConnectorHelper


class IOCExtractorConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.author = OrganizationAuthor(name="IOC Extractor")

    @staticmethod
    def _get_description(stix_entity: dict, opencti_entity: dict) -> str:
        """Extract description from entity data."""
        return stix_entity.get("description") or opencti_entity.get("description")

    @staticmethod
    def _get_markings_from_entity(stix_entity: dict) -> list[Reference] | None:
        """Extract marking references from the source entity."""
        marking_refs = stix_entity.get("object_marking_refs", [])
        return [Reference(id=ref) for ref in marking_refs] if marking_refs else None

    def _extract_and_check_markings(self, opencti_entity: dict) -> None:
        """Extract TLP from entity and check against max_tlp config."""
        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity.get("objectMarking", []):
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]
        max_tlp = self.config.ioc_extractor.max_tlp
        if not OpenCTIConnectorHelper.check_max_tlp(tlp, max_tlp):
            raise ValueError(
                f"Do not send any data, TLP of the observable ({tlp}) is greater "
                f"than MAX TLP ({max_tlp})"
            )

    @staticmethod
    def _ioc_to_stix_object(ioc: ExtractedIOC, markings=None, author=None):
        """Convert an ExtractedIOC to a connectors-sdk model instance."""
        match ioc.type:
            case "ipv4":
                return IPV4Address(value=ioc.value, markings=markings, author=author)
            case "ipv6":
                return IPV6Address(value=ioc.value, markings=markings, author=author)
            case "domain":
                return DomainName(value=ioc.value, markings=markings, author=author)
            case "url":
                return URL(value=ioc.value, markings=markings, author=author)
            case "md5":
                return File(
                    hashes={HashAlgorithm.MD5: ioc.value},
                    markings=markings,
                    author=author,
                )
            case "sha1":
                return File(
                    hashes={HashAlgorithm.SHA1: ioc.value},
                    markings=markings,
                    author=author,
                )
            case "sha256":
                return File(
                    hashes={HashAlgorithm.SHA256: ioc.value},
                    markings=markings,
                    author=author,
                )
            case _:
                return None

    def _build_stix_objects(
        self, iocs: list[ExtractedIOC], entity_id: str, markings=None
    ) -> tuple[list[dict], list[str]]:
        """Build STIX observable objects and relationships from extracted IOCs."""
        stix_objects = []
        observable_ids = []

        for ioc in iocs:
            sdk_object = self._ioc_to_stix_object(
                ioc, markings=markings, author=self.author
            )
            if sdk_object is None:
                continue

            stix_obj = sdk_object.to_stix2_object()
            stix_objects.append(stix_obj)
            observable_ids.append(stix_obj["id"])

        return stix_objects, observable_ids

    @staticmethod
    def _enrich_container_object_refs(
        stix_entity: dict, stix_objects: list, observable_ids: list[str]
    ) -> list:
        """Add observable IDs to the Report's object_refs in the bundle."""
        # entity_type = stix_entity.get("type", "")
        # if entity_type != "report":
        #    return stix_objects

        if "object_refs" in stix_entity:
            stix_entity["object_refs"].extend(observable_ids)
        else:
            stix_entity["object_refs"] = observable_ids

        return stix_entity

    def _send_bundle(self, stix_objects: list) -> list:
        """Send the STIX bundle to the OpenCTI platform."""
        stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            bundle=stix_objects_bundle, cleanup_inconsistent_bundle=True
        )
        return bundles_sent

    def process_message(self, data: dict) -> str:
        """Process enrichment message: extract IOCs and return enriched bundle."""
        try:
            opencti_entity = data["enrichment_entity"]
            stix_objects = data["stix_objects"]
            stix_entity = data["stix_entity"]

            # Check TLP marking against max_tlp configuration
            self._extract_and_check_markings(opencti_entity)

            config = self.config.ioc_extractor
            description = self._get_description(stix_entity, opencti_entity)

            # Extract IOCs from description
            iocs = extract_iocs(
                text=description or "",
                extract_hashes=config.extract_hashes,
                extract_ipv4=config.extract_ipv4,
                extract_ipv6=config.extract_ipv6,
                extract_domains=config.extract_domains,
                extract_urls=config.extract_urls,
                skip_private_ips=config.skip_private_ips,
            )

            if not iocs:
                self._send_bundle(stix_objects)
                self.helper.connector_logger.info(
                    "[IOC EXTRACTOR] No IOCs found in entity content",
                    {"entity_id": data.get("entity_id")},
                )
                return "No IOCs found in entity content"

            # Build STIX observables and relationships
            markings = self._get_markings_from_entity(stix_entity)
            enrichment_objects, observable_ids = self._build_stix_objects(
                iocs, stix_entity["id"], markings=markings
            )

            # For Containers, add observables to object_refs
            if "Container" in opencti_entity.get("parent_types", []):
                stix_entity = self._enrich_container_object_refs(
                    stix_entity, stix_objects, observable_ids
                )
            else:
                for observable_id in observable_ids:
                    # Create related-to relationship
                    relationship = Relationship(
                        type=RelationshipType.RELATED_TO,
                        source=Reference(id=observable_id),
                        target=stix_entity,
                    )
                    stix_objects.append(relationship.to_stix2_object())

            # Merge enrichment objects with original bundle (include author identity)
            all_objects = (
                [self.author.to_stix2_object()] + stix_objects + enrichment_objects
            )
            bundles_sent = self._send_bundle(all_objects)

            self.helper.connector_logger.info(
                "[IOC EXTRACTOR] Enrichment complete",
                {
                    "iocs_found": len(iocs),
                    "bundles_sent": len(bundles_sent),
                    "entity_id": data.get("entity_id"),
                },
            )
            return f"Extracted {len(iocs)} IOC(s), sent {len(bundles_sent)} bundle(s)"

        except Exception as err:
            # Always send back the original bundle for playbook continuity
            self._send_bundle(data["stix_objects"])
            self.helper.connector_logger.error(
                "[IOC EXTRACTOR] Unexpected error",
                {"error_message": str(err)},
            )
            return f"Error: {str(err)}"

    def run(self) -> None:
        """Run the connector, listening for enrichment messages."""
        self.helper.listen(message_callback=self.process_message)
