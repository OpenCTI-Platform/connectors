import json
from urllib.parse import quote

import stix2
from anyrun.connectors import LookupConnector
from config import Config, config
from pycti import (
    Identity,
    Indicator,
    Note,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)

ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE = {
    "relatedDNS": "Domain-Name",
    "relatedURLs": "Url",
    "destinationIP": "IPv4-Addr",
}

ANYRUN_INDICATOR_TO_STIX = {
    "relatedDNS": "domain-name",
    "relatedURLs": "url",
    "destinationIP": "ipv4-addr",
}

SDK_ENTITY_TO_LOOKUP_OBJECT = {
    "domain_name": "domainName",
    "destination_ip": "destinationIp",
    "url": "url",
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
}

# Map an algorithm key (as returned by the SDK / used in our lookup params)
# to the canonical STIX File hash key used in indicator patterns.
HASH_ALGORITHM_TO_STIX = {
    "sha256": "SHA-256",
    "sha1": "SHA-1",
    "md5": "MD5",
}


class AnyRunTILookup:
    def __init__(self, config_obj: Config):
        self._helper = OpenCTIConnectorHelper(config)
        self._config = config_obj

        self._identity = stix2.Identity(
            id=Identity.generate_id("ANY.RUN", "organization"),
            name="ANY.RUN",
            identity_class="organization",
            description=(
                "Empowers SOC teams with a Sandbox for real-time malware analysis, "
                "Threat Intelligence Lookup, and high-quality feeds to enhance "
                "detection and threat coverage."
            ),
            contact_information="techsupport@any.run",
        )

        self._helper.send_stix2_bundle(
            self._helper.stix2_create_bundle([self._identity]),
        )

    def _process_message(self, data):
        self._load_opencti_entity(data)

        lookup_search_results = self._get_intelligence()

        if (
            self._is_empty(lookup_search_results)
            or lookup_search_results.get("summary").get("threatLevel") > 2
        ):
            self._helper.api.work.to_received(
                self._helper.work_id, "Object was not found in ANY.RUN TI Lookup."
            )
            return

        self._create_related_objects(
            lookup_search_results.get("relatedDNS"), "relatedDNS"
        )
        self._create_related_objects(
            lookup_search_results.get("relatedURLs"), "relatedURLs"
        )
        self._create_related_objects(
            lookup_search_results.get("destinationIP"), "destinationIP"
        )

        self._update_main_observable(lookup_search_results)
        self._create_note()

        if self._opencti_entity.get("entity_type") == "IPv4-Addr":
            self._create_country_relationship(
                lookup_search_results.get("destinationIPgeo")
            )

        if self._opencti_entity.get("entity_type") in (
            "StixFile",
            "Artifact",
        ) and lookup_search_results.get("summary").get("threatLevel") in (1, 2):
            self._create_file_indicator(
                lookup_search_results.get("summary").get("threatLevel")
            )

    def _create_country_relationship(self, destination_ips: list[dict | None]) -> None:
        """
        Creates STIX Country relationship for main observable

        :param destination_ips: Geo countries
        """
        for ipgeo in destination_ips:
            opencti_locations = self._helper.api.location.list(search=ipgeo)
            if not opencti_locations:
                continue

            self._helper.send_stix2_bundle(
                self._helper.stix2_create_bundle(
                    [
                        stix2.Relationship(
                            id=StixCoreRelationship.generate_id(
                                "located-at",
                                self._opencti_entity.get("standard_id"),
                                opencti_locations[0].get("standard_id"),
                            ),
                            relationship_type="located-at",
                            created_by_ref=self._identity.get("id"),
                            source_ref=self._opencti_entity.get("standard_id"),
                            target_ref=opencti_locations[0].get("standard_id"),
                        )
                    ]
                )
            )

    def _create_related_objects(
        self, indicators: list[dict], indicator_type: str
    ) -> None:
        """
        Process ANY.RUN task indicators. If indicator's threat level is 'No threads detected' creates related observable
            else creates a new stix indicator

        :param indicators: List of ANY.RUN indicators
        :param indicator_type: ANY.RUN indicator type
        """
        objects: list = []

        for ioc in indicators:
            value = self._extract_indicator_value(ioc, indicator_type)
            if not value:
                continue

            if ioc["threatLevel"] == 0:
                observable = _build_observable(indicator_type, value, self._identity)

                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to",
                        observable.id,
                        self._opencti_entity.get("standard_id"),
                    ),
                    confidence=100,
                    description="Detected by ANY.RUN TI Lookup",
                    relationship_type="related-to",
                    created_by_ref=self._identity.get("id"),
                    source_ref=observable.id,
                    target_ref=self._opencti_entity.get("standard_id"),
                )

                objects.append(observable)
                objects.append(relationship)

            elif ioc["threatLevel"] in (1, 2):
                pattern = f"[{ANYRUN_INDICATOR_TO_STIX.get(indicator_type)}:value = '{value}']"

                indicator = stix2.Indicator(
                    id=Indicator.generate_id(pattern),
                    created_by_ref=self._identity.get("id"),
                    name=value,
                    pattern_type="stix",
                    pattern=pattern,
                    custom_properties={
                        "x_opencti_score": {0: 0, 1: 50, 2: 100}.get(
                            ioc.get("threatLevel")
                        ),
                        "x_opencti_created_by_ref": self._identity.get("id"),
                        "x_opencti_main_observable_type": ANYRUN_INDICATOR_TO_MAIN_OBSERVABLE.get(
                            indicator_type
                        ),
                    },
                )

                relationship = stix2.Relationship(
                    id=StixCoreRelationship.generate_id(
                        "based-on",
                        indicator.id,
                        self._opencti_entity.get("standard_id"),
                    ),
                    confidence=100,
                    description="Detected by ANY.RUN TI Lookup",
                    relationship_type="based-on",
                    created_by_ref=self._identity.get("id"),
                    source_ref=indicator.id,
                    target_ref=self._opencti_entity.get("standard_id"),
                )

                objects.append(indicator)
                objects.append(relationship)

        if objects:
            self._helper.send_stix2_bundle(self._helper.stix2_create_bundle(objects))

    def _create_file_indicator(self, score: int) -> None:
        """
        Creates STIX File indicator using the proper ``file:hashes.'XXX'`` pattern.

        :param score: ANY.RUN score
        """
        params = self._prepare_lookup_params()
        algorithm, value = next(iter(params.items()))
        stix_algorithm = HASH_ALGORITHM_TO_STIX.get(algorithm)
        if stix_algorithm is None:
            return

        pattern = f"[file:hashes.'{stix_algorithm}' = '{value}']"

        indicator = stix2.Indicator(
            id=Indicator.generate_id(pattern),
            created_by_ref=self._identity.get("id"),
            description="Detected by ANY.RUN TI Lookup",
            name=value,
            pattern_type="stix",
            pattern=pattern,
            custom_properties={
                "x_opencti_score": {1: 50, 2: 100}.get(score),
                "x_opencti_created_by_ref": self._identity.get("id"),
                "x_opencti_main_observable_type": "File",
            },
        )

        relationship = stix2.Relationship(
            id=StixCoreRelationship.generate_id(
                "based-on",
                indicator.id,
                self._opencti_entity.get("standard_id"),
            ),
            confidence=100,
            description="Detected by ANY.RUN TI Lookup",
            relationship_type="based-on",
            created_by_ref=self._identity.get("id"),
            source_ref=indicator.id,
            target_ref=self._opencti_entity.get("standard_id"),
        )

        self._helper.send_stix2_bundle(
            self._helper.stix2_create_bundle([indicator, relationship])
        )

    def _update_main_observable(self, lookup_search_results: dict) -> None:
        """
        Updates main observable using ANY.RUN Lookup summary

        :param lookup_search_results: ANY.RUN lookup result
        """
        custom_properties = self._get_custom_properties(lookup_search_results)
        entity_type = self._opencti_entity.get("entity_type")

        if entity_type in ("StixFile", "Artifact"):
            hashes = {
                hash_data.get("algorithm"): hash_data.get("hash")
                for hash_data in self._opencti_entity.get("hashes") or []
            }
            if not hashes:
                return
            observable = stix2.File(hashes=hashes, custom_properties=custom_properties)
        elif entity_type in ("Domain-Name", "Hostname"):
            observable = stix2.DomainName(
                value=self._opencti_entity.get("value"),
                custom_properties=custom_properties,
            )
        elif entity_type == "Url":
            observable = stix2.URL(
                value=self._opencti_entity.get("value"),
                custom_properties=custom_properties,
            )
        elif entity_type == "IPv4-Addr":
            observable = stix2.IPv4Address(
                value=self._opencti_entity.get("value"),
                custom_properties=custom_properties,
            )
        else:
            return

        self._helper.send_stix2_bundle(
            self._helper.stix2_create_bundle([observable]), update=True
        )

    def _get_custom_properties(self, lookup_search_results: dict) -> dict:
        return {
            "x_opencti_labels": lookup_search_results.get("summary").get("tags"),
            "x_opencti_score": self._update_score(lookup_search_results),
            "x_opencti_description": "Detected by ANY.RUN TI Lookup",
            "x_opencti_created_by_ref": self._identity.get("id"),
            "x_opencti_external_references": self._create_external_references(
                lookup_search_results.get("sourceTasks")
            ),
        }

    def _update_score(self, lookup_search_results: dict) -> int:
        """
        Adds score to the main observable

        :param lookup_search_results: ANY.RUN lookup result
        :return: The greatest score
        """
        opencti_score = self._opencti_entity.get("x_opencti_score", 0)
        anyrun_score = lookup_search_results.get("summary").get("threatLevel")

        if not opencti_score:
            return anyrun_score

        if not anyrun_score:
            return opencti_score

        anyrun_score = {0: 0, 1: 50, 2: 100}.get(anyrun_score)

        if anyrun_score > opencti_score:
            return anyrun_score

        return opencti_score

    def _load_opencti_entity(self, data) -> None:
        """
        Loads OpenCTI entity object using message data

        :param data: Message data
        """
        self._helper.log_debug(str(data))

        self._opencti_entity = self._helper.api.stix_cyber_observable.read(
            id=data["entity_id"], withFiles=True
        )

        if self._opencti_entity is None:
            raise ValueError(
                "Observable not found (or the connector does not has access to this observable, check the group of the connector user)"
            )

    def _get_intelligence(self) -> dict | None:
        """
        Executes a request to ANY.RUN TI Lookup

        :return: TI Lookup summary
        """
        with LookupConnector(
            self._config.anyrun_token,
            integration=self._config.VERSION,
            enable_requests=True,
        ) as connector:
            connector.check_authorization()

            return connector.get_intelligence(
                **self._prepare_lookup_params(), lookup_depth=self._config.lookup_depth
            )

    def _prepare_lookup_params(self) -> dict:
        """
        Converts OpenCTI entity data to the SDK query parameters

        :return: Query parameters
        """
        entity_type = self._opencti_entity["entity_type"]

        if entity_type == "Domain-Name":
            return {"domain_name": self._opencti_entity["value"]}
        if entity_type == "Hostname":
            return {"domain_name": self._opencti_entity["value"]}
        if entity_type == "IPv4-Addr":
            return {"destination_ip": self._opencti_entity["value"]}
        if entity_type == "Url":
            return {"url": self._opencti_entity["value"]}
        if entity_type in ("StixFile", "Artifact"):
            if hashes := self._opencti_entity.get("hashes"):
                for file_hash in hashes:
                    if (algorithm := file_hash.get("algorithm")) in (
                        "SHA-256",
                        "SHA-1",
                        "MD5",
                    ):
                        return {
                            algorithm.lower().replace("-", ""): file_hash.get("hash")
                        }
            raise ValueError(
                "StixFile or Artifact entity must have at least one of the following hashes: SHA-256, SHA-1, MD5"
            )

        raise ValueError(
            "Wrong scope! Supported only Artifact, StixFile, Directory, Domain-Name, "
            "Hostname, IPv4-Addr, Mutex, Process, Url, Windows-Registry-Key, "
            "Windows-Registry-Value-Type observables"
        )

    def _create_note(self) -> None:
        """
        Creates note for the main observable
        """
        entity_type, entity_value = list(self._prepare_lookup_params().items())[0]

        params = {
            "query": f"{SDK_ENTITY_TO_LOOKUP_OBJECT.get(entity_type)}:{entity_value}",
            "dateRange": self._config.lookup_depth,
        }

        url = (
            f"https://intelligence.any.run/analysis/lookup#{quote(json.dumps(params))}"
        )
        note_content = f"ANY.RUN TI Lookup link:\n {url}"

        self._helper.send_stix2_bundle(
            self._helper.stix2_create_bundle(
                [
                    stix2.Note(
                        id=Note.generate_id(None, note_content),
                        abstract=note_content,
                        content=note_content,
                        created_by_ref=self._identity.get("id"),
                        object_refs=[self._opencti_entity.get("standard_id")],
                    )
                ]
            )
        )

    @staticmethod
    def _create_external_references(
        source_tasks: list[dict | None],
    ) -> list[stix2.ExternalReference] | None:
        """
        Adds external references to the indicator

        :param source_tasks: List of the related tasks
        :return: List of the external references
        """
        if not source_tasks:
            return None

        refs_identifiers = []
        for task in source_tasks:
            if task.get("threatLevel") == 2:
                refs_identifiers.append(
                    stix2.ExternalReference(
                        source_name=f"ANY.RUN analysis {task.get('uuid')}",
                        url=task.get("related"),
                        description="ANY.RUN related analysis URL",
                    )
                )
        return refs_identifiers or None

    @staticmethod
    def _extract_indicator_value(indicator: dict, indicator_type: str) -> str | None:
        """
        Extracts indicator value according to the indicator type

        :param indicator: ANY.RUN indicator
        :param indicator_type: ANY.RUN indicator type
        :return: ANY.RUN indicator value
        """
        if indicator_type == "relatedDNS":
            return indicator.get("domainName")
        if indicator_type == "relatedURLs":
            return indicator.get("url")
        return indicator.get("destinationIP")

    @staticmethod
    def _is_empty(lookup_search_results: dict) -> bool:
        """
        Checks if ANY.RUN TI Lookup summary is empty

        :param lookup_search_results: TI Lookup summary
        :return: True if TI Lookup summary is not empty else False
        """
        for key, value in lookup_search_results.items():
            if key != "summary" and value:
                return False
        return True

    def mainloop(self):
        self._helper.listen(self._process_message)


def _build_observable(
    indicator_type: str, value: str, identity: stix2.Identity
) -> stix2.DomainName | stix2.URL | stix2.IPv4Address:
    """
    Build a STIX Cyber Observable matching the related-indicator type.

    The STIX 2.1 spec assigns deterministic UUID5 ids to SCOs based on the
    object's value contributing properties, so we don't need to set ``id=``
    explicitly here - the underlying ``stix2`` library does it for us as long
    as we provide every contributing property (``value`` for DomainName / URL
    / IPv4Address).
    """
    custom_properties = {
        "x_opencti_description": "Detected by ANY.RUN TI Lookup",
        "x_opencti_created_by_ref": identity.get("id"),
    }
    if indicator_type == "relatedDNS":
        return stix2.DomainName(value=value, custom_properties=custom_properties)
    if indicator_type == "relatedURLs":
        return stix2.URL(value=value, custom_properties=custom_properties)
    return stix2.IPv4Address(value=value, custom_properties=custom_properties)


if __name__ == "__main__":
    anyrun_connector = AnyRunTILookup(Config())
    anyrun_connector.mainloop()
