import stix2
import yara
from connector.settings import ConnectorSettings
from pycti import (
    Identity,
    MarkingDefinition,
    OpenCTIConnectorHelper,
    StixCoreRelationship,
)
from stix2 import Relationship

# Custom GraphQL attributes used by ``_build_malware_relationships`` when
# listing the matched Indicator's ``indicates -> Malware`` relationships.
# We extend the default ``to`` block with the Malware fields needed to
# build a minimal :class:`stix2.Malware` SDO (``name``, ``description``,
# ``is_family``) so the Artifact -> Malware ``related-to`` relationships
# we emit are NOT silently dropped by
# ``send_stix2_bundle(..., cleanup_inconsistent_bundle=True)`` for
# missing target SDOs.
_INDICATES_MALWARE_LIST_ATTRIBUTES = """
    id
    standard_id
    entity_type
    parent_types
    relationship_type
    to {
        ... on BasicObject {
            id
            entity_type
        }
        ... on StixObject {
            standard_id
        }
        ... on Malware {
            name
            description
            is_family
        }
    }
"""


class YaraConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.octi_api_url = str(self.config.opencti.url).rstrip("/")
        self.tlp_level = self.config.yara.tlp_level
        self.author = stix2.Identity(
            id=Identity.generate_id("YARA", "organization"),
            name="YARA",
            identity_class="organization",
            description="YARA connector for OpenCTI",
        )

    def _get_artifact_contents(self, artifact) -> list[bytes]:
        """
        Retrieves the content associated with the artefact from OpenCTI, extracts the files and downloads their
        contents in binary format for further processing.

        :param artifact: Dictionary containing all the information in the OpenCTI artefact, potentially with an
                         'importFiles' key and a list of files to be retrieved.
        :return: List of the binary contents of the files associated with the artefact, returns an empty list `[]`
                 if no files are associated.
        """
        self.helper.connector_logger.debug(
            "Getting Artifact contents (bytes) from OpenCTI"
        )

        artifact_files_contents = artifact.get("importFiles", [])

        files_contents = []
        if artifact_files_contents:
            for artifact_file_content in artifact_files_contents:
                file_name = artifact_file_content.get("name")
                file_id = artifact_file_content.get("id")
                file_url = self.octi_api_url + "/storage/get/" + file_id
                file_content = self.helper.api.fetch_opencti_file(file_url, binary=True)
                files_contents.append(file_content)
                self.helper.connector_logger.debug(
                    f"Associated file found in Artifact with file_name :{file_name}"
                )
        else:
            self.helper.connector_logger.debug("No associated files found in Artifact")
        return files_contents

    def _get_yara_indicators(self) -> list:
        self.helper.connector_logger.debug("Getting all YARA Indicators in OpenCTI")

        data = {"pagination": {"hasNextPage": True, "endCursor": None}}
        all_entities = []
        # ``objectLabel`` is requested so the label-propagation path in
        # ``_scan_artifact`` does not need a second per-indicator API
        # round-trip; it stays empty / harmless when label propagation is
        # disabled.
        customAttributes = """
        id
        name
        standard_id
        pattern
        pattern_type
        valid_from
        objectMarking {
            standard_id
        }
        objectLabel {
            id
            value
            color
        }
        """
        while data["pagination"]["hasNextPage"]:
            after = data["pagination"]["endCursor"]
            data = self.helper.api.indicator.list(
                first=1000,
                after=after,
                filters={
                    "mode": "and",
                    "filters": [{"key": "pattern_type", "values": ["yara"]}],
                    "filterGroups": [],
                },
                orderBy="created_at",
                orderMode="asc",
                withPagination=True,
                customAttributes=customAttributes,
            )
            all_entities += data["entities"]
        return all_entities

    def _collect_marking_refs(self, artifact, indicator):
        """Collect unique marking definition refs from both entities, falling back to default marking."""
        marking_refs = set()
        for marking in artifact.get("objectMarking", []):
            std_id = marking.get("standard_id")
            if std_id:
                marking_refs.add(std_id)
        for marking in indicator.get("objectMarking", []):
            std_id = marking.get("standard_id")
            if std_id:
                marking_refs.add(std_id)
        if not marking_refs and self.tlp_level:
            tlp_value = "TLP:" + self.tlp_level.upper()
            marking_refs.add(MarkingDefinition.generate_id("TLP", tlp_value))
        return list(marking_refs) if marking_refs else None

    def _scan_artifact(self, artifact, yara_indicators) -> tuple[list, list[str]]:
        self.helper.connector_logger.debug("Scanning Artifact contents with YARA")

        artifact_contents = self._get_artifact_contents(artifact)

        bundle_objects = []
        matched_indicators = {}
        # Track indicators whose *propagation side-effects* (label
        # propagation, ``indicates`` -> Malware relationship lookup +
        # emission) have already run for this artifact. ``_scan_artifact``
        # iterates over every ``importFile`` of the Artifact and every
        # YARA indicator, so a single Artifact / Indicator pair can match
        # repeatedly (one match per file). Without this guard we would:
        #
        # * call ``stix_cyber_observable.add_label`` once per file per
        #   label (the OpenCTI side-channel API is idempotent, but the
        #   duplicate mutations are wasted round-trips);
        # * call ``stix_core_relationship.list`` once per file (waste);
        # * append duplicate Artifact -> Malware ``related-to``
        #   relationships and duplicate Malware SDOs to ``bundle_objects``
        #   (the STIX ``Relationship.id`` is deterministic so a downstream
        #   dedup would catch them, but we should not rely on that).
        #
        # Keying on ``standard_id`` (rather than ``id``) is intentional:
        # the platform identity of an indicator is its ``standard_id``,
        # which is what every other emit / lookup uses, and a future
        # change to how we list YARA indicators would not silently break
        # the dedup contract.
        propagated_indicator_ids: set[str] = set()
        errors = []
        for artifact_content in artifact_contents:
            for indicator in yara_indicators:
                try:
                    rule_content = indicator["pattern"]
                    rule = yara.compile(source=rule_content)
                except yara.SyntaxError as e:
                    msg = f"YARA syntax error in rule '{indicator['name']}': {e}"
                    self.helper.connector_logger.error(msg)
                    errors.append(msg)
                    continue

                results = rule.match(data=artifact_content, timeout=60)
                if not results:
                    continue

                marking_refs = self._collect_marking_refs(artifact, indicator)
                relationship = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to",
                        artifact["standard_id"],
                        indicator["standard_id"],
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.author["id"],
                    source_ref=artifact["standard_id"],
                    target_ref=indicator["standard_id"],
                    description="YARA rule matched for this Artifact",
                )
                if marking_refs:
                    relationship = relationship.new_version(
                        object_marking_refs=marking_refs
                    )
                bundle_objects.append(relationship)
                # Include matched indicator in bundle so cleanup_inconsistent_bundle
                # does not remove the relationship referencing it
                if indicator["standard_id"] not in matched_indicators:
                    matched_indicators[indicator["standard_id"]] = stix2.Indicator(
                        id=indicator["standard_id"],
                        name=indicator["name"],
                        pattern=indicator["pattern"],
                        pattern_type=indicator["pattern_type"],
                        valid_from=indicator["valid_from"],
                    )
                self.helper.connector_logger.debug(
                    f"Created Relationship from Artifact to YARA Indicator {indicator['name']}"
                )

                # Run the optional propagation side-effects at most once
                # per Artifact / Indicator pair (the loop above repeats
                # the match for every file under the same artifact).
                if indicator["standard_id"] in propagated_indicator_ids:
                    continue
                propagated_indicator_ids.add(indicator["standard_id"])

                # Optional: propagate every label carried by the matching
                # YARA indicator onto the enriched artifact. Labels are read
                # straight off the indicator (``objectLabel`` is requested in
                # ``_get_yara_indicators``'s ``customAttributes``) so no extra
                # API round-trip is needed per indicator.
                if self.config.yara.propagate_labels:
                    self._propagate_labels(artifact, indicator)

                # Optional: follow every ``indicates`` relationship from the
                # matching YARA indicator to Malware entities and emit a
                # ``related-to`` STIX relationship from the artifact to each
                # of those malware entities, so the artifact's knowledge
                # graph directly shows the malware family the YARA rule was
                # authored against.
                if self.config.yara.propagate_malware_relationship:
                    bundle_objects.extend(
                        self._build_malware_relationships(
                            artifact, indicator, marking_refs
                        )
                    )

        return bundle_objects + list(matched_indicators.values()), errors

    def _propagate_labels(self, artifact: dict, indicator: dict) -> None:
        """Copy every label of ``indicator`` onto ``artifact``.

        Labels are read from the in-memory ``indicator["objectLabel"]``
        list (loaded by :meth:`_get_yara_indicators` via the GraphQL
        ``customAttributes``). Each label is added through the
        ``stix_cyber_observable.add_label`` mutation — using the
        side-channel API here is intentional because the artifact
        already exists in OpenCTI and we only want to mutate its label
        set, not re-emit a full STIX object that would also have to
        carry every other property.

        Malformed ``objectLabel`` entries (non-dict items or dicts
        missing the ``id`` field) are logged at ``warning`` level so an
        operator can spot a malformed payload coming back from the
        platform; per-label API failures are logged at ``error`` level.
        In both cases the loop continues so a single bad label does not
        abort the rest of the scan.
        """
        artifact_ref = artifact.get("observable_value", artifact.get("id"))
        indicator_name = indicator.get("name")
        labels = indicator.get("objectLabel") or []
        for label in labels:
            if not isinstance(label, dict):
                self.helper.connector_logger.warning(
                    "Skipping malformed objectLabel entry (not a dict)",
                    meta={
                        "label": repr(label)[:80],
                        "indicator": indicator_name,
                        "artifact": artifact_ref,
                    },
                )
                continue
            label_id = label.get("id")
            if not label_id:
                self.helper.connector_logger.warning(
                    "Skipping objectLabel entry without 'id'",
                    meta={
                        "label": label.get("value"),
                        "indicator": indicator_name,
                        "artifact": artifact_ref,
                    },
                )
                continue
            try:
                self.helper.api.stix_cyber_observable.add_label(
                    id=artifact["id"], label_id=label_id
                )
            except Exception as exc:  # noqa: BLE001 - we only want to log
                self.helper.connector_logger.error(
                    "Error propagating label from YARA Indicator to Artifact",
                    meta={
                        "label": label.get("value", label_id),
                        "indicator": indicator_name,
                        "artifact": artifact_ref,
                        "error": str(exc),
                    },
                )

    def _build_malware_relationships(
        self, artifact: dict, indicator: dict, marking_refs
    ) -> list:
        """Return STIX objects propagating the Malware link onto ``artifact``.

        For every Malware entity that ``indicator`` ``indicates`` we
        emit two things:

        * the target ``stix2.Malware`` SDO (deduplicated by
          ``standard_id``) so ``send_stix2_bundle(...,
          cleanup_inconsistent_bundle=True)`` does not drop the
          relationship as "inconsistent" when the Malware is not yet
          present in the bundle the caller built for this enrichment;
        * the ``related-to`` STIX relationship from ``artifact`` to
          the Malware (carrying ``marking_refs`` so it inherits the
          Artifact -> Indicator TLP markings).

        Only ``indicates`` relationships are considered: a stray
        ``related-to`` / ``part-of`` leaving the indicator must not
        pull in malware the YARA rule does not actually indicate.

        The Malware SDO is built from the fields returned by
        :data:`_INDICATES_MALWARE_LIST_ATTRIBUTES` (``name``,
        ``is_family``, ``description``). ``standard_id`` is used as
        the SDO id so the platform merges by id on ingestion and the
        existing Malware entity is not overwritten (only linked).

        The Malware SDO is deliberately emitted **without**
        ``object_marking_refs``. The SDO's only purpose is to keep the
        bundle self-consistent for
        ``cleanup_inconsistent_bundle=True``; the OpenCTI ingestion
        path merges by ``standard_id``, so attaching markings would
        propagate the Artifact / Indicator TLP onto the existing
        Malware entity (potentially over-restricting an entity that
        is shared across the platform). The TLP markings stay on the
        Artifact -> Malware ``related-to`` relationship, which is the
        new object actually owned by this enrichment cycle.
        """
        indicator_name = indicator.get("name")
        try:
            relationships = self.helper.api.stix_core_relationship.list(
                fromId=indicator["id"],
                relationship_type="indicates",
                toTypes=["Malware"],
                customAttributes=_INDICATES_MALWARE_LIST_ATTRIBUTES,
            )
        except Exception as exc:  # noqa: BLE001
            self.helper.connector_logger.error(
                "Error listing 'indicates' relationships from YARA Indicator",
                meta={"indicator": indicator_name, "error": str(exc)},
            )
            return []

        out: list = []
        seen_malware_ids: set[str] = set()
        for rel in relationships or []:
            target = (rel.get("to") or {}) if isinstance(rel, dict) else {}
            malware_standard_id = target.get("standard_id")
            if not malware_standard_id:
                continue
            try:
                # Emit the Malware SDO once per cycle so the
                # Artifact -> Malware relationship survives
                # ``cleanup_inconsistent_bundle=True``. ``standard_id``
                # matches the existing entity in OpenCTI so the
                # ingestion path links / merges, not creates a new SDO.
                # We intentionally do not set ``object_marking_refs``
                # here so the merge does not pollute the existing
                # Malware entity's markings; the Artifact -> Malware
                # ``related-to`` relationship carries ``marking_refs``
                # instead.
                if malware_standard_id not in seen_malware_ids:
                    seen_malware_ids.add(malware_standard_id)
                    malware_name = target.get("name") or malware_standard_id
                    malware_description = target.get("description") or None
                    out.append(
                        stix2.Malware(
                            id=malware_standard_id,
                            name=malware_name,
                            is_family=bool(target.get("is_family", False)),
                            description=malware_description,
                            allow_custom=True,
                        )
                    )

                malware_relationship = Relationship(
                    id=StixCoreRelationship.generate_id(
                        "related-to",
                        artifact["standard_id"],
                        malware_standard_id,
                    ),
                    relationship_type="related-to",
                    created_by_ref=self.author["id"],
                    source_ref=artifact["standard_id"],
                    target_ref=malware_standard_id,
                    description=(
                        "Artifact matched a YARA Indicator that indicates "
                        "this Malware"
                    ),
                )
                if marking_refs:
                    malware_relationship = malware_relationship.new_version(
                        object_marking_refs=marking_refs
                    )
                out.append(malware_relationship)
                self.helper.connector_logger.debug(
                    "Propagated Artifact -> Malware relationship",
                    meta={
                        "artifact": artifact["standard_id"],
                        "malware": malware_standard_id,
                        "indicator": indicator_name,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                self.helper.connector_logger.error(
                    "Error building Artifact -> Malware relationship",
                    meta={"indicator": indicator_name, "error": str(exc)},
                )
        return out

    def _process_message(self, data: dict) -> str:
        entity_id = data["entity_id"]
        stix_objects = data.get("stix_objects", [])

        # Preserve original file name to avoid artifact.bin fallback in pycti
        # Artifact naming relies on the presence of `x_opencti_additional_names`
        # but this field is not provided in the enrichment message from OpenCTI.
        if data.get("entity_type") == "Artifact":
            stix_entity = data.get("stix_entity", {})
            x_opencti_files = stix_entity.get("x_opencti_files", [])
            if x_opencti_files:
                file_name = x_opencti_files[0].get("name")
                if file_name:
                    for obj in stix_objects:
                        if isinstance(obj, dict) and obj.get("id") == entity_id:
                            self.helper.connector_logger.info(
                                f"Setting x_opencti_additional_names for Artifact {entity_id} to preserve original file name: {file_name}"
                            )
                            obj.setdefault("x_opencti_additional_names", [file_name])
                            break

        # Check scope — forward original bundle if entity type is out of scope
        entity_type = data.get("entity_type")
        if entity_type not in self.config.connector.scope:
            self.helper.connector_logger.info(
                "Entity type not in connector scope, forwarding original bundle",
                meta={"entity_id": entity_id, "entity_type": entity_type},
            )
            bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)
            return "Entity type not in scope"

        self.helper.connector_logger.info(f"Enriching {entity_id}")
        artifact = data["enrichment_entity"]
        self.helper.connector_logger.info(f"Artifact to enrich: {artifact}")

        yara_indicators = self._get_yara_indicators()
        if not yara_indicators:
            self.helper.connector_logger.debug("No YARA Indicators to match")
            bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)
            return "No YARA Indicators to match"

        rule_count = len(yara_indicators)
        self.helper.connector_logger.debug(
            f"Scanning an Artifact with {rule_count} rules"
        )
        new_objects, errors = self._scan_artifact(artifact, yara_indicators)

        if new_objects:
            all_objects = stix_objects + [self.author] + new_objects
        else:
            all_objects = stix_objects
        self.helper.connector_logger.debug(
            f"Sending {len(all_objects)} new relationships to OpenCTI"
        )
        bundle = self.helper.stix2_create_bundle(all_objects)
        self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)

        if errors:
            return f"Completed with {len(errors)} YARA error(s): {'; '.join(errors)}"

        return "Done"

    # Start the main loop
    def start(self) -> None:
        self.helper.connector_logger.info("YARA connector started")
        self.helper.listen(message_callback=self._process_message)
