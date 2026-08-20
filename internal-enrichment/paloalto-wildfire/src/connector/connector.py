from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import urljoin

import stix2
from connector.settings import ConnectorSettings
from paloalto_wildfire_client import PaloaltoWildfireClient, WildfireAPIError
from pycti import (
    Identity,
    MalwareAnalysis,
    MarkingDefinition,
    OpenCTIConnectorHelper,
)

# WildFire verdict code -> human readable label.
_VERDICT_LABELS = {
    0: "benign",
    1: "malware",
    2: "grayware",
    4: "phishing",
    5: "command-and-control",
}

# WildFire verdict code -> OpenCTI score (0-100).
_VERDICT_SCORES = {
    0: 10,
    1: 90,
    2: 40,
    4: 80,
    5: 95,
}

# WildFire verdict code -> STIX malware-analysis result (malware-result-ov).
_VERDICT_RESULTS = {
    0: "benign",
    1: "malicious",
    2: "suspicious",
    4: "malicious",
    5: "malicious",
}

# Preference order when several hashes are available on the observable.
_HASH_PRIORITY = {"SHA-256": 3, "SHA-1": 2, "MD5": 1}


def _custom_tlp(definition: str) -> stix2.MarkingDefinition:
    # OpenCTI models TLP:CLEAR and TLP:AMBER+STRICT as custom statement markings,
    # not as the legacy STIX markings; using TLP_WHITE etc. would emit the wrong
    # marking id in the bundle.
    return stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", definition),
        definition_type="statement",
        definition={"statement": "custom"},
        custom_properties={
            "x_opencti_definition_type": "TLP",
            "x_opencti_definition": definition,
        },
    )


def _tlp_marking(definition: str):
    """Return the stix2 MarkingDefinition for a TLP definition string, or None."""
    standard = {
        "TLP:WHITE": stix2.TLP_WHITE,
        "TLP:GREEN": stix2.TLP_GREEN,
        "TLP:AMBER": stix2.TLP_AMBER,
        "TLP:RED": stix2.TLP_RED,
    }
    if definition in standard:
        return standard[definition]
    if definition in ("TLP:CLEAR", "TLP:AMBER+STRICT"):
        return _custom_tlp(definition)
    return None


class PaloaltoWildfireConnector:
    """
    Internal-enrichment connector that enriches file observables with Palo Alto
    Networks WildFire verdicts.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = PaloaltoWildfireClient(
            helper,
            api_key=self.config.paloalto_wildfire.api_key.get_secret_value(),
            base_url=self.config.paloalto_wildfire.api_base_url,
        )
        self.max_tlp = self.config.paloalto_wildfire.max_tlp
        self.max_file_size = self.config.paloalto_wildfire.max_file_size

        self.identity = stix2.Identity(
            id=Identity.generate_id(
                name="Palo Alto Networks WildFire", identity_class="organization"
            ),
            name="Palo Alto Networks WildFire",
            identity_class="organization",
            description="File verdicts from Palo Alto Networks WildFire.",
        )
        self.tlp = _custom_tlp("TLP:CLEAR")
        self.stix_objects: list = []

    @staticmethod
    def _extract_hash(opencti_entity: dict):
        best = None
        best_rank = 0
        for entry in opencti_entity.get("hashes", []) or []:
            rank = _HASH_PRIORITY.get(entry.get("algorithm"), 0)
            if rank > best_rank:
                best = entry.get("hash")
                best_rank = rank
        return best

    def _search_hash(self, opencti_entity: dict):
        """Look up the WildFire verdict (and report) for an observable's hash."""
        file_hash = self._extract_hash(opencti_entity)
        if not file_hash:
            self.helper.connector_logger.info("No usable hash on the observable.")
            return None
        verdict = self.client.get_verdict(file_hash)
        if verdict is None:
            self.helper.connector_logger.info(
                "Hash unknown to WildFire.", meta={"hash": file_hash}
            )
            return None
        report = self.client.get_report(file_hash) or {}
        return {"verdict": verdict, "hash": file_hash, "report": report}

    def _download_file(self, opencti_entity: dict):
        """
        Download the file attached to an observable from OpenCTI storage.

        Returns a ``(filename, content, error)`` tuple. On success ``error`` is
        ``None``; on failure ``content`` is ``None`` and ``error`` is a
        human-readable reason (enforces ``max_file_size`` and rejects empty files).
        """
        import_files = opencti_entity.get("importFiles") or []
        if not import_files:
            return None, None, "No file attached to the observable."
        file_entry = import_files[0]
        file_id = file_entry.get("id")
        if not file_id:
            return None, None, "Attached file has no id."

        file_name = file_entry.get("name", "artifact")
        max_mb = round(self.max_file_size / (1024 * 1024), 1)

        declared_size = file_entry.get("size")
        if declared_size is not None and int(declared_size) > self.max_file_size:
            return None, None, f"File '{file_name}' exceeds the {max_mb} MB limit."

        file_url = urljoin(str(self.config.opencti.url), f"storage/get/{file_id}")
        content = self.helper.api.fetch_opencti_file(file_url, True)
        if content is None:
            return None, None, f"Failed to download file '{file_name}' from OpenCTI."
        if len(content) == 0:
            return None, None, f"File '{file_name}' is empty (0 bytes)."
        if len(content) > self.max_file_size:
            return None, None, f"File '{file_name}' exceeds the {max_mb} MB limit."
        return file_name, content, None

    def _submit(self, opencti_entity: dict):
        """Submit the observable's file to WildFire and poll for a verdict."""
        file_name, content, error = self._download_file(opencti_entity)
        if error:
            self.helper.connector_logger.info(
                "Skipping WildFire submission.", meta={"reason": error}
            )
            return None
        sha256 = self.client.submit_file(file_name, content)
        if not sha256:
            self.helper.connector_logger.warning(
                "WildFire did not return a sample id for the submitted file."
            )
            return None
        self.helper.connector_logger.info(
            "Submitted file to WildFire, waiting for verdict.", meta={"sha256": sha256}
        )
        verdict = self.client.poll_verdict(
            sha256, max_wait=self.config.paloalto_wildfire.submission_timeout
        )
        if verdict is None:
            return None
        report = self.client.get_report(sha256) or {}
        return {"verdict": verdict, "hash": sha256, "report": report}

    def _create_knowledge(
        self, stix_entity: dict, opencti_entity: dict, result: dict
    ) -> list:
        """Create the STIX objects enriching the observable from a WildFire result."""
        verdict = result["verdict"]
        report = result.get("report", {})

        enriched_entity = deepcopy(stix_entity)
        enriched_objects = [
            enriched_entity if obj["id"] == enriched_entity["id"] else obj
            for obj in self.stix_objects
        ]

        label = _VERDICT_LABELS.get(verdict, "unknown")
        score = _VERDICT_SCORES.get(verdict)

        if opencti_entity["entity_type"] in ["StixFile", "Artifact"]:
            hashes = enriched_entity.get("hashes", {})
            if report.get("md5"):
                hashes["MD5"] = report["md5"]
            if report.get("sha1"):
                hashes["SHA-1"] = report["sha1"]
            if report.get("sha256"):
                hashes["SHA-256"] = report["sha256"]
            if hashes:
                enriched_entity["hashes"] = hashes

        if opencti_entity["entity_type"] == "StixFile" and report.get("size"):
            try:
                enriched_entity["size"] = int(report["size"])
            except (TypeError, ValueError):
                pass

        if (
            opencti_entity["entity_type"] == "StixFile"
            and report.get("filetype")
            and not enriched_entity.get("mime_type")
        ):
            # Complete the file type from the WildFire report (mapped onto the STIX
            # File mime_type field) when the observable does not already carry one.
            enriched_entity["mime_type"] = report["filetype"]

        if score is not None:
            enriched_entity["x_opencti_score"] = score

        labels = enriched_entity.get("labels") or []
        wildfire_label = f"wildfire:{label}"
        if wildfire_label not in labels:
            labels.append(wildfire_label)
        enriched_entity["labels"] = labels

        result_name = "WildFire " + (
            result.get("hash") or opencti_entity.get("observable_value", "")
        )
        external_reference = stix2.ExternalReference(
            source_name="Palo Alto Networks WildFire",
            url="https://wildfire.paloaltonetworks.com/",
            external_id=report.get("sha256") or result.get("hash"),
            description=f"WildFire verdict: {label}",
        )
        # Derive the marking from the source observable's OpenCTI markings.
        # Enrichment messages carry them in opencti_entity["objectMarking"], not
        # always as STIX object_marking_refs on the observable, so reading the STIX
        # field would silently downgrade the Malware Analysis object to the default
        # TLP. Include the resolved marking objects in the bundle so the SDO is
        # correctly marked and self-contained (not stripped by
        # cleanup_inconsistent_bundle). Fall back to TLP:CLEAR when none is present.
        source_markings: list = []
        for marking_definition in opencti_entity.get("objectMarking") or []:
            if marking_definition.get("definition_type") == "TLP":
                marking = _tlp_marking(marking_definition.get("definition"))
                if marking is not None and marking not in source_markings:
                    source_markings.append(marking)
        if not source_markings:
            source_markings = [self.tlp]
        malware_analysis = stix2.MalwareAnalysis(
            id=MalwareAnalysis.generate_id(result_name, "WildFire"),
            product="WildFire",
            result_name=result_name,
            analysis_started=datetime.now(tz=timezone.utc),
            submitted=datetime.now(tz=timezone.utc),
            result=_VERDICT_RESULTS.get(verdict, "unknown"),
            sample_ref=enriched_entity["id"],
            created_by_ref=self.identity.id,
            object_marking_refs=[marking.id for marking in source_markings],
            external_references=[external_reference],
        )
        enriched_objects.append(malware_analysis)

        return [self.identity] + source_markings + enriched_objects

    def _process_observable(self, stix_entity: dict, opencti_entity: dict):
        self.helper.connector_logger.info(
            "Processing the observable",
            meta={
                "observable_type": opencti_entity["entity_type"],
                "observable_value": opencti_entity.get("observable_value"),
            },
        )
        if opencti_entity["entity_type"] in ["StixFile", "Artifact"]:
            result = self._search_hash(opencti_entity)
            if result is None and self.config.paloalto_wildfire.submit_unknown:
                result = self._submit(opencti_entity)
            if result is None:
                return None
            return self._create_knowledge(stix_entity, opencti_entity, result)
        return None

    def _send_bundle(self, stix_objects: list) -> list:
        if len(stix_objects) == 0:
            return []
        bundle = self.helper.stix2_create_bundle(stix_objects)
        return self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)

    def _process_message(self, data: dict) -> str:
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]
        opencti_entity = data["enrichment_entity"]

        self.stix_objects = stix_objects
        original_stix_objects = deepcopy(stix_objects)

        tlp = "TLP:CLEAR"
        for marking_definition in opencti_entity["objectMarking"]:
            if marking_definition["definition_type"] == "TLP":
                tlp = marking_definition["definition"]

        try:
            if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
                self._send_bundle(original_stix_objects)
                message = "Do not send any data, TLP of the observable is greater than MAX TLP"
                self.helper.connector_logger.info(f"[CONNECTOR] {message}")
                return message

            if opencti_entity["entity_type"] not in ["StixFile", "Artifact"]:
                if not data.get("event_type"):
                    # Entity bundle passed through a playbook: return the original
                    # bundle unchanged when the entity is not in the connector scope.
                    self._send_bundle(original_stix_objects)
                    message = (
                        "Observable not in connector scope, original bundle returned"
                    )
                    self.helper.connector_logger.info(f"[CONNECTOR] {message}")
                    return message
                raise ValueError(
                    f"Failed to process observable, {opencti_entity['entity_type']} "
                    "is not a supported entity type."
                )

            enriched_objects = self._process_observable(stix_entity, opencti_entity)
            if enriched_objects:
                bundles_sent = self._send_bundle(enriched_objects)
                message = f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
                self.helper.connector_logger.info(message)
                return message

            message = "No WildFire verdict found for the observable"
            self.helper.connector_logger.info(message)
            self._send_bundle(original_stix_objects)
            return message

        except WildfireAPIError as err:
            self.helper.connector_logger.error(
                f"[CONNECTOR] {err.__class__.__name__}: {str(err)}"
            )
            self._send_bundle(original_stix_objects)
            raise
        except Exception as err:
            self.helper.connector_logger.error(
                "[CONNECTOR] An unexpected error occurred", meta={"error": str(err)}
            )
            self._send_bundle(original_stix_objects)
            raise

    def run(self) -> None:
        self.helper.listen(message_callback=self._process_message)
