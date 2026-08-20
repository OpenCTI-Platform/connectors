from copy import deepcopy
from datetime import datetime, timezone

import stix2
from connector.settings import ConnectorSettings
from fortisandbox_client import FortiSandboxAPIError, FortisandboxClient
from pycti import (
    Identity,
    MalwareAnalysis,
    MarkingDefinition,
    OpenCTIConnectorHelper,
)

# FortiSandbox rating -> OpenCTI score (0-100).
_RATING_SCORES = {
    "malicious": 90,
    "high risk": 80,
    "medium risk": 60,
    "suspicious": 60,
    "low risk": 40,
    "clean": 10,
}

# FortiSandbox rating -> STIX malware-analysis result (malware-result-ov).
_RATING_RESULTS = {
    "malicious": "malicious",
    "high risk": "malicious",
    "medium risk": "suspicious",
    "suspicious": "suspicious",
    "low risk": "suspicious",
    "clean": "benign",
}


def _custom_tlp(definition: str) -> stix2.MarkingDefinition:
    # OpenCTI models TLP:CLEAR and TLP:AMBER+STRICT as custom statement markings,
    # not as the legacy STIX markings. The x_opencti_* fields require
    # allow_custom=True (matching connectors-sdk's TLPMarking.to_stix2_object).
    return stix2.MarkingDefinition(
        id=MarkingDefinition.generate_id("TLP", definition),
        definition_type="statement",
        definition={"statement": "custom"},
        allow_custom=True,
        x_opencti_definition_type="TLP",
        x_opencti_definition=definition,
    )


def _tlp_clear() -> stix2.MarkingDefinition:
    return _custom_tlp("TLP:CLEAR")


# Plain STIX markings cover these levels; CLEAR / AMBER+STRICT are custom (above).
_STIX_TLP_MARKINGS = {
    "TLP:WHITE": stix2.TLP_WHITE,
    "TLP:GREEN": stix2.TLP_GREEN,
    "TLP:AMBER": stix2.TLP_AMBER,
    "TLP:RED": stix2.TLP_RED,
}


class FortisandboxConnector:
    """
    Internal-enrichment connector that enriches file observables with FortiSandbox
    ratings (and, optionally, submits unknown files for on-demand analysis).
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper

        self.client = FortisandboxClient(
            helper,
            api_base_url=self.config.fortisandbox.api_base_url,
            username=self.config.fortisandbox.username,
            password=self.config.fortisandbox.password.get_secret_value(),
            api_version=self.config.fortisandbox.api_version,
            ssl_verify=self.config.fortisandbox.ssl_verify,
        )
        self.max_tlp = self.config.fortisandbox.max_tlp
        self.max_file_size = self.config.fortisandbox.max_file_size

        self.identity = stix2.Identity(
            id=Identity.generate_id(name="FortiSandbox", identity_class="organization"),
            name="FortiSandbox",
            identity_class="organization",
            description="File verdicts from Fortinet FortiSandbox.",
        )
        self.tlp = _tlp_clear()
        self.stix_objects: list = []

    def _marking_for(self, definition: str) -> stix2.MarkingDefinition:
        """Resolve a TLP definition string to its STIX marking object."""
        if definition == "TLP:CLEAR":
            return self.tlp
        if definition == "TLP:AMBER+STRICT":
            return _custom_tlp("TLP:AMBER+STRICT")
        return _STIX_TLP_MARKINGS.get(definition, self.tlp)

    def _observable_markings(self, opencti_entity: dict) -> list:
        """
        Return the source observable's markings so the enrichment inherits them
        instead of downgrading to the connector default. OpenCTI enrichment
        payloads expose markings on ``objectMarking`` (not always on the STIX
        ``object_marking_refs``); fall back to the connector default when none.
        """
        markings = [
            self._marking_for(md["definition"])
            for md in opencti_entity.get("objectMarking") or []
            if md.get("definition_type") == "TLP" and md.get("definition")
        ]
        return markings or [self.tlp]

    @staticmethod
    def _extract_hash(opencti_entity: dict):
        by_algo = {}
        for entry in opencti_entity.get("hashes", []) or []:
            algo = entry.get("algorithm")
            if algo:
                by_algo[algo] = entry.get("hash")
        if by_algo.get("SHA-256"):
            return by_algo["SHA-256"], "sha256"
        if by_algo.get("SHA-1"):
            return by_algo["SHA-1"], "sha1"
        if by_algo.get("MD5"):
            return by_algo["MD5"], "md5"
        return None, None

    def _search_hash(self, opencti_entity: dict):
        file_hash, ctype = self._extract_hash(opencti_entity)
        if not file_hash:
            self.helper.connector_logger.info("No usable hash on the observable.")
            return None
        data = self.client.get_file_rating(file_hash, ctype=ctype)
        if not data:
            return None
        rating = str(data.get("rating") or "").strip()
        if not rating or rating.lower() == "unknown":
            return None
        return data

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

        api_url = self.helper.api.api_url.replace("/graphql", "")
        file_uri = f"{api_url}/storage/get/{file_id}"
        content = self.helper.api.fetch_opencti_file(file_uri, True)
        if content is None:
            return None, None, f"Failed to download file '{file_name}' from OpenCTI."
        if len(content) == 0:
            return None, None, f"File '{file_name}' is empty (0 bytes)."
        if len(content) > self.max_file_size:
            return None, None, f"File '{file_name}' exceeds the {max_mb} MB limit."
        return file_name, content, None

    def _submit(self, opencti_entity: dict):
        file_name, content, error = self._download_file(opencti_entity)
        if error:
            self.helper.connector_logger.info(
                "Skipping FortiSandbox submission.", meta={"reason": error}
            )
            return None
        sid = self.client.submit_file(file_name, content)
        if not sid:
            self.helper.connector_logger.warning(
                "FortiSandbox did not return a submission id."
            )
            return None
        self.helper.connector_logger.info(
            "Submitted file to FortiSandbox, waiting for verdict.", meta={"sid": sid}
        )
        return self.client.get_submission_verdict(
            sid, max_wait=self.config.fortisandbox.submission_timeout
        )

    def _create_knowledge(
        self, stix_entity: dict, opencti_entity: dict, data: dict
    ) -> list:
        rating = str(data.get("rating") or "").strip()
        key = rating.lower()
        score = _RATING_SCORES.get(key)

        enriched_entity = deepcopy(stix_entity)
        enriched_objects = [
            enriched_entity if obj["id"] == enriched_entity["id"] else obj
            for obj in self.stix_objects
        ]

        if opencti_entity["entity_type"] in ["StixFile", "Artifact"]:
            hashes = enriched_entity.get("hashes", {})
            if data.get("sha256"):
                hashes["SHA-256"] = data["sha256"]
            if data.get("sha1"):
                hashes["SHA-1"] = data["sha1"]
            if data.get("md5"):
                hashes["MD5"] = data["md5"]
            if hashes:
                enriched_entity["hashes"] = hashes

        if score is not None:
            enriched_entity["x_opencti_score"] = score

        labels = enriched_entity.get("labels") or []
        rating_label = f"fortisandbox:{key}" if key else "fortisandbox:unknown"
        if rating_label not in labels:
            labels.append(rating_label)
        if data.get("malware_name"):
            malware_label = f"malware:{data['malware_name']}"
            if malware_label not in labels:
                labels.append(malware_label)
        enriched_entity["labels"] = labels

        result_name = "FortiSandbox " + (
            data.get("sha256") or opencti_entity.get("observable_value", "")
        )
        if data.get("detail_url"):
            external_reference = stix2.ExternalReference(
                source_name="FortiSandbox",
                url=data["detail_url"],
                description=f"FortiSandbox rating: {rating}",
            )
        elif data.get("sha256"):
            external_reference = stix2.ExternalReference(
                source_name="FortiSandbox",
                external_id=data["sha256"],
                description=f"FortiSandbox rating: {rating}",
            )
        else:
            external_reference = stix2.ExternalReference(
                source_name="FortiSandbox",
                description=f"FortiSandbox rating: {rating}",
            )

        # Inherit the source observable's markings so the enrichment never produces
        # an unmarked / TLP-downgraded Malware Analysis object; fall back to the
        # connector default marking when the observable carries none.
        markings = self._observable_markings(opencti_entity)
        malware_analysis = stix2.MalwareAnalysis(
            id=MalwareAnalysis.generate_id(result_name, "FortiSandbox"),
            product="FortiSandbox",
            result_name=result_name,
            analysis_started=datetime.now(tz=timezone.utc),
            submitted=datetime.now(tz=timezone.utc),
            result=_RATING_RESULTS.get(key, "unknown"),
            sample_ref=enriched_entity["id"],
            created_by_ref=self.identity.id,
            object_marking_refs=markings,
            external_references=[external_reference],
        )
        enriched_objects.append(malware_analysis)

        # Include the marking objects themselves so the refs resolve in the bundle.
        return [self.identity] + markings + enriched_objects

    def _process_observable(self, stix_entity: dict, opencti_entity: dict):
        self.helper.connector_logger.info(
            "Processing the observable",
            meta={
                "observable_type": opencti_entity["entity_type"],
                "observable_value": opencti_entity.get("observable_value"),
            },
        )
        if opencti_entity["entity_type"] not in ["StixFile", "Artifact"]:
            return None

        data = self._search_hash(opencti_entity)
        if data is None and self.config.fortisandbox.submit_unknown:
            data = self._submit(opencti_entity)
        if not data:
            return None
        return self._create_knowledge(stix_entity, opencti_entity, data)

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

        if opencti_entity["entity_type"] not in ["StixFile", "Artifact"]:
            # A missing event_type means the enrichment was triggered by a playbook:
            # return the original bundle unchanged so the playbook can continue.
            if not data.get("event_type"):
                self._send_bundle(original_stix_objects)
                message = (
                    "Entity type is out of the connector scope, "
                    "original bundle returned unchanged"
                )
                self.helper.connector_logger.info(f"[CONNECTOR] {message}")
                return message
            raise ValueError(
                f"Failed to process observable, "
                f"{opencti_entity['entity_type']} is not a supported entity type."
            )

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

            enriched_objects = self._process_observable(stix_entity, opencti_entity)
            if enriched_objects:
                bundles_sent = self._send_bundle(enriched_objects)
                message = f"Sent {len(bundles_sent)} stix bundle(s) for worker import"
                self.helper.connector_logger.info(message)
                return message

            message = "No FortiSandbox verdict found for the observable"
            self.helper.connector_logger.info(message)
            self._send_bundle(original_stix_objects)
            return message

        except FortiSandboxAPIError as err:
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
