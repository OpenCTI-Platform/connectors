from typing import Any

from connector.converter_to_stix import (
    TLP_RANK,
    ConverterToStix,
    intelowl_tlp,
    observable_to_intelowl,
)
from connector.settings import ConnectorSettings
from intelowl_client import IntelOwlClient, IntelOwlClientError
from pycti import OpenCTIConnectorHelper


class IntelOwlConnector:
    """Enrich observables by running an IntelOwl playbook on them.

    For each observable in scope, the connector starts the configured playbook in IntelOwl,
    waits for the job to finish, and sends back:

    - a Note on the observable with IntelOwl's verdict and each analyzer's status,
      linked to the job in IntelOwl,
    - the observable's score from the verdict, and IntelOwl's tags as labels (both optional),
    - a Malware entity and a `related-to` relationship when IntelOwl names a malware family.

    Every bundle includes the original `stix_objects`, so the connector works in playbooks.
    """

    def __init__(
        self,
        config: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
        client: IntelOwlClient | None = None,
    ) -> None:
        self.config = config
        self.helper = helper
        self.client = client or IntelOwlClient(
            base_url=str(config.intelowl.url),
            api_key=config.intelowl.api_key.get_secret_value(),
            verify_ssl=config.intelowl.verify_ssl,
        )

    def _entity_in_scope(self, opencti_entity: dict[str, Any]) -> bool:
        # Compare OpenCTI entity types (e.g. `StixFile`), not STIX ID prefixes (`file--`)
        scopes = self.helper.connect_scope.lower().replace(" ", "").split(",")
        return (opencti_entity.get("entity_type") or "").lower() in scopes

    @staticmethod
    def _entity_tlp(
        opencti_entity: dict[str, Any],
        stix_entity: dict[str, Any] | None = None,
        stix_objects: list[Any] | None = None,
    ) -> str | None:
        """The most restrictive TLP on the observable, whatever the marking order.

        Both the OpenCTI entity's markings and the STIX observable's
        `object_marking_refs` (resolved against marking definitions in the bundle,
        as a playbook may send them) are considered.
        """
        tlps = [
            marking["definition"]
            for marking in opencti_entity.get("objectMarking") or []
            if marking.get("definition_type") == "TLP" and marking.get("definition")
        ]
        refs = set((stix_entity or {}).get("object_marking_refs") or [])
        for obj in stix_objects or []:
            if not isinstance(obj, dict) or obj.get("id") not in refs:
                continue
            name = obj.get("name") or ""
            definition = obj.get("definition") or {}
            if name.upper().startswith("TLP:"):
                tlps.append(name)
            elif isinstance(definition, dict) and definition.get("tlp"):
                tlps.append(f"TLP:{definition['tlp']}")
        if not tlps:
            return None
        # An unknown TLP name is treated as RED rather than guessed at.
        return max(
            (tlp.upper() if tlp.upper() in TLP_RANK else "TLP:RED" for tlp in tlps),
            key=TLP_RANK.__getitem__,
        )

    def _send_bundle(self, stix_objects: list[Any]) -> str:
        bundle = self.helper.stix2_create_bundle(stix_objects)
        bundles_sent = self.helper.send_stix2_bundle(
            bundle, cleanup_inconsistent_bundle=True
        )
        return f"Sending {len(bundles_sent)} STIX bundle(s) for worker import"

    def process_message(self, data: dict[str, Any]) -> str:
        """Enrich one observable. Called by the helper for every enrichment request.

        A failure is raised so it shows on the work in OpenCTI, except when the request
        comes from a playbook: then the original bundle is sent back so the playbook continues.
        """
        try:
            return self._enrich(data)
        except Exception as err:
            if data.get("event_type"):
                raise
            self.helper.connector_logger.warning(
                "Enrichment failed, returning the playbook bundle unchanged",
                {"entity_id": data.get("entity_id"), "error": str(err)},
            )
            return self._send_bundle(data["stix_objects"])

    def _enrich(self, data: dict[str, Any]) -> str:
        opencti_entity = data["enrichment_entity"]
        stix_objects = data["stix_objects"]
        stix_entity = data["stix_entity"]

        if not self._entity_in_scope(opencti_entity):
            if not data.get("event_type"):
                # From a playbook: hand the bundle back unchanged so the playbook continues
                return self._send_bundle(stix_objects)
            raise ValueError(
                f"Failed to process observable, {opencti_entity['entity_type']} is not a supported entity type."
            )

        entity_tlp = self._entity_tlp(opencti_entity, stix_entity, stix_objects)
        max_tlp = f"TLP:{self.config.connector.max_tlp.upper()}"
        if not self.helper.check_max_tlp(entity_tlp, max_tlp):
            raise ValueError(
                "Do not send any data, TLP of the observable is greater than MAX TLP, "
                "the connector does not have access to this observable, please check the group of the connector user"
            )

        target = observable_to_intelowl(stix_entity)
        if target is None:
            self.helper.connector_logger.warning(
                "Observable has no value IntelOwl can analyze, skipping",
                {"entity_id": data["entity_id"]},
            )
            return self._send_bundle(stix_objects)
        classification, value = target

        playbook = self.config.intelowl.playbook
        try:
            job_id = self.client.analyze_observable(
                value=value,
                classification=classification,
                playbook=playbook,
                tlp=intelowl_tlp(entity_tlp),
                tags=["opencti"],
            )
            self.helper.connector_logger.info(
                "IntelOwl job started",
                {
                    "job_id": job_id,
                    "playbook": playbook,
                    "classification": classification,
                },
            )
            job = self.client.wait_for_job(
                job_id,
                poll_interval=self.config.intelowl.poll_interval,
                timeout=self.config.intelowl.job_timeout,
            )
        except IntelOwlClientError as err:
            raise ValueError(f"IntelOwl analysis failed: {err}") from err

        if job.get("status") in ("failed", "killed"):
            raise ValueError(
                f"IntelOwl job {job_id} ended with status {job.get('status')!r}"
            )

        converter = ConverterToStix.for_entity_tlp(entity_tlp)
        new_objects = converter.convert(
            stix_entity=stix_entity,
            value=value,
            playbook=playbook,
            job=job,
            job_url=self.client.job_url(job_id),
            update_score=self.config.intelowl.update_score,
            create_labels=self.config.intelowl.create_labels,
        )
        # stix_entity was updated in place (score, labels) and is part of stix_objects
        return self._send_bundle(stix_objects + new_objects)

    def run(self) -> None:
        """Listen for enrichment requests."""
        self.helper.listen(message_callback=self.process_message)
