"""MITRE Fight Fraud Framework (F3) connector module."""

import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

from connector.constants import (
    F3_KILL_CHAIN_NAME,
    F3_KILL_CHAIN_PHASES,
    F3_STIX_BUNDLE_URL,
)
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

STATEMENT_MARKINGS = [
    "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168",
    "marking-definition--17d82bb2-eeeb-4898-bda5-3ddbcd2b799d",
]


class MitreFraud:
    """MITRE Fight Fraud Framework (F3) connector.

    This connector imports the MITRE Fight Fraud Framework (F3) knowledge base,
    a curated set of tactics and techniques used by financial fraud actors.
    It fetches the F3 STIX bundle, enriches kill chain phases with
    ``x_opencti_order`` for proper ordering in OpenCTI, and sends the bundle
    for ingestion.

    Attributes
    ----------
    config : ConnectorSettings
        Connector configuration.
    helper : OpenCTIConnectorHelper
        OpenCTI connector helper for API interactions.
    """

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self._kill_chain_order_mapping = self._build_kill_chain_order_mapping()

    @staticmethod
    def _build_kill_chain_order_mapping() -> dict:
        """Build a mapping from phase_name to x_opencti_order for F3 kill chain.

        Returns
        -------
        dict
            A dictionary mapping phase_name strings to order values.
        """
        mapping = {}
        for phase in F3_KILL_CHAIN_PHASES:
            mapping[phase["name"]] = phase["order"]
        return mapping

    def retrieve_data(self, url: str) -> Optional[dict]:
        """Retrieve and parse the F3 STIX bundle from the given URL.

        Parameters
        ----------
        url : str
            URL to fetch the STIX bundle from.

        Returns
        -------
        Optional[dict]
            The parsed STIX bundle as a dictionary, or None on failure.
        """
        try:
            serialized_bundle = (
                urllib.request.urlopen(
                    url,
                    context=ssl.create_default_context(),
                )
                .read()
                .decode("utf-8")
            )
            stix_bundle = json.loads(serialized_bundle)
            stix_objects = stix_bundle["objects"]

            # Filter revoked objects
            revoked_objects = list(
                filter(
                    lambda stix: stix.get("revoked", False) is True,
                    stix_objects,
                )
            )
            revoked_ids = [stix["id"] for stix in revoked_objects]

            not_revoked_objects = list(
                filter(
                    lambda stix: self._filter_stix_revoked(revoked_ids, stix),
                    stix_objects,
                )
            )
            stix_bundle["objects"] = not_revoked_objects

            # Remove statement markings if configured
            if self.config.mitre_fraud.remove_statement_marking:
                stix_bundle["objects"] = [
                    obj
                    for obj in stix_bundle["objects"]
                    if obj["id"] not in STATEMENT_MARKINGS
                ]
                self._remove_statement_marking(stix_bundle)

            # Enrich kill chain phases with x_opencti_order
            self._enrich_kill_chain_phases(stix_bundle)

            return stix_bundle
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.connector_logger.error(
                f"Error retrieving url {url}: {urllib_error}"
            )
        return None

    @staticmethod
    def _filter_stix_revoked(revoked_ids: list, stix: dict) -> bool:
        """Check whether a STIX object should be kept (not revoked).

        Parameters
        ----------
        revoked_ids : list
            List of revoked STIX object IDs.
        stix : dict
            The STIX object to check.

        Returns
        -------
        bool
            True if the object should be kept, False otherwise.
        """
        if stix["id"] in revoked_ids:
            return False
        if stix["type"] == "relationship" and (
            stix.get("source_ref") in revoked_ids
            or stix.get("target_ref") in revoked_ids
        ):
            return False
        return True

    @staticmethod
    def _remove_statement_marking(stix_bundle: dict):
        """Remove statement marking references from all objects in the bundle.

        Parameters
        ----------
        stix_bundle : dict
            The STIX bundle to process in-place.
        """
        for obj in stix_bundle["objects"]:
            if "object_marking_refs" in obj:
                new_markings = [
                    ref
                    for ref in obj["object_marking_refs"]
                    if ref not in STATEMENT_MARKINGS
                ]
                if len(new_markings) == 0:
                    del obj["object_marking_refs"]
                else:
                    obj["object_marking_refs"] = new_markings

    def _enrich_kill_chain_phases(self, stix_bundle: dict):
        """Enrich kill chain phases in attack patterns with x_opencti_order.

        Only phases belonging to the F3 kill chain are enriched;
        all other phases are left untouched.

        Parameters
        ----------
        stix_bundle : dict
            The STIX bundle to process in-place.
        """
        for obj in stix_bundle["objects"]:
            if obj.get("type") != "attack-pattern":
                continue
            if "kill_chain_phases" not in obj:
                continue

            enriched_phases = []
            for phase in obj["kill_chain_phases"]:
                kill_chain_name = phase.get("kill_chain_name", "")
                phase_name = phase.get("phase_name", "")

                enriched_phase = {
                    "kill_chain_name": kill_chain_name,
                    "phase_name": phase_name,
                }

                if kill_chain_name == F3_KILL_CHAIN_NAME:
                    order = self._kill_chain_order_mapping.get(phase_name)
                    if order is not None:
                        enriched_phase["x_opencti_order"] = order

                enriched_phases.append(enriched_phase)

            obj["kill_chain_phases"] = enriched_phases

    def process_data(self):
        """Main process to fetch, enrich, and send the F3 STIX bundle."""
        try:
            timestamp = int(time.time())
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {
                        "last_run_datetime": datetime.fromtimestamp(
                            last_run, tz=timezone.utc
                        ).strftime("%Y-%m-%d %H:%M:%S")
                    },
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            now = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            friendly_name = "MITRE Fight Fraud (F3) run @ " + now.strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Fetching MITRE Fight Fraud (F3) dataset...",
                {"url": F3_STIX_BUNDLE_URL},
            )

            data = self.retrieve_data(F3_STIX_BUNDLE_URL)

            if data:
                bundles_sent = self.helper.send_stix2_bundle(
                    json.dumps(data),
                    entities_types=self.config.connector.scope,
                    work_id=work_id,
                    update=True,
                )
                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": str(len(bundles_sent))},
                )

            message = (
                f"{self.helper.connect_name} connector successfully run, "
                f"storing last_run as " + now.strftime("%Y-%m-%d %H:%M:%S")
            )
            self.helper.set_state({"last_run": timestamp})
            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """Start the connector and schedule periodic runs."""
        self.helper.connector_logger.info("Fetching MITRE Fight Fraud (F3) datasets...")
        self.helper.schedule_process(
            message_callback=self.process_data,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
