import json
import ssl
import sys
import time
import urllib
from datetime import datetime, timezone
from typing import Optional

from pycti import OpenCTIConnectorHelper, OpenCTINGConnectorHelper
from src import ConfigLoader

from .constants import (
    ENTERPRISE_ATTACK_KILL_CHAIN_PHASES_V18,
    ENTERPRISE_ATTACK_KILL_CHAIN_PHASES_V19,
    ICS_ATTACK_KILL_CHAIN_PHASES,
    MOBILE_ATTACK_KILL_CHAIN_PHASES,
    STATEMENT_MARKINGS,
)


def time_from_unixtime(timestamp):
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def get_unixtime_now():
    return int(time.time())


def days_to_seconds(days):
    return int(days) * 24 * 60 * 60


def filter_stix_revoked(revoked_ids, stix):
    # Pure revoke
    if stix["id"] in revoked_ids:
        return False
    # Side of relationship revoked
    if stix["type"] == "relationship" and (
        stix["source_ref"] in revoked_ids or stix["target_ref"] in revoked_ids
    ):
        return False
    # Side of sighting revoked
    if stix["type"] == "sighting" and (
        stix["sighting_of_ref"] in revoked_ids
        or any(ref in revoked_ids for ref in stix["where_sighted_refs"])
    ):
        return False
    return True


class Mitre:
    """Mitre connector."""

    def __init__(self):
        # Load configuration file and connection helper
        # Instantiate the connector helper from config
        self.config = ConfigLoader()
        # Detached mode: when an `opencti-ng` block is configured, ingest
        # directly into opencti-ng (JWT auth, file-based state) instead of going
        # through the legacy OpenCTI worker/queue.
        if self.config.opencti_ng is not None:
            self.helper = OpenCTINGConnectorHelper(
                config=self.config.model_dump_pycti()
            )
        else:
            self.helper = OpenCTIConnectorHelper(
                config=self.config.model_dump_pycti()
            )

        self.mitre_remove_statement_marking = self.config.mitre.remove_statement_marking

        self.mitre_interval = self.config.mitre.interval
        urls = [
            self.config.mitre.enterprise_file_url,
            self.config.mitre.mobile_attack_file_url,
            self.config.mitre.ics_attack_file_url,
            self.config.mitre.capec_file_url,
        ]
        self.mitre_urls = list(
            filter(lambda url: url is not None and url.lower() != "false", urls)
        )
        self.interval = days_to_seconds(self.mitre_interval)

    def retrieve_data(self, url: str) -> Optional[dict]:
        """
        Retrieve data from the given url.

        Parameters
        ----------
        url : str
            Url to retrieve.

        Returns
        -------
        str
            A string with the content or None in case of failure.
        """
        try:
            # Fetch json bundle from MITRE
            serialized_bundle = (
                urllib.request.urlopen(
                    url,
                    context=ssl.create_default_context(),
                )
                .read()
                .decode("utf-8")
            )
            # Convert the data to python dictionary
            stix_bundle = json.loads(serialized_bundle)
            stix_objects = stix_bundle["objects"]
            # First find all revoked ids
            revoked_objects = list(
                filter(
                    lambda stix: (
                        stix.get("revoked", False) is True
                        or stix.get("x_capec_status", "") == "Deprecated"
                    ),
                    stix_objects,
                )
            )
            revoked_ids = list(map(lambda stix: stix["id"], revoked_objects))
            # Filter every revoked MITRE elements
            not_revoked_objects = list(
                filter(
                    lambda stix: filter_stix_revoked(revoked_ids, stix), stix_objects
                )
            )
            stix_bundle["objects"] = not_revoked_objects
            # Remove statement marking
            if self.mitre_remove_statement_marking:
                stix_objects = stix_bundle["objects"]
                stix_bundle["objects"] = list(
                    filter(
                        lambda stix: stix["id"] not in STATEMENT_MARKINGS, stix_objects
                    )
                )
                self.remove_statement_marking(stix_bundle)
            # Enrich kill chain phases with x_opencti_order and versioned phases
            self.enrich_kill_chain_phases(stix_bundle, url)
            return stix_bundle
        except (
            urllib.error.URLError,
            urllib.error.HTTPError,
            urllib.error.ContentTooShortError,
        ) as urllib_error:
            self.helper.log_error(f"Error retrieving url {url}: {urllib_error}")
            self.helper.metric.inc("client_error_count")
        return None

    @staticmethod
    def remove_statement_marking(stix_bundle: dict):
        for obj in stix_bundle["objects"]:
            if "object_marking_refs" in obj:
                new_markings = []
                for ref in obj["object_marking_refs"]:
                    if ref not in STATEMENT_MARKINGS:
                        new_markings.append(ref)
                if len(new_markings) == 0:
                    del obj["object_marking_refs"]
                else:
                    obj["object_marking_refs"] = new_markings

    @staticmethod
    def get_collection_major_version(stix_bundle: dict) -> Optional[str]:
        """
        Extract the major version from the x-mitre-collection object in the bundle.

        Parameters
        ----------
        stix_bundle : dict
            The STIX bundle to search.

        Returns
        -------
        Optional[str]
            The major version (e.g., "18" from "18.1") or None if not found.
        """
        for obj in stix_bundle["objects"]:
            if obj.get("type") == "x-mitre-collection":
                version_str = obj.get("x_mitre_version", "")
                if version_str:
                    return version_str.split(".")[0]
        return None

    @staticmethod
    def _build_kill_chain_order_mapping(
        collection_version: Optional[str] = None,
    ) -> dict:
        """
        Build a mapping from (kill_chain_name, phase_name) to x_opencti_order.

        The Enterprise variant is selected from ``collection_version``
        because MITRE ATT&CK v19 (April 2026) split the legacy
        ``defense-evasion`` tactic into ``stealth`` /
        ``defense-impairment`` and shifted every subsequent tactic's
        order up by one. Pre-v19 bundles (operators pinning
        ``MITRE_ENTERPRISE_FILE_URL`` to an older release) carry
        ``defense-evasion``; v19+ bundles carry the two new tactic
        names. Selecting the right variant at build time keeps the
        order mapping aligned with whichever schema the inbound bundle
        actually uses — without this guard, a v18 bundle would lose
        ``x_opencti_order`` on every Defense Evasion attack-pattern
        (and OpenCTI would silently default the order to 0 in the
        UI).

        Mobile and ICS mappings are unchanged across v18 / v19 (the
        Defense Evasion split is Enterprise-only per the official
        ATT&CK v19 release notes), so they share a single static
        mapping regardless of the collection version.

        Parameters
        ----------
        collection_version : Optional[str]
            The major version of the bundle's ``x-mitre-collection``
            object (e.g. ``"18"``, ``"19"``). When ``None`` or
            unparseable (synthetic bundles, partial fixtures, etc.),
            falls back to the v19+ shape — the canonical
            ``enterprise-attack/enterprise-attack.json`` on MITRE's
            CTI repo currently ships v19, so the unknown-version path
            mirrors the most likely real-world input.

        Returns
        -------
        dict
            A dictionary mapping (kill_chain_name, phase_name) tuples to order values.
        """
        try:
            major = int(collection_version) if collection_version else None
        except (TypeError, ValueError):
            major = None
        enterprise_phases = (
            ENTERPRISE_ATTACK_KILL_CHAIN_PHASES_V18
            if major is not None and major < 19
            else ENTERPRISE_ATTACK_KILL_CHAIN_PHASES_V19
        )
        mapping = {}
        for phase in enterprise_phases:
            mapping[("mitre-attack", phase["name"])] = phase["order"]
        for phase in MOBILE_ATTACK_KILL_CHAIN_PHASES:
            mapping[("mitre-mobile-attack", phase["name"])] = phase["order"]
        for phase in ICS_ATTACK_KILL_CHAIN_PHASES:
            mapping[("mitre-ics-attack", phase["name"])] = phase["order"]
        return mapping

    def enrich_kill_chain_phases(self, stix_bundle: dict, url: str):
        """
        Enrich kill chain phases in attack patterns with x_opencti_order and versioned phases.
        For ATT&CK matrices (not CAPEC), this adds:
        - x_opencti_order to existing kill chain phases
        - Versioned kill chain phases (e.g., "mitre-attack-v18") with x_opencti_order

        Parameters
        ----------
        stix_bundle : dict
            The STIX bundle to process.
        url : str
            The URL from which the bundle was retrieved (used to check if CAPEC).
        """
        # Check if this is CAPEC
        is_capec = "capec" in url.lower()

        # Get the collection major version for ATT&CK matrices
        collection_version = None
        if not is_capec:
            collection_version = self.get_collection_major_version(stix_bundle)
            if collection_version:
                self.helper.log_info(
                    f"Found MITRE ATT&CK collection major version: {collection_version}"
                )
            else:
                self.helper.log_warning(
                    "Could not find x-mitre-collection version in bundle, skipping versioned kill chain phases"
                )

        # Build the order mapping. ``collection_version`` selects the
        # Enterprise variant (v18 vs v19+) so a bundle pinned to a
        # pre-v19 release still maps ``defense-evasion`` correctly —
        # see :meth:`_build_kill_chain_order_mapping` for the full
        # rationale.
        order_mapping = self._build_kill_chain_order_mapping(collection_version)

        # Track per-cycle missing-phase pairs so the warning logs once
        # per unique ``(kill_chain_name, phase_name)`` rather than once
        # per attack-pattern. The previous shape fired the warning
        # inside the per-phase loop, which on a missing tactic with N
        # techniques produced N identical warnings per cycle — for a
        # MITRE-scale bundle (Enterprise carries ~600 techniques across
        # 14 tactics) that could turn a single mapping miss into
        # hundreds of duplicate log lines per cycle. Deduping at the
        # cycle level keeps the operator-visible signal sharp without
        # losing it on the first appearance of an unmapped phase.
        missing_phases: set[tuple[str, str]] = set()

        # Process all attack patterns
        for obj in stix_bundle["objects"]:
            if obj.get("type") == "attack-pattern" and "kill_chain_phases" in obj:
                enriched_phases = []
                for phase in obj["kill_chain_phases"]:
                    kill_chain_name = phase.get("kill_chain_name", "")
                    phase_name = phase.get("phase_name", "")

                    # Look up the order for this phase
                    order = order_mapping.get((kill_chain_name, phase_name))

                    # Record the miss for the deduped per-cycle summary
                    # (CAPEC phases are expected to be unmapped — no
                    # ``x_opencti_order`` is required for them — so
                    # only track ATT&CK matrices).
                    if (
                        order is None
                        and not is_capec
                        and kill_chain_name
                        in (
                            "mitre-attack",
                            "mitre-mobile-attack",
                            "mitre-ics-attack",
                        )
                    ):
                        missing_phases.add((kill_chain_name, phase_name))

                    # Build enriched phase with x_opencti_order
                    enriched_phase = {
                        "kill_chain_name": kill_chain_name,
                        "phase_name": phase_name,
                    }
                    if order is not None:
                        enriched_phase["x_opencti_order"] = order

                    enriched_phases.append(enriched_phase)

                    # Add versioned kill chain phase for ATT&CK matrices
                    if collection_version and kill_chain_name in (
                        "mitre-attack",
                        "mitre-mobile-attack",
                        "mitre-ics-attack",
                    ):
                        versioned_phase = {
                            "kill_chain_name": f"{kill_chain_name}-v{collection_version}",
                            "phase_name": phase_name,
                        }
                        if order is not None:
                            versioned_phase["x_opencti_order"] = order
                        enriched_phases.append(versioned_phase)

                # Replace with enriched phases
                obj["kill_chain_phases"] = enriched_phases

        # Emit one structured warning per unique missing phase so a
        # future MITRE tactic addition surfaces as a clear actionable
        # signal in the operator's logs rather than getting silently
        # defaulted to ``x_opencti_order=0`` in the UI. Using
        # ``connector_logger.warning`` (the structured-logger API) so
        # the ``kill_chain_name`` / ``phase_name`` ride as proper
        # metadata fields — the older ``helper.log_warning`` would
        # collapse them into the message body.
        for kill_chain_name, phase_name in sorted(missing_phases):
            self.helper.connector_logger.warning(
                "No order mapping found for kill chain phase; "
                "x_opencti_order will default to 0 in the UI",
                meta={
                    "kill_chain_name": kill_chain_name,
                    "phase_name": phase_name,
                    "collection_version": collection_version,
                },
            )

    def process_data(self):
        unixtime_now = get_unixtime_now()
        time_now = time_from_unixtime(unixtime_now)

        current_state = self.helper.get_state()
        last_run = current_state.get("last_run", None) if current_state else None
        self.helper.log_debug(f"Connector last run: {time_from_unixtime(last_run)}")

        if last_run and self.interval > unixtime_now - last_run:
            self.helper.log_debug("Connector will not run this time.")
            return

        self.helper.log_info(f"Connector will run now {time_now}.")
        self.helper.metric.inc("run_count")
        self.helper.metric.state("running")

        friendly_name = f"MITRE run @ {time_now}"
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        self.helper.log_info("Fetching MITRE datasets...")
        for url in self.mitre_urls:
            self.helper.log_debug(f"Fetching {url}...")
            data = self.retrieve_data(url)

            if not data:
                continue

            self.helper.send_stix2_bundle(
                json.dumps(data),
                entities_types=self.helper.connect_scope,
                work_id=work_id,
                update=True,
            )
            self.helper.metric.inc("record_send", len(data["objects"]))

        message = f"Connector successfully run, storing last_run as {time_now}"
        self.helper.log_info(message)
        self.helper.set_state({"last_run": unixtime_now})
        self.helper.api.work.to_processed(work_id, message)

    def run(self):
        get_run_and_terminate = getattr(self.helper, "get_run_and_terminate", None)

        if callable(get_run_and_terminate) and self.helper.get_run_and_terminate():
            self.process_data()
            self.helper.force_ping()
            return

        while True:
            try:
                self.process_data()
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stop")
                self.helper.metric.state("stopped")
                sys.exit(0)
            except Exception as e:
                self.helper.log_error(str(e))
            finally:
                self.helper.metric.state("idle")
                time.sleep(60)


if __name__ == "__main__":
    try:
        mitre_connector = Mitre()
        mitre_connector.run()
    except Exception:
        import traceback

        traceback.print_exc()
        sys.exit(1)
