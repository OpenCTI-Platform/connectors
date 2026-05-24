import sys
from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper

from .config_variables import ConfigConnector
from .converter_to_stix import ConverterToStix
from .s1_client import SentinelOneClient


def _parse_iso_datetime(value: str) -> datetime:
    """Parse an ISO 8601 datetime string and return a UTC-aware ``datetime``.

    ``datetime.fromisoformat`` only learned to accept the trailing ``Z``
    suffix in Python 3.11; both the persisted state
    (``current_state["last_run"]`` is written as ``...Z`` further down
    in this module) and ``SENTINELONE_INCIDENTS_IMPORT_START_DATE``
    (the shipped samples use ``2026-01-01T00:00:00Z``) would otherwise
    crash on startup or on the second run with a ``ValueError``.
    Normalise a trailing ``Z`` to ``+00:00`` first, then coerce
    timezone-naive values to UTC so downstream comparisons against
    UTC-aware values (``incident_created_at`` in
    :meth:`SentinelOneClient.fetch_incidents`) do not raise
    ``TypeError`` when aware and naive datetimes are compared.
    """
    normalised = value.strip()
    if normalised.endswith("Z"):
        normalised = normalised[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalised)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    else:
        parsed = parsed.astimezone(timezone.utc)
    return parsed


class IncidentConnector:
    def __init__(self):
        self.config = ConfigConnector()
        self.helper = OpenCTIConnectorHelper(self.config.load)

        self.to_process = []

        self.s1_client = SentinelOneClient(self.helper.connector_logger, self.config)
        self.stix_client = ConverterToStix(self.helper)

    def process_message(self) -> None:
        """
        The main process for the connector, triggered
        at each interval.

        """
        self.helper.connector_logger.info(
            "Starting connector...",
            meta={"connector_name": self.helper.connect_name},
        )

        try:
            # Get the current state. ``_parse_iso_datetime`` normalises
            # both the persisted state (written as ``...Z``) and the
            # configured ``SENTINELONE_INCIDENTS_IMPORT_START_DATE`` to
            # a UTC-aware datetime so the downstream comparison against
            # ``incident_created_at`` in ``fetch_incidents`` does not
            # crash with ``TypeError`` (aware vs naive) or silently fall
            # back to the configured start date on every run because
            # ``datetime.fromisoformat`` rejected the ``Z`` suffix.
            current_state = self.helper.get_state() or {}
            last_run = (
                _parse_iso_datetime(current_state["last_run"])
                if "last_run" in current_state
                else None
            )

            self.helper.connector_logger.info(
                "Connector last run",
                meta={"last_run": str(last_run) if last_run else "Never"},
            )
            self.helper.connector_logger.info(
                "Running connector...",
                meta={"connector_name": self.helper.connect_name},
            )

            # Performing the collection of intelligence
            start_date = last_run or _parse_iso_datetime(self.config.import_start_date)

            ############### PHASE 1: SCAN FOR INCIDENTS ###############

            # query new incidents
            self._query_new_incidents(start_date)

            # The scan filters incidents by their ``createdAt`` against
            # ``start_date`` — there is no flag/sign filter anymore — so
            # the log line reflects the current behaviour.
            self.helper.connector_logger.info(
                "Connector completed incidents scan",
                meta={"start_date": str(start_date)},
            )
            #########################################################

            ################ PHASE 2: Process Incidents ###############
            # Individual work is made and closed in the incident processing method.
            if self.to_process:
                self._process_incidents()
            #########################################################

            ################ PHASE 3: Update State ###############

            # Store the current timestamp as the last run of the
            # connector. Use a UTC-aware ``datetime.now`` (the previous
            # ``datetime.utcfromtimestamp`` is deprecated in Python
            # 3.12+) and serialise back to the canonical
            # ``YYYY-MM-DDTHH:MM:SSZ`` shape so the next cycle's
            # ``_parse_iso_datetime`` round-trip is exact.
            now_utc = datetime.now(timezone.utc)
            current_state_datetime = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
            current_state = self.helper.get_state()
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            self.helper.connector_logger.info(
                f"{self.helper.connect_name} connector successfully run, storing "
                f"last_run as {current_state_datetime}"
            )
            #########################################################

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stopped...")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        """
        Schedules the connector to run at an interval
        based on the environment variables (or conf).
        """

        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )

    def _query_new_incidents(self, start_date: datetime) -> None:
        """
        Queries for incidents created on SentinelOne strictly after
        ``start_date`` and adds them to the ``to_process`` list. No
        flag/sign filter is applied — the ``createdAt`` cursor is the
        only selection criterion.
        """

        # Retrieve all incidents from SentinelOne
        self.helper.connector_logger.info("Retrieving and filtering Incidents...")
        self.to_process = self.s1_client.fetch_incidents(start_date)
        if not self.to_process:
            self.helper.connector_logger.info(
                "Connector retrieved no incidents from SentinelOne"
            )
            return
        self.helper.connector_logger.info(f"Found {len(self.to_process)} incidents")

        for incident in self.to_process:
            self.helper.connector_logger.debug(
                f"Found applicable incident with ID: {incident.get('id')}"
            )

        self.helper.connector_logger.info("Retrieval process complete")

    def _process_incidents(self):
        """
        Processes each incident in the to_process list by creating
        corresponding stix objects.

        Incident objects are mandatory whereas the rest of objects
        are optional and depend on the incident data: UserAccount,
        Notes, Indicators, Attack Patterns.
        """

        self.helper.log_info(
            f"Connector Beginning creation of {len(self.to_process)} applicable Incidents"
        )
        for _, s1_incident in enumerate(self.to_process):
            s1_incident_id = s1_incident.get("id")
            friendly_name = f"S1 Incident Connector: Creating Incident From Threat with ID: {s1_incident_id}"

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            self.helper.log_info(
                f"Connector Beggining Creation of Incident for S1 ID: {s1_incident_id}"
            )

            stix_objects = []

            # Incident + Source
            incident_items = self.stix_client.create_incident(
                s1_incident, s1_incident_id, self.config.s1_url
            )
            if not incident_items:
                self.helper.connector_logger.error(
                    "Connector unable to create Incident, creation process cannot continue."
                )
                break

            cti_incident_id = incident_items[0].get("id")
            stix_objects.extend(incident_items)

            # UserAccount + Relationship to Incident.
            # ``create_user_account_observable`` returns an empty list
            # when the incident carries no ``agentComputerName``; treat
            # the falsy return uniformly via ``extend([])`` rather than
            # crashing on ``extend(None)``.
            account_items = (
                self.stix_client.create_user_account_observable(
                    s1_incident, cti_incident_id
                )
                or []
            )
            stix_objects.extend(account_items)

            # List Of Notes
            s1_incident_notes = self.s1_client.fetch_incident_notes(s1_incident_id)
            notes_items = self.stix_client.create_notes(
                s1_incident_notes, cti_incident_id
            )
            stix_objects.extend(notes_items)

            # List Of Indicators  with Relationships to Incident
            indicators_items = self.stix_client.create_hash_indicators(
                s1_incident, cti_incident_id
            )
            stix_objects.extend(indicators_items)

            # List Of Attack Patterns with Relationships to Incident and Sub Attack Patterns with
            # Relationships to the Attack Patterns
            attack_patterns_items = self.stix_client.create_attack_patterns(
                s1_incident, cti_incident_id
            )
            stix_objects.extend(attack_patterns_items)

            # Informative log of all created objects
            message = ""
            if incident_items:
                message += "Incident"
            if account_items:
                message += ", UserAccount"
            if notes_items:
                message += ", Notes"
            if indicators_items:
                message += ", Indicators"
            if attack_patterns_items:
                message += ", Attack Patterns"
            self.helper.connector_logger.info(
                f"Connector created the following objects for the Incident: {message}"
            )

            # Send the bundle to OpenCTI
            bundle = self.helper.stix2_create_bundle(stix_objects)
            bundles_sent = self.helper.send_stix2_bundle(
                bundle, work_id=work_id, cleanup_inconsistent_bundle=True
            )
            self.helper.connector_logger.info(
                f"Connector Sent Bundle of {len(bundles_sent)} STIX objects to OpenCTI"
            )

            self.helper.api.work.to_processed(work_id, "completed creation of incident")

        self.helper.log_info("Completed Incident Creation Process.")
