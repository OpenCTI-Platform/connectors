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
            # Capture the cursor candidate BEFORE fetching so any
            # incident created during this cycle (between the
            # ``fetch_incidents`` call and the end-of-cycle
            # ``set_state``) is still picked up on the next cycle.
            # The previous shape captured ``datetime.now`` after
            # processing, which produced a data-loss window: incidents
            # created in the interval ``[fetch_start, cycle_end]`` had
            # ``createdAt > start_date`` for THIS cycle (so they were
            # fetched) but also ``createdAt < cycle_end`` (so on the
            # next cycle their ``createdAt`` would be ``<= start_date``
            # and the strict-after cursor would skip them). Capturing
            # the cursor here makes the persisted state describe
            # "everything created up to this instant has been
            # considered" — anything newer is left for the next cycle.
            cycle_cursor = datetime.now(timezone.utc)
            cycle_cursor_iso = cycle_cursor.strftime("%Y-%m-%dT%H:%M:%SZ")

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
            processing_complete = True
            if self.to_process:
                processing_complete = self._process_incidents()
            #########################################################

            ################ PHASE 3: Update State ###############

            # Only advance the ``last_run`` cursor when BOTH the fetch
            # AND the per-incident processing completed without a
            # failure that left incidents behind:
            #
            # * ``self.s1_client.last_fetch_complete`` is ``False`` when
            #   pagination aborted mid-walk on a transport / 5xx /
            #   non-2xx response — the rest of the SentinelOne
            #   ``/threats`` window in scope was not consumed, so
            #   advancing the cursor would silently drop those
            #   incidents from the ingest forever.
            # * ``processing_complete`` is ``False`` when at least one
            #   per-incident bundle assembly failed (``create_incident``
            #   returned an empty list or a per-incident exception was
            #   caught). The successful incidents in the same batch
            #   were already sent to OpenCTI with deterministic
            #   ``Incident.generate_id`` keys; the next cycle will
            #   re-fetch the same window and OpenCTI will dedup them
            #   while retrying the failed ones.
            #
            # When the cycle is clean we persist ``cycle_cursor_iso``
            # (captured up front, before fetching) rather than a
            # ``datetime.now()`` taken after processing — see the
            # ``cycle_cursor`` rationale at the top of this method.
            fetch_complete = self.s1_client.last_fetch_complete
            if fetch_complete and processing_complete:
                current_state = self.helper.get_state() or {}
                current_state["last_run"] = cycle_cursor_iso
                self.helper.set_state(current_state)
                self.helper.connector_logger.info(
                    f"{self.helper.connect_name} connector successfully run, "
                    f"storing last_run as {cycle_cursor_iso}"
                )
            else:
                self.helper.connector_logger.warning(
                    "Holding last_run cursor at previous value so the "
                    "incomplete window is retried on the next cycle",
                    meta={
                        "fetch_complete": fetch_complete,
                        "processing_complete": processing_complete,
                    },
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
            # See the ``_process_incidents`` rationale for the
            # ``threatInfo.threatId`` preference: SentinelOne's v2.1
            # ``/threats`` items expose the canonical identifier
            # there; the top-level ``id`` is only a convenience mirror
            # in current responses. Use the same preference here so
            # the debug log line stays useful even on a payload that
            # omits the top-level alias.
            threat_info = incident.get("threatInfo", {})
            incident_id = threat_info.get("threatId") or incident.get("id")
            self.helper.connector_logger.debug(
                f"Found applicable incident with ID: {incident_id}"
            )

        self.helper.connector_logger.info("Retrieval process complete")

    def _process_incidents(self) -> bool:
        """
        Processes each incident in the to_process list by creating
        corresponding stix objects.

        Incident objects are mandatory whereas the rest of objects
        are optional and depend on the incident data: UserAccount,
        Notes, Indicators, Attack Patterns.

        Returns
        -------
        bool
            ``True`` when every incident in the batch produced a
            bundle and the work was closed cleanly; ``False`` when at
            least one incident failed conversion (empty
            ``incident_items``) or raised an unhandled exception. The
            caller in :meth:`process_message` uses this flag to
            decide whether to advance the persisted ``last_run``
            cursor — holding the cursor on a partial-success cycle
            lets the next cycle retry the failed incidents (OpenCTI's
            deterministic ``Incident.generate_id`` keys guarantee the
            successful ones are deduplicated on the retry pass).
        """

        self.helper.connector_logger.info(
            "Connector beginning creation of applicable incidents",
            meta={"incident_count": len(self.to_process)},
        )
        processing_complete = True
        for _, s1_incident in enumerate(self.to_process):
            # SentinelOne's v2.1 ``/threats`` items expose the
            # canonical identifier under ``threatInfo.threatId``;
            # the top-level ``id`` is populated as a convenience
            # mirror in current responses but is not guaranteed by
            # the API documentation. Prefer the nested field and
            # fall back to the top-level alias so the notes endpoint
            # URL composition (``threats/{incident_id}/notes``) and
            # the STIX external-reference URL composed in
            # ``ConverterToStix.create_incident`` stay correct even
            # if a future SentinelOne release drops the top-level
            # mirror — otherwise this would silently become
            # ``threats/None/notes`` and break every incident's
            # bundle assembly.
            threat_info = s1_incident.get("threatInfo", {})
            s1_incident_id = threat_info.get("threatId") or s1_incident.get("id")
            friendly_name = f"S1 Incident Connector: Creating Incident From Threat with ID: {s1_incident_id}"

            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            self.helper.connector_logger.info(
                "Connector beginning creation of incident",
                meta={"s1_incident_id": s1_incident_id},
            )

            # Wrap the per-incident bundle assembly in a try/except so
            # one malformed SentinelOne payload (e.g. a missing
            # ``threatInfo`` key the converter relies on) does not
            # abort the rest of the batch. The previous shape ``break``ed
            # out of the loop on the first ``create_incident`` failure
            # which left every later incident in ``self.to_process``
            # unprocessed AND still advanced the ``last_run`` cursor at
            # the end of the cycle — silently dropping them from the
            # ingest forever. ``processing_complete`` is flipped on any
            # failure so :meth:`process_message` holds the cursor and
            # the next cycle retries the same window.
            try:
                stix_objects = []

                # Incident + Source
                incident_items = self.stix_client.create_incident(
                    s1_incident, s1_incident_id, self.config.s1_url
                )
                if not incident_items:
                    self.helper.connector_logger.error(
                        "Connector unable to create Incident; skipping this "
                        "one and continuing with the rest of the batch.",
                        meta={"s1_incident_id": s1_incident_id},
                    )
                    self.helper.api.work.to_processed(
                        work_id,
                        "incident creation failed",
                        in_error=True,
                    )
                    processing_complete = False
                    continue

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

                # Always include the author Identity SDO in the bundle
                # so ``created_by_ref`` resolves under
                # ``cleanup_inconsistent_bundle=True`` instead of being
                # silently stripped — matches the pattern used by
                # every sibling incident connector
                # (elastic-security-incidents, harfanglab-incidents,
                # sigmahq).
                stix_objects.append(self.stix_client.author)

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

                self.helper.api.work.to_processed(
                    work_id, "completed creation of incident"
                )
            except Exception as exc:
                self.helper.connector_logger.error(
                    "Unhandled error while processing SentinelOne incident; "
                    "marking work as in-error and continuing with the rest "
                    "of the batch.",
                    meta={
                        "s1_incident_id": s1_incident_id,
                        "error": str(exc),
                    },
                )
                self.helper.api.work.to_processed(
                    work_id,
                    f"incident processing failed: {exc}",
                    in_error=True,
                )
                processing_complete = False

        self.helper.connector_logger.info("Completed incident creation process")
        return processing_complete
