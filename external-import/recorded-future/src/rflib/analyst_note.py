import threading
from datetime import datetime, timezone

from .rf_to_stix2 import StixNote


class AnalystNote(threading.Thread):

    def __init__(
        self,
        helper,
        rfapi,
        last_published_notes_interval,
        rf_initial_lookback,
        rf_pull_signatures,
        rf_insikt_only,
        rf_topics,
        tlp,
        rf_person_to_TA,
        rf_TA_to_intrusion_set,
        risk_as_score,
        risk_threshold,
    ):
        threading.Thread.__init__(self)
        self.helper = helper
        self.rfapi = rfapi
        self.last_published_notes_interval = last_published_notes_interval
        self.rf_initial_lookback = rf_initial_lookback
        self.rf_pull_signatures = rf_pull_signatures
        self.rf_insikt_only = rf_insikt_only
        self.rf_topics = rf_topics
        self.tlp = tlp
        self.rf_person_to_TA = rf_person_to_TA
        self.rf_TA_to_intrusion_set = rf_TA_to_intrusion_set
        self.risk_as_score = risk_as_score
        self.risk_threshold = risk_threshold

    def run(self):
        """
        Fetch and ingest RecordedFuture Analyst Notes
        :return:
        """

        # Get the current state
        now = datetime.now()
        current_timestamp = int(datetime.timestamp(now))
        current_state = self.helper.get_state() or {}

        if current_state is not None and "last_analyst_notes_run" in current_state:
            last_analyst_notes_run = current_state["last_analyst_notes_run"]

            self.helper.connector_logger.info(
                "[CONNECTOR] Connector last analyst notes run",
                {"last_run_datetime": last_analyst_notes_run},
            )
            published = self.last_published_notes_interval
        else:
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector has never run...",
                {"initial_lookback_hours": self.rf_initial_lookback},
            )
            published = self.rf_initial_lookback

        # Friendly name will be displayed on OpenCTI platform
        friendly_name = "Recorded Future Analyst Notes"

        # Initiate a new work
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        try:
            # Import, convert and send to OpenCTI platform Analyst Notes
            tas = self.rfapi.get_threat_actors()
            self.convert_and_send(published, tas, work_id)
        except Exception as e:
            self.helper.connector_logger.error(str(e))

        # Store the current timestamp as a last run of the connector
        self.helper.connector_logger.debug(
            "Getting current state and update it with last run of the connector",
            {"current_timestamp": current_timestamp},
        )

        current_state = self.helper.get_state() or {}
        last_run_datetime = datetime.fromtimestamp(
            current_timestamp, tz=timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        current_state.update({"last_analyst_notes_run": last_run_datetime})
        self.helper.set_state(state=current_state)
        message = (
            f"{self.helper.connect_name} connector successfully run, storing last run for Analyst Notes as "
            + str(last_run_datetime)
        )
        self.helper.api.work.to_processed(work_id, message)

    def convert_and_send(self, published, tas, work_id):
        """
        Pulls Analyst Notes, converts to Stix2, sends to OpenCTI
        :param published:
        :param tas:
        :param work_id:
        :return:
        """
        self.helper.connector_logger.info(
            f"[ANALYST NOTES] Pull Signatures is {str(self.rf_pull_signatures)} of type "
            f"{type(self.rf_pull_signatures)}"
        )
        self.helper.connector_logger.info(
            f"[ANALYST NOTES] Insikt Only is {str(self.rf_insikt_only)} of type {type(self.rf_insikt_only)}"
        )
        self.helper.connector_logger.info(
            f"[ANALYST NOTES] Topics are {str(self.rf_topics)} of type {type(self.rf_topics)}"
        )
        notes = []
        notes_ids = []
        for topic in self.rf_topics:
            new_notes = self.rfapi.get_analyst_notes(
                published, self.rf_pull_signatures, self.rf_insikt_only, topic
            )
            for new_note in new_notes:
                if new_note["id"] not in notes_ids:
                    notes.append(new_note)
                    notes_ids.append(new_note["id"])

        self.helper.connector_logger.info(
            f"[ANALYST NOTES] Fetched {len(notes)} Analyst notes from API"
        )
        for note in notes:
            try:
                stix_note = StixNote(
                    self.helper,
                    tas,
                    self.rfapi,
                    self.rf_person_to_TA,
                    self.rf_TA_to_intrusion_set,
                    self.risk_as_score,
                    self.risk_threshold,
                )
                stix_note.from_json(note, self.tlp)
                stix_note.create_relations()
                bundle = stix_note.to_stix_bundle()
                self.helper.connector_logger.info(
                    "[ANALYST NOTES] Sending Bundle to server with "
                    + str(len(bundle.objects))
                    + " objects"
                )
                self.helper.send_stix2_bundle(
                    bundle.serialize(),
                    work_id=work_id,
                )
            except Exception as exception:
                self.helper.connector_logger.error(
                    f"[ANALYST NOTES] Bundle has been skipped due to exception: "
                    f"{str(exception)}"
                )
                continue
