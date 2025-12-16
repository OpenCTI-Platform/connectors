import sys
import traceback
from datetime import datetime, timedelta, timezone

from api_client.client import MISPClient, MISPClientError
from api_client.models import EventRestSearchListItem
from batch_processor import GenericBatchProcessor, GenericBatchProcessorConfig
from connector.config_loader import ConfigLoader
from connector.threats_guesser import ThreatsGuesser
from connector.use_cases import ConverterError, EventConverter
from connector.work_manager import WorkManager
from exceptions.work_processing_error import WorkProcessingError
from pycti import OpenCTIConnectorHelper

LOG_PREFIX = "[Connector]"


class Misp:
    def __init__(self):
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(self.config.model_dump_pycti())
        self._logger = self.helper.connector_logger
        self.work_manager = WorkManager(self.config, self.helper, self._logger)

        self.client = MISPClient(
            url=self.config.misp.url,
            key=self.config.misp.key,
            verify_ssl=self.config.misp.ssl_verify,
            certificate=self.config.misp.client_cert,
        )
        self.converter = EventConverter(
            report_type=self.config.misp.report_type,
            report_description_attribute_filters=self.config.misp.report_description_attribute_filters,
            external_reference_base_url=(
                self.config.misp.reference_url or self.config.misp.url
            ),
            convert_event_to_report=self.config.misp.create_reports,
            convert_attribute_to_associated_file=self.config.misp.import_with_attachments,
            convert_attribute_to_indicator=self.config.misp.create_indicators,
            convert_attribute_to_observable=self.config.misp.create_observables,
            convert_object_to_observable=self.config.misp.create_object_observables,
            convert_unsupported_object_to_text_observable=self.config.misp.import_unsupported_observables_as_text,
            convert_unsupported_object_to_transparent_text_observable=self.config.misp.import_unsupported_observables_as_text_transparent,
            convert_tag_to_author=self.config.misp.author_from_tags,
            convert_tag_to_label=self.config.misp.create_tags_as_labels,
            convert_tag_to_marking=self.config.misp.markings_from_tags,
            propagate_report_labels=self.config.misp.propagate_labels,
            original_tags_to_keep_as_labels=self.config.misp.keep_original_tags_as_label,
            default_attribute_score=self.config.misp.import_to_ids_no_score,
            guess_threats_from_tags=self.config.misp.guess_threats_from_tags,
            threats_guesser=(
                ThreatsGuesser(self.helper.api)
                if self.config.misp.guess_threats_from_tags
                else None
            ),
        )
        if self.config.connector.batch_size:
            processor_config = GenericBatchProcessorConfig(
                batch_size=self.config.connector.batch_size,
                work_name_template="MISP run - Batch #{batch_num}",
                state_key="event_id",
                entity_type="stix_objects",
                display_name="STIX objects",
                empty_batch_behavior="skip",
            )
            self.processor = GenericBatchProcessor(
                work_manager=self.work_manager,
                config=processor_config,
                logger=self._logger,
            )

    def process_event(self, event: EventRestSearchListItem):
        # Check against filter
        if (
            self.config.misp.import_owner_orgs
            and event.Event.Org.name not in self.config.misp.import_owner_orgs
        ):
            self.helper.connector_logger.info(
                "Event owner Organization not in `MISP_IMPORT_OWNER_ORGS`, skipping event",
                {"event_owner_organization": event.Event.Org.name},
            )
            return
        if (
            self.config.misp.import_owner_orgs_not
            and event.Event.Org.name in self.config.misp.import_owner_orgs_not
        ):
            self.helper.connector_logger.info(
                "Event owner Organization in `MISP_IMPORT_OWNER_ORGS_NOT`, skipping event",
                {"event_owner_organization": event.Event.Org.name},
            )
            return
        if (
            self.config.misp.import_distribution_levels
            and event.Event.distribution
            not in self.config.misp.import_distribution_levels
        ):
            self.helper.connector_logger.info(
                "Event distribution level not in `MISP_IMPORT_DISTRIBUTION_LEVELS`, skipping event",
                {"event_distribution_level": event.Event.distribution},
            )
            return
        if (
            self.config.misp.import_threat_levels
            and event.Event.threat_level_id not in self.config.misp.import_threat_levels
        ):
            self.helper.connector_logger.info(
                "Event threat level not in `MISP_IMPORT_THREAT_LEVELS`, skipping event",
                {"event_threat_level": event.Event.threat_level_id},
            )
            return
        if self.config.misp.import_only_published and not event.Event.published:
            self.helper.connector_logger.info(
                "Event not published and `MISP_IMPORT_ONLY_PUBLISHED` enabled, skipping event",
                {"event_published": event.Event.published},
            )
            return

        self.helper.connector_logger.info(
            "Processing event",
            {"event_id": event.Event.id, "event_uuid": event.Event.uuid},
        )

        bundle_objects = self.converter.process(
            event=event,
            include_relationships=len(event.Event.Attribute) < 10_000,
        )
        if bundle_objects:
            now = datetime.now(tz=timezone.utc)

            if self.config.connector.batch_size:
                self.processor.config.work_name_template = (
                    "MISP run @ "
                    + now.isoformat(timespec="seconds")
                    + " - Batch #{batch_num}"
                )
                if (
                    self.processor.get_current_batch_size() + len(bundle_objects)
                ) >= self.processor.config.batch_size * 2:
                    self._logger.info(
                        "Need to Flush before adding next items to preserve consistency of the bundle",
                        {"prefix": LOG_PREFIX},
                    )
                    if self.processor.get_current_batch_size() > 0:
                        self.processor.flush()
                self.processor.add_items(bundle_objects)
            else:
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id,
                    friendly_name="MISP run @ " + now.isoformat(timespec="seconds"),
                )

                bundle = self.helper.stix2_create_bundle(bundle_objects)
                sent_bundles = self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                self.helper.connector_logger.info(
                    "Sent STIX2 bundles:", {"sent_bundles_count": len(sent_bundles)}
                )
                self.helper.metric.inc("record_send", len(bundle_objects))

                self.helper.api.work.to_processed(
                    work_id,
                    f"MISP event successfully imported (event id = {event.Event.id})",
                )

    def process(self):
        """Connector main process to collect intelligence."""
        error_flag = False
        error_message = None

        try:
            now = datetime.now(tz=timezone.utc)

            self.helper.metric.inc("run_count")
            self.helper.metric.state("running")

            current_state = self.helper.get_state() or {}
            if "last_run" in current_state and "last_event" in current_state:
                last_run = datetime.fromisoformat(current_state["last_run"])
                last_event = datetime.fromisoformat(current_state["last_event"])
                self.helper.connector_logger.info(
                    "Current state of the connector:",
                    {
                        "last_run": last_run,
                        "last_event": last_event,
                    },
                )

            elif "last_run" in current_state:
                last_run = datetime.fromisoformat(current_state["last_run"])
                last_event = last_run
                self.helper.connector_logger.info(
                    "Current state of the connector:",
                    {
                        "last_run": last_run,
                        "last_event": last_event,
                    },
                )
            else:
                if self.config.misp.import_from_date:
                    last_event = self.config.misp.import_from_date
                else:
                    last_event = now
                self.helper.connector_logger.info("Connector has never run")

            # Put the date
            next_event_date = last_event + timedelta(seconds=1)

            # Query all events
            self.helper.connector_logger.info(
                "Fetching MISP events with filters:",
                {
                    "date_field_filter": self.config.misp.date_filter_field,
                    "date_value_filter": next_event_date,
                    "keyword": self.config.misp.import_keyword,
                    "included_tags": self.config.misp.import_tags,
                    "excluded_tags": self.config.misp.import_tags_not,
                    "included_org_creators": self.config.misp.import_creator_orgs,
                    "excluded_org_creators": self.config.misp.import_creator_orgs_not,
                    "enforce_warning_list": self.config.misp.enforce_warning_list,
                    "with_attachments": self.config.misp.import_with_attachments,
                },
            )

            events = self.client.search_events(
                date_field_filter=self.config.misp.date_filter_field,
                date_value_filter=next_event_date,
                keyword=self.config.misp.import_keyword,
                included_tags=self.config.misp.import_tags,
                excluded_tags=self.config.misp.import_tags_not,
                included_org_creators=self.config.misp.import_creator_orgs,
                excluded_org_creators=self.config.misp.import_creator_orgs_not,
                enforce_warning_list=self.config.misp.enforce_warning_list,
                with_attachments=self.config.misp.import_with_attachments,
            )

            processed_events_count = 0
            last_event_datetime = None

            for event in events:
                self.helper.connector_logger.info(
                    "MISP event found",
                    {"event_id": event.Event.id, "event_uuid": event.Event.uuid},
                )

                try:
                    self.process_event(event)
                except ConverterError as err:
                    self.helper.connector_logger.error(
                        f"Error while converting MISP event, skipping it. {err}",
                        {"event_id": event.Event.id, "event_uuid": event.Event.uuid},
                    )
                    continue
                finally:
                    if self.config.connector.batch_size:
                        try:
                            if self.processor.get_current_batch_size() > 0:
                                work_id = self.processor.flush()
                                if work_id:
                                    self._logger.info(
                                        "Batch processor: Flushed remaining items",
                                        {"prefix": LOG_PREFIX},
                                    )
                            self.processor.update_final_state()
                        except Exception as e:
                            self._logger.error(
                                "Failed to flush batch processor",
                                {"prefix": LOG_PREFIX, "error": str(e)},
                            )

                # Line below will raise if `self.config.misp.datetime_attribute`` is not a valid field (i.e. defined in MISP models)
                # This behavior is expected as it would mean that config/env vars are not validated correctly
                event_datetime_value = getattr(
                    event.Event, self.config.misp.datetime_attribute
                )

                if self.config.misp.datetime_attribute in [
                    "timestamp",
                    "publish_timestamp",
                    "sighting_timestamp",
                ]:
                    event_datetime = datetime.fromtimestamp(
                        int(event_datetime_value), tz=timezone.utc
                    )
                elif self.config.misp.datetime_attribute == "date":
                    event_datetime = datetime.fromisoformat(
                        event_datetime_value
                    ).replace(tzinfo=timezone.utc)
                else:
                    # Should never be raised as it would mean that config/env vars are not validated correctly
                    raise ValueError(
                        "`MISP_DATETIME_ATTRIBUTE` must be either: 'date', 'timestamp', 'publish_timestamp' or 'sighting_timestamp'"
                    )

                # Need to check if datetime is more recent than the previous event since
                # events are not ordered by datetime in API response
                if last_event_datetime is None or event_datetime > last_event_datetime:
                    last_event_datetime = event_datetime

                processed_events_count += 1

            self.helper.connector_logger.info(
                "Connector ran successfully",
                {"processed_events_count": processed_events_count},
            )

            # Loop is over, storing the state
            # We cannot store the state before, because MISP events are NOT ordered properly
            # and there is NO WAY to order them using their library
            current_state["last_run"] = now.isoformat()
            if last_event_datetime:
                current_state["last_event"] = last_event_datetime.isoformat()

            self.helper.set_state(current_state)
            self.helper.connector_logger.info(
                "Updating connector state as:", current_state
            )

        except MISPClientError as err:
            error_message = f"MISP Client error: {str(err)}"
            self.helper.connector_logger.error(err)
            self.helper.metric.inc("client_error_count")
            error_flag = True

        except WorkProcessingError as work_err:
            error_message = f"Work processing error: {str(work_err)}"
            work_id = getattr(
                work_err, "work_id", self.work_manager.get_current_work_id()
            )
            self._logger.warning(
                "Work processing error",
                meta={
                    "prefix": LOG_PREFIX,
                    "error": str(work_err),
                    "work_id": work_id,
                },
            )
            error_flag = True

        except (KeyboardInterrupt, SystemExit):
            error_message = "Connector stopped by user or system"
            self.helper.connector_logger.info(
                "Connector stopped by user or system",
                {"connector_name": self.helper.connect_name},
            )
            error_flag = True
            raise
        except Exception as err:
            error_message = f"Unexpected error: {str(err)}"
            self.helper.connector_logger.error(
                "Unexpected error. See connector's log for more details.",
                {"error": err},
            )
            error_flag = True

        finally:
            self.helper.metric.state("idle")
            self._logger.info(
                "Connector stopped",
                {"prefix": LOG_PREFIX, "connector_name": self.helper.connect_name},
            )
            try:
                self.work_manager.process_all_remaining_works(
                    error_flag=error_flag, error_message=error_message
                )
                self._logger.info(
                    "All remaining works marked to process", {"prefix": LOG_PREFIX}
                )
            except Exception as cleanup_err:
                self._logger.error(
                    "Error during cleanup",
                    meta={"prefix": LOG_PREFIX, "error": str(cleanup_err)},
                )

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector.
        If `CONNECTOR_QUEUE_THRESHOLD` is set, if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)
        It requires the `duration_period` connector variable in ISO-8601 standard format
        Example: `CONNECTOR_DURATION_PERIOD=PT5M` => Will run the process every 5 minutes
        :return: None
        """
        self.helper.schedule_process(
            message_callback=self.process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )


if __name__ == "__main__":
    try:
        mispConnector = Misp()
        mispConnector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
