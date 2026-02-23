from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from api_client.client import MISPClient, MISPClientError
from connector.use_cases import ConverterError, EventConverter
from exceptions import MispWorkProcessingError
from utils.batch_processor import BatchProcessor
from utils.threats_guesser import ThreatsGuesser
from utils.work_manager import WorkManager

if TYPE_CHECKING:
    import stix2
    from api_client.models import EventRestSearchListItem
    from connector.settings import ConnectorSettings
    from pycti import OpenCTIConnectorHelper

LOG_PREFIX = "[Connector]"


class Misp:
    def __init__(self, config: "ConnectorSettings", helper: "OpenCTIConnectorHelper"):
        self.config = config
        self.helper = helper
        self.logger = helper.connector_logger

        self.client_api: MISPClient = MISPClient(
            url=self.config.misp.url,
            key=self.config.misp.key.get_secret_value(),
            verify_ssl=self.config.misp.ssl_verify,
            certificate=self.config.misp.client_cert,
            timeout=self.config.misp.request_timeout,
        )

        self.converter = EventConverter(
            logger=self.logger,
            report_type=self.config.misp.report_type,
            report_description_attribute_filters=self.config.misp.report_description_attribute_filters,
            external_reference_base_url=self.config.misp.reference_url
            or self.config.misp.url,
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

        self.work_manager = WorkManager(self.config, self.helper, self.logger)
        self.batch_processor: "BatchProcessor" = BatchProcessor(
            work_manager=self.work_manager,
            logger=self.logger,
            batch_size=self.config.misp.batch_count,
        )

    def _check_batch_size_and_flush(
        self,
        all_entities: "list[stix2.v21._STIXBase21]",
    ) -> None:
        """Check if batch needs to be flushed and flush if necessary.

        Args:
            all_entities: list of entities to be added

        """
        if (
            self.batch_processor.get_current_batch_size() + len(all_entities)
        ) >= self.config.misp.batch_count * 2:
            self.logger.debug(
                "Need to Flush before adding next items to preserve consistency of the bundle",
                {"prefix": LOG_PREFIX},
            )
            self.batch_processor.flush()

    def _check_and_add_entities_to_batch(
        self,
        all_entities: "list[stix2.v21._STIXBase21]",
        author: "stix2.Identity",
        markings: "list[stix2.MarkingDefinition]",
    ) -> None:
        """Add entities to the batch processor.

        Args:
            all_entities: list of entities to add
            author: Author of the entities
            markings: Markings of the entities
        """
        self._check_batch_size_and_flush(all_entities)
        self.batch_processor.add_item(author)
        self.batch_processor.add_items(markings)
        self.batch_processor.add_items(all_entities)

    def _flush_batch_processor(self) -> None:
        """Flush any remaining items in the batch processor."""
        try:
            work_id = self.batch_processor.flush()
            if work_id:
                self.logger.debug(
                    "Batch processor: Flushed remaining items",
                    {"prefix": LOG_PREFIX},
                )
        except Exception as e:
            self.logger.error(
                "Failed to flush batch processor",
                {"prefix": LOG_PREFIX, "error": str(e)},
            )

    def _validate_event(self, event: "EventRestSearchListItem") -> bool:
        """Validate the event.

        Args:
            event: The event to validate

        Returns:
            True if the event is valid, False otherwise

        """
        if (
            self.config.misp.import_owner_orgs
            and event.Event.Org.name not in self.config.misp.import_owner_orgs
        ):
            self.logger.info(
                "Event owner Organization not in `MISP_IMPORT_OWNER_ORGS`, skipping event",
                {
                    "prefix": LOG_PREFIX,
                    "event_owner_organization": event.Event.Org.name,
                },
            )
            return False

        if (
            self.config.misp.import_owner_orgs_not
            and event.Event.Org.name in self.config.misp.import_owner_orgs_not
        ):
            self.logger.info(
                "Event owner Organization in `MISP_IMPORT_OWNER_ORGS_NOT`, skipping event",
                {
                    "prefix": LOG_PREFIX,
                    "event_owner_organization": event.Event.Org.name,
                },
            )
            return False

        if (
            self.config.misp.import_distribution_levels
            and event.Event.distribution
            not in self.config.misp.import_distribution_levels
        ):
            self.logger.info(
                "Event distribution level not in `MISP_IMPORT_DISTRIBUTION_LEVELS`, skipping event",
                {
                    "prefix": LOG_PREFIX,
                    "event_distribution_level": event.Event.distribution,
                },
            )
            return False

        if (
            self.config.misp.import_threat_levels
            and event.Event.threat_level_id not in self.config.misp.import_threat_levels
        ):
            self.logger.info(
                "Event threat level not in `MISP_IMPORT_THREAT_LEVELS`, skipping event",
                {
                    "prefix": LOG_PREFIX,
                    "event_threat_level": event.Event.threat_level_id,
                },
            )
            return False

        if self.config.misp.import_only_published and not event.Event.published:
            self.logger.info(
                "Event not published and `MISP_IMPORT_ONLY_PUBLISHED` enabled, skipping event",
                {
                    "prefix": LOG_PREFIX,
                    "event_published": event.Event.published,
                },
            )
            return False

        current_state = self.work_manager.get_state()
        if self.config.misp.datetime_attribute == "date":
            current_event_id = current_state.get("current_event_id")
            remaining_objects_count = current_state.get("remaining_objects_count")

            if not current_event_id:
                return True

            if int(event.Event.id) < int(current_event_id) or (
                event.Event.id == current_event_id and remaining_objects_count == 0
            ):
                self.logger.info(
                    "Event already processed by the connector, skipping event",
                    {
                        "prefix": LOG_PREFIX,
                        "event_id": event.Event.id,
                    },
                )
                return False
        else:
            last_event_date = current_state.get("last_event_date")
            remaining_objects_count = current_state.get("remaining_objects_count")

            if not last_event_date:
                return True

            event_datetime = self._get_event_datetime(event)
            last_event_datetime = datetime.fromisoformat(last_event_date)
            if event_datetime < last_event_datetime:
                self.logger.info(
                    "Event already processed by the connector, skipping event",
                    {
                        "prefix": LOG_PREFIX,
                        "event_id": event.Event.id,
                        "event_datetime": event_datetime.isoformat(),
                    },
                )
                return False

        return True

    def _get_event_datetime(self, event: "EventRestSearchListItem") -> datetime:
        """Get the datetime of the event based on the configured attribute.

        Args:
            event: The MISP event

        Returns:
            The datetime of the event

        """
        event_datetime_attribute = self.config.misp.datetime_attribute
        event_datetime_value = getattr(event.Event, event_datetime_attribute)

        if event_datetime_attribute in {
            "timestamp",
            "publish_timestamp",
            "sighting_timestamp",
        }:
            event_datetime = datetime.fromtimestamp(
                int(event_datetime_value), tz=timezone.utc
            )
        elif event_datetime_attribute == "date":
            event_datetime = datetime.fromisoformat(event_datetime_value).replace(
                tzinfo=timezone.utc
            )
        else:
            raise ValueError(
                "`MISP_DATETIME_ATTRIBUTE` must be either: 'date', "
                "'timestamp', 'publish_timestamp' or 'sighting_timestamp'"
            )

        return event_datetime

    def _process_bundle_in_batch(
        self,
        event: "EventRestSearchListItem",
        bundle_objects: "list[stix2.v21._STIXBase21]",
        author: "stix2.Identity",
        markings: "list[stix2.MarkingDefinition]",
    ) -> None:
        """Process a bundle of STIX objects in a batch.

        Args:
            event_id: ID of the event
            bundle_objects: list of STIX objects to process
            author: Author of the event
            markings: Markings of the event
        """
        bundle_size = len(bundle_objects)
        current_state = self.work_manager.get_state()
        remaining_objects_count = (
            current_state.get("remaining_objects_count") or bundle_size
        )
        object_index = bundle_size - remaining_objects_count
        batch_chunk_size = self.config.misp.batch_count
        for i in range(
            object_index,
            bundle_size,
            batch_chunk_size,
        ):
            now = datetime.now(tz=timezone.utc)
            self.batch_processor.work_name_template = (
                f"MISP run @ {now.isoformat(timespec='seconds')}"
                f" - Event # {event.Event.id}"
                f" - Batch # {max(1, i // batch_chunk_size)}"
                f" / {max(1, bundle_size // batch_chunk_size)}"
            )

            bundle_objects_chunk = bundle_objects[i : i + batch_chunk_size]
            self._check_and_add_entities_to_batch(
                bundle_objects_chunk, author, markings
            )

            new_state: dict = {}
            if self.config.misp.datetime_attribute == "date":
                new_state["current_event_id"] = event.Event.id

            remaining_objects_count = max(
                0, remaining_objects_count - len(bundle_objects_chunk)
            )
            new_state["remaining_objects_count"] = remaining_objects_count
            self.work_manager.update_state(state_update=new_state)

        # Flush any remaining items and Update the final state
        self._flush_batch_processor()
        self.work_manager.update_state(state_update={"remaining_objects_count": 0})

    def process_events(self) -> str | None:
        """Fetch, convert and send MISP events."""

        try:
            initial_state = self.helper.get_state() or {}
            self.logger.info(
                "Retrieved state",
                {"prefix": LOG_PREFIX, "initial_state": initial_state},
            )

            self.logger.info("Starting MISP full ingestion...", {"prefix": LOG_PREFIX})

            now = datetime.now(tz=timezone.utc)
            self.helper.metric.inc("run_count")
            self.helper.metric.state("running")

            if last_event := initial_state.get("last_event_date"):
                last_event_date = datetime.fromisoformat(last_event)
                self.logger.info(
                    "Current state of the connector:",
                    {
                        "prefix": LOG_PREFIX,
                        "last_event": last_event,
                    },
                )
            else:
                last_event_date = self.config.misp.import_from_date or now
                self.logger.info("Connector has never run")

            filter_params = {
                "date_field_filter": self.config.misp.date_filter_field,
                "date_value_filter": last_event_date,
                "datetime_attribute": self.config.misp.datetime_attribute,
                "keyword": self.config.misp.import_keyword,
                "included_tags": self.config.misp.import_tags,
                "excluded_tags": self.config.misp.import_tags_not,
                "included_org_creators": self.config.misp.import_creator_orgs,
                "excluded_org_creators": self.config.misp.import_creator_orgs_not,
                "enforce_warning_list": self.config.misp.enforce_warning_list,
                "with_attachments": self.config.misp.import_with_attachments,
            }

            self.logger.info(
                "Fetching MISP events with filters:",
                {"prefix": LOG_PREFIX, **filter_params},
            )

            curr_event_date = None
            try:
                for event in self.client_api.search_events(**filter_params):
                    event_log_data = {
                        "prefix": LOG_PREFIX,
                        "event_id": event.Event.id,
                        "event_uuid": event.Event.uuid,
                    }

                    if not self._validate_event(event):
                        continue

                    curr_event_date = self._get_event_datetime(event).isoformat()
                    new_state = {"last_event_date": curr_event_date}

                    self.work_manager.update_state(state_update=new_state)

                    if self.work_manager.check_connector_buffering():
                        self.logger.info(
                            "Connector is buffering, this event will be processed in the next scheduler process",
                            event_log_data,
                        )
                        break

                    self.logger.info("MISP event found - Processing...", event_log_data)
                    try:
                        author, markings, bundle_objects = self.converter.process(
                            event=event,
                            include_relationships=(
                                len(event.Event.Attribute or [])
                                + len(event.Event.Object or [])
                            )
                            # TODO: Add a configuration for the maximum number of attributes and objects
                            < 10000,
                        )
                    except ConverterError as err:
                        self.logger.error(
                            f"Error while converting MISP event, skipping it. {err}",
                            event_log_data,
                        )
                        continue

                    self.logger.debug(
                        "Converted to STIX entities",
                        {
                            "prefix": LOG_PREFIX,
                            "entities_count": len(bundle_objects + markings + [author]),
                        },
                    )

                    self._process_bundle_in_batch(
                        event=event,
                        bundle_objects=bundle_objects,
                        author=author,
                        markings=markings,
                    )

                else:
                    if self.config.misp.datetime_attribute != "date":
                        # If the datetime attribute is not date, we need to update
                        # the last event date to avoid processing the same event again

                        if curr_event_date is None:
                            self.logger.debug(
                                "No event date found, skipping update of last event date",
                                {
                                    "prefix": LOG_PREFIX,
                                },
                            )
                            return None

                        last_event_date = curr_event_date

                        last_event_datetime = datetime.fromisoformat(last_event_date)
                        # Check if the last event date is not the same as the current time
                        if last_event_datetime != now:
                            # Add 1 second to the last event date to avoid processing the same event again
                            last_event_datetime += timedelta(seconds=1)
                            self.logger.debug(
                                "Updating last event date (add 1 second) to avoid processing the same event again",
                                {
                                    "prefix": LOG_PREFIX,
                                    "last_event_date": last_event_datetime.isoformat(),
                                },
                            )
                            new_state = {
                                "last_event_date": last_event_datetime.isoformat()
                            }
                            self.work_manager.update_state(state_update=new_state)

                        else:
                            self.logger.debug(
                                "Last event date is the same as the current time, skipping update of last event date",
                                {
                                    "prefix": LOG_PREFIX,
                                    "last_event_date": last_event_datetime.isoformat(),
                                },
                            )

            finally:
                self._flush_batch_processor()

            return None

        except Exception as e:
            error_msg = f"MISP events processing failed: {e}"
            self.logger.error(
                "MISP events processing failed",
                {"prefix": LOG_PREFIX, "error": str(e)},
            )
            return error_msg

    def process(self) -> None:
        """Connector main process to collect intelligence."""
        error_flag = False
        error_message = None

        try:
            error_result = self.process_events()
            if error_result:
                error_message = error_result
                error_flag = True

        except MISPClientError as err:
            self.helper.connector_logger.error(err)
            self.helper.metric.inc("client_error_count")

            error_message = f"MISP client error: {err}"
            error_flag = True

        except (KeyboardInterrupt, SystemExit):
            error_message = "Connector stopped due to user interrupt"
            self.logger.info(
                "Connector stopped due to user interrupt",
                {"prefix": LOG_PREFIX, "connector_name": self.helper.connect_name},
            )
            error_flag = True
            raise

        except MispWorkProcessingError as work_err:
            error_message = f"Work processing error: {work_err}"
            work_id = getattr(
                work_err, "work_id", self.work_manager.get_current_work_id()
            )
            self.logger.warning(
                "Work processing error",
                meta={
                    "prefix": LOG_PREFIX,
                    "error": str(work_err),
                    "work_id": work_id,
                },
            )
            error_flag = True

        except Exception as err:
            error_message = f"Unexpected error: {err}"
            self.logger.error(
                "Unexpected error",
                {"prefix": LOG_PREFIX, "error": str(err)},
            )
            error_flag = True

        finally:
            self.helper.metric.state("idle")
            self.logger.info(
                "Connector stopped",
                {"prefix": LOG_PREFIX, "connector_name": self.helper.connect_name},
            )
            try:
                self.work_manager.process_all_remaining_works(
                    error_flag=error_flag, error_message=error_message
                )
                self.logger.info(
                    "All remaining works marked to process", {"prefix": LOG_PREFIX}
                )
            except Exception as cleanup_err:
                self.logger.error(
                    "Error during cleanup",
                    meta={"prefix": LOG_PREFIX, "error": str(cleanup_err)},
                )

    def run(self) -> None:
        """
        Run the main process encapsulated in a scheduler
        It allows you to schedule the process to run at a certain intervals
        This specific scheduler from the pycti connector helper will also check the queue size of a connector
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
