from datetime import datetime, timezone
from typing import TYPE_CHECKING

from api_client.client import MISPClient, MISPClientError
from connector.threats_guesser import ThreatsGuesser
from connector.use_cases import ConverterError, EventConverter
from exceptions.connector_errors import MispWorkProcessingError
from utils.batch_processors import GenericBatchProcessor, GenericBatchProcessorConfig
from utils.batch_processors.configs.batch_processor_config_event import (
    log_batch_completion,
    validate_stix_object,
)
from utils.work_manager import WorkManager

if TYPE_CHECKING:
    import stix2
    from api_client.models import EventRestSearchListItem
    from connector.settings import ConnectorSettings, MispConfig
    from pycti import OpenCTIConnectorHelper

LOG_PREFIX = "[Connector]"


class Misp:
    def __init__(self, config: "ConnectorSettings", helper: "OpenCTIConnectorHelper"):
        self.config = config
        self.config_misp: MispConfig = config.misp

        self.helper = helper
        self.logger = helper.connector_logger

        self.client_api: MISPClient = MISPClient(
            url=self.config_misp.url,
            key=self.config_misp.key.get_secret_value(),
            verify_ssl=self.config_misp.ssl_verify,
            certificate=self.config_misp.client_cert,
        )

        self.converter = EventConverter(
            logger=self.logger,
            report_type=self.config_misp.report_type,
            report_description_attribute_filters=self.config_misp.report_description_attribute_filters,
            external_reference_base_url=self.config_misp.reference_url
            or self.config_misp.url,
            convert_event_to_report=self.config_misp.create_reports,
            convert_attribute_to_associated_file=self.config_misp.import_with_attachments,
            convert_attribute_to_indicator=self.config_misp.create_indicators,
            convert_attribute_to_observable=self.config_misp.create_observables,
            convert_object_to_observable=self.config_misp.create_object_observables,
            convert_unsupported_object_to_text_observable=self.config_misp.import_unsupported_observables_as_text,
            convert_unsupported_object_to_transparent_text_observable=self.config_misp.import_unsupported_observables_as_text_transparent,
            convert_tag_to_author=self.config_misp.author_from_tags,
            convert_tag_to_label=self.config_misp.create_tags_as_labels,
            convert_tag_to_marking=self.config_misp.markings_from_tags,
            propagate_report_labels=self.config_misp.propagate_labels,
            original_tags_to_keep_as_labels=self.config_misp.keep_original_tags_as_label,
            default_attribute_score=self.config_misp.import_to_ids_no_score,
            guess_threats_from_tags=self.config_misp.guess_threats_from_tags,
            threats_guesser=(
                ThreatsGuesser(self.helper.api)
                if self.config_misp.guess_threats_from_tags
                else None
            ),
        )

        self.work_manager = WorkManager(self.config, self.helper, self.logger)
        self.batch_processor: "GenericBatchProcessor" = self._create_batch_processor()

    def _create_batch_processor(self) -> "GenericBatchProcessor":
        """Create and configure the batch processor.

        Returns:
            Configured GenericBatchProcessor instance

        """
        processor_config = GenericBatchProcessorConfig(
            batch_size=self.config.batch.chunk_size,
            work_name_template="MISP - Batch #{batch_num}",
            state_key="last_event_date",
            entity_type="stix_objects",
            display_name="STIX objects",
            exception_class=MispWorkProcessingError,
            display_name_singular="STIX object",
            auto_process=False,
            postprocessing_function=log_batch_completion,
            validation_function=validate_stix_object,
            empty_batch_behavior="update_state",
        )
        return GenericBatchProcessor(
            work_manager=self.work_manager,
            config=processor_config,
            logger=self.logger,
        )

    def _log_entities_summary(
        self,
        all_entities: "list[stix2.v21._STIXBase21]",
    ) -> None:
        """Log summary of converted entities.

        Args:
            all_entities: list of all converted entities
            current_idx: Current index in processing
            total: Total number of entities

        """
        entity_types: dict[str, int] = {}
        for entity in all_entities:
            entity_type_attr = getattr(entity, "type", None)
            if entity_type_attr:
                entity_types[entity_type_attr] = (
                    entity_types.get(entity_type_attr, 0) + 1
                )
        entities_summary = ", ".join([f"{k}: {v}" for k, v in entity_types.items()])
        self.logger.info(
            "Converted to STIX entities",
            {
                "prefix": LOG_PREFIX,
                "entities_count": len(all_entities),
                "entities_summary": entities_summary,
            },
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
        ) >= self.config.batch.chunk_size * 2:
            self.logger.info(
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
                self.logger.info(
                    "Batch processor: Flushed remaining items",
                    {"prefix": LOG_PREFIX},
                )
            self.batch_processor.update_final_state()
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
            self.config_misp.import_owner_orgs
            and event.Event.Org.name not in self.config_misp.import_owner_orgs
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
            self.config_misp.import_owner_orgs_not
            and event.Event.Org.name in self.config_misp.import_owner_orgs_not
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
            self.config_misp.import_distribution_levels
            and event.Event.distribution
            not in self.config_misp.import_distribution_levels
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
            self.config_misp.import_threat_levels
            and event.Event.threat_level_id not in self.config_misp.import_threat_levels
        ):
            self.logger.info(
                "Event threat level not in `MISP_IMPORT_THREAT_LEVELS`, skipping event",
                {
                    "prefix": LOG_PREFIX,
                    "event_threat_level": event.Event.threat_level_id,
                },
            )
            return False

        if self.config_misp.import_only_published and not event.Event.published:
            self.logger.info(
                "Event not published and `MISP_IMPORT_ONLY_PUBLISHED` enabled, skipping event",
                {
                    "prefix": LOG_PREFIX,
                    "event_published": event.Event.published,
                },
            )
            return False

        return True

    def _process_bundle_in_batch(
        self,
        event_id: str,
        bundle_objects: "list[stix2.v21._STIXBase21]",
        author: "stix2.Identity",
        markings: "list[stix2.MarkingDefinition]",
        remaining_objects_count: int,
    ) -> None:
        """Process a bundle of STIX objects in a batch.

        Args:
            event_id: ID of the event
            bundle_objects: list of STIX objects to process
            author: Author of the event
            markings: Markings of the event
            remaining_objects_count: Number of remaining objects to process
        """
        bundle_size = len(bundle_objects)
        object_index = bundle_size - remaining_objects_count
        batch_chunk_size = self.config.batch.chunk_size
        for i in range(
            object_index,
            bundle_size,
            batch_chunk_size,
        ):
            now = datetime.now(tz=timezone.utc)
            self.batch_processor.config.work_name_template = (
                f"MISP run @ {now.isoformat(timespec='seconds')}"
                f" - Event # {event_id}"
                f" - Batch # {i // batch_chunk_size}"
                f" / {len(bundle_objects) // batch_chunk_size}"
            )

            bundle_objects_chunk = bundle_objects[i : i + batch_chunk_size]
            self._check_and_add_entities_to_batch(
                bundle_objects_chunk, author, markings
            )
            remaining_objects_count = max(
                0, remaining_objects_count - len(bundle_objects_chunk)
            )
            self.work_manager.update_state(
                state_update={"remaining_objects_count": remaining_objects_count}
            )

        # Flush any remaining items and Update the final state
        self._flush_batch_processor()

    def process_event(self) -> str | None:
        """Setup and run the orchestrator to process MISP events."""

        try:
            initial_state = self.helper.get_state()
            self.logger.info(
                "Retrieved state",
                {"prefix": LOG_PREFIX, "initial_state": initial_state},
            )

            self.logger.info("Starting MISP full ingestion...", {"prefix": LOG_PREFIX})

            now = datetime.now(tz=timezone.utc)
            self.helper.metric.inc("run_count")
            self.helper.metric.state("running")

            if initial_state is not None and (
                last_event := initial_state.get(self.batch_processor.config.state_key)
            ):
                last_event_date = datetime.fromisoformat(last_event)
                self.logger.info(
                    "Current state of the connector:",
                    {
                        "prefix": LOG_PREFIX,
                        "last_event": last_event,
                    },
                )
            else:
                last_event_date = self.config_misp.import_from_date or now
                self.batch_processor.set_latest_date(last_event_date.isoformat())
                self.batch_processor.update_final_state()
                self.logger.info("Connector has never run")

            filter_params = {
                "date_field_filter": self.config_misp.date_filter_field,
                "date_value_filter": last_event_date,
                "datetime_attribute": self.config_misp.datetime_attribute,
                "keyword": self.config_misp.import_keyword,
                "included_tags": self.config_misp.import_tags,
                "excluded_tags": self.config_misp.import_tags_not,
                "included_org_creators": self.config_misp.import_creator_orgs,
                "excluded_org_creators": self.config_misp.import_creator_orgs_not,
                "enforce_warning_list": self.config_misp.enforce_warning_list,
                "with_attachments": self.config_misp.import_with_attachments,
            }

            self.logger.info(
                "Fetching MISP events with filters:",
                {"prefix": LOG_PREFIX, **filter_params},
            )

            date_attr_used = self.config_misp.datetime_attribute == "date"
            last_event_datetime = None
            try:
                for event in self.client_api.search_events(**filter_params):
                    event_log_data = {
                        "prefix": LOG_PREFIX,
                        "event_id": event.Event.id,
                        "event_uuid": event.Event.uuid,
                    }
                    if self.work_manager.check_connector_buffering():
                        self.logger.info(
                            "Connector is buffering, this event will be processed in the next scheduler process",
                            event_log_data,
                        )
                        break

                    if not self._validate_event(event):
                        continue

                    current_state = self.work_manager.get_state()
                    prev_event_id = current_state.get("current_event_id")
                    remaining_objects_count = current_state.get(
                        "remaining_objects_count"
                    )

                    if prev_event_id is not None and (
                        event.Event.id < prev_event_id
                        or (
                            event.Event.id == prev_event_id
                            and remaining_objects_count == 0
                        )
                    ):
                        self.logger.info(
                            "Event already processed, skipping", event_log_data
                        )
                        continue

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

                    self._log_entities_summary(bundle_objects)

                    event_datetime_value = getattr(
                        event.Event, self.config_misp.datetime_attribute
                    )
                    if self.config_misp.datetime_attribute in {
                        "timestamp",
                        "publish_timestamp",
                        "sighting_timestamp",
                    }:
                        event_datetime = datetime.fromtimestamp(
                            int(event_datetime_value), tz=timezone.utc
                        )
                    elif date_attr_used:
                        event_datetime = datetime.fromisoformat(
                            event_datetime_value
                        ).replace(tzinfo=timezone.utc)
                    else:
                        raise ValueError(
                            "`MISP_DATETIME_ATTRIBUTE` must be either: 'date', "
                            "'timestamp', 'publish_timestamp' or 'sighting_timestamp'"
                        )

                    if (
                        last_event_datetime is None
                        or event_datetime > last_event_datetime
                    ):
                        last_event_datetime = event_datetime
                        self.batch_processor.set_latest_date(event_datetime.isoformat())

                    if not remaining_objects_count:
                        remaining_objects_count = len(bundle_objects)
                        self.work_manager.update_state(
                            state_update={
                                "current_event_id": event.Event.id,
                                "remaining_objects_count": remaining_objects_count,
                            }
                        )

                    self._process_bundle_in_batch(
                        event_id=event.Event.id,
                        bundle_objects=bundle_objects,
                        author=author,
                        markings=markings,
                        remaining_objects_count=remaining_objects_count,
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
            error_result = self.process_event()
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
