"""Report-specific orchestrator for fetching and processing report data."""

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any

from api_client.models import EventRestSearchListItem
from connector.threats_guesser import ThreatsGuesser
from connector.use_cases import EventConverter
from utils.batch_processors.configs import EVENT_BATCH_PROCESSOR_CONFIG
from utils.batch_processors.generic_batch_processor import GenericBatchProcessor
from utils.orchestrators import BaseOrchestrator

if TYPE_CHECKING:
    from connector.settings import MispConfig
    from utils.protocols import LoggerProtocol
    from utils.work_manager import WorkManager

LOG_PREFIX = "[OrchestratorEvent]"


class OrchestratorEvent(BaseOrchestrator):
    """Event-specific orchestrator for fetching and processing event data."""

    def __init__(
        self,
        work_manager: "WorkManager",
        logger: "LoggerProtocol",
        config: "MispConfig",
    ) -> None:
        """Initialize the Event Orchestrator.

        Args:
            work_manager: Work manager for handling OpenCTI work operations
            logger: Logger instance for logging
            config: Configuration object containing connector settings

        """
        super().__init__(work_manager, logger, config)

        self.logger.info(
            "API URL",
            {"prefix": LOG_PREFIX, "api_url": self.config.url.unicode_string()},
        )
        self.logger.info(
            "Event import start date",
            {"prefix": LOG_PREFIX, "start_date": self.config.import_from_date},
        )

        self.converter = EventConverter(
            logger=self.logger,
            report_type=self.config.report_type,
            report_description_attribute_filters=self.config.report_description_attribute_filters,
            external_reference_base_url=self.config.reference_url or self.config.url,
            convert_event_to_report=self.config.create_reports,
            convert_attribute_to_associated_file=self.config.import_with_attachments,
            convert_attribute_to_indicator=self.config.create_indicators,
            convert_attribute_to_observable=self.config.create_observables,
            convert_object_to_observable=self.config.create_object_observables,
            convert_unsupported_object_to_text_observable=self.config.import_unsupported_observables_as_text,
            convert_unsupported_object_to_transparent_text_observable=self.config.import_unsupported_observables_as_text_transparent,
            convert_tag_to_author=self.config.author_from_tags,
            convert_tag_to_label=self.config.create_tags_as_labels,
            convert_tag_to_marking=self.config.markings_from_tags,
            propagate_report_labels=self.config.propagate_labels,
            original_tags_to_keep_as_labels=self.config.keep_original_tags_as_label,
            default_attribute_score=self.config.import_to_ids_no_score,
            guess_threats_from_tags=self.config.guess_threats_from_tags,
            threats_guesser=(
                ThreatsGuesser(self.work_manager.opencti_api)
                if self.config.guess_threats_from_tags
                else None
            ),
        )
        self.batch_processor: GenericBatchProcessor = self._create_batch_processor()

    def _create_batch_processor(self) -> GenericBatchProcessor:
        """Create and configure the batch processor.

        Returns:
            Configured GenericBatchProcessor instance

        """
        return GenericBatchProcessor(
            work_manager=self.work_manager,
            config=EVENT_BATCH_PROCESSOR_CONFIG,
            logger=self.logger,
        )

    def _validate_event(self, event: EventRestSearchListItem) -> bool:
        """Validate the event.

        Args:
            event: The event to validate

        Returns:
            True if the event is valid, False otherwise

        """
        if (
            self.config.import_owner_orgs
            and event.Event.Org.name not in self.config.import_owner_orgs
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
            self.config.import_owner_orgs_not
            and event.Event.Org.name in self.config.import_owner_orgs_not
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
            self.config.import_distribution_levels
            and event.Event.distribution not in self.config.import_distribution_levels
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
            self.config.import_threat_levels
            and event.Event.threat_level_id not in self.config.import_threat_levels
        ):
            self.logger.info(
                "Event threat level not in `MISP_IMPORT_THREAT_LEVELS`, skipping event",
                {
                    "prefix": LOG_PREFIX,
                    "event_threat_level": event.Event.threat_level_id,
                },
            )
            return False

        if self.config.import_only_published and not event.Event.published:
            self.logger.info(
                "Event not published and `MISP_IMPORT_ONLY_PUBLISHED` enabled, skipping event",
                {
                    "prefix": LOG_PREFIX,
                    "event_published": event.Event.published,
                },
            )
            return False

        return True

    def run(self, initial_state: dict[str, Any] | None) -> None:
        """Run the event orchestrator.

        Args:
            initial_state: Initial state for the orchestrator

        """
        now = datetime.now(tz=timezone.utc)

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
            last_event_date = self.config.import_from_date or now
            self.batch_processor.set_latest_date(last_event_date.isoformat())
            self.batch_processor.update_final_state()
            self.logger.info("Connector has never run")

        next_event_date = last_event_date + timedelta(seconds=1)
        self.logger.info(
            "Fetching MISP events with filters:",
            {
                "prefix": LOG_PREFIX,
                "date_field_filter": self.config.date_filter_field,
                "date_value_filter": next_event_date,
                "keyword": self.config.import_keyword,
                "included_tags": self.config.import_tags,
                "excluded_tags": self.config.import_tags_not,
                "included_org_creators": self.config.import_creator_orgs,
                "excluded_org_creators": self.config.import_creator_orgs_not,
                "enforce_warning_list": self.config.enforce_warning_list,
                "with_attachments": self.config.import_with_attachments,
            },
        )

        date_attr_used = self.config.datetime_attribute == "date"
        try:
            last_event_datetime = None
            date_changed = False
            bundle_split = False
            for event_index, event in enumerate(
                self.client_api.search_events(
                    date_field_filter=self.config.date_filter_field,
                    date_value_filter=next_event_date,
                    datetime_attribute=self.config.datetime_attribute,
                    keyword=self.config.import_keyword,
                    included_tags=self.config.import_tags,
                    excluded_tags=self.config.import_tags_not,
                    included_org_creators=self.config.import_creator_orgs,
                    excluded_org_creators=self.config.import_creator_orgs_not,
                    enforce_warning_list=self.config.enforce_warning_list,
                    with_attachments=self.config.import_with_attachments,
                )
            ):
                if not self._validate_event(event):
                    continue

                self.logger.info(
                    "MISP event found",
                    {
                        "prefix": LOG_PREFIX,
                        "event_id": event.Event.id,
                        "event_uuid": event.Event.uuid,
                    },
                )

                author, markings, bundle_objects = self.converter.process(
                    event=event,
                    include_relationships=(
                        len(event.Event.Attribute or []) + len(event.Event.Object or [])
                    )
                    # TODO: Add a configuration for the maximum number of attributes and objects
                    < 10000,
                )

                event_datetime_value = getattr(
                    event.Event, self.config.datetime_attribute
                )
                if self.config.datetime_attribute in {
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

                if last_event_datetime is None or event_datetime > last_event_datetime:
                    last_event_datetime = event_datetime
                    date_changed = True
                    if date_attr_used and bundle_split:
                        # If a previous event bundle was split and the date changed,
                        # then update the final state and stop process (to avoid flooding the queue)
                        self.batch_processor.set_latest_date(
                            # Subtract 2 seconds to ensure this event will be
                            # processed in the next scheduler process
                            (event_datetime - timedelta(seconds=2)).isoformat()
                        )
                        break
                else:
                    date_changed = False

                self._log_entities_summary(bundle_objects, 0, 1)

                if len(bundle_objects) > self.batch_processor.config.batch_size:
                    if (
                        not date_attr_used or date_changed
                    ) and self.work_manager._helper.check_connector_buffering():
                        self.logger.info(
                            "Connector is buffering, this event will be splitted in the next scheduler process",
                            {
                                "prefix": LOG_PREFIX,
                                "event_id": event.Event.id,
                                "event_uuid": event.Event.uuid,
                            },
                        )
                        break

                    bundle_split = True
                    self.logger.info(
                        "Bundle objects count is greater than the batch size, splitting the bundle",
                        {
                            "prefix": LOG_PREFIX,
                            "bundle_objects_count": len(bundle_objects),
                            "batch_size": self.batch_processor.config.batch_size,
                        },
                    )

                    for i in range(
                        0, len(bundle_objects), self.batch_processor.config.batch_size
                    ):
                        bundle_objects_chunk = bundle_objects[
                            i : i + self.batch_processor.config.batch_size
                        ]
                        self.batch_processor.config.work_name_template = (
                            f"MISP run @ {now.isoformat(timespec='seconds')}"
                            f" - Event # {event_index + 1}"
                            f" - Batch # {i // self.batch_processor.config.batch_size}"
                            f" / {len(bundle_objects) // self.batch_processor.config.batch_size}"
                        )

                        self._check_batch_size_and_flush(
                            self.batch_processor, bundle_objects_chunk
                        )
                        self._add_entities_to_batch(
                            self.batch_processor, bundle_objects_chunk, author, markings
                        )

                    # Flush the remaining items and Update the final state
                    self.batch_processor.set_latest_date(event_datetime.isoformat())
                    self._flush_batch_processor()

                    if not date_attr_used:
                        # If the `date` attribute is not used, update the final state and stop process (to avoid flooding the queue)
                        self.batch_processor.update_final_state()
                        break

                else:
                    self.batch_processor.config.work_name_template = f"MISP run @ {now.isoformat(timespec='seconds')} - Event # {event_index + 1}"
                    # Normal case: One event => One work in queue
                    self._add_entities_to_batch(
                        self.batch_processor, bundle_objects, author, markings
                    )

                    # Flush the remaining items and Update the final state
                    self.batch_processor.set_latest_date(event_datetime.isoformat())
                    self._flush_batch_processor()
            else:
                # All events were processed
                if last_event_datetime is not None and date_attr_used:
                    # If the `date` attribute is used, set the latest date to the next day,
                    # otherwise the same event will be processed again
                    self.batch_processor.set_latest_date(
                        (last_event_datetime + timedelta(days=1)).isoformat()
                    )

        finally:
            self._flush_batch_processor()

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
