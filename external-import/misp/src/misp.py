import math
import sys
import traceback
from datetime import datetime, timezone

import stix2
from api_client.client import MISPClient, MISPClientError
from api_client.models import EventRestSearchListItem
from connector.config_loader import ConfigLoader
from connector.threats_guesser import ThreatsGuesser
from connector.use_cases import EventConverter
from pycti import OpenCTIConnectorHelper


class Misp:
    def __init__(self):
        self.config = ConfigLoader()
        self.helper = OpenCTIConnectorHelper(self.config.model_dump_pycti())

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

    def process(self):
        """Connector main process to collect intelligence."""
        try:
            now = datetime.now(tz=timezone.utc)
            friendly_name = "MISP run @ " + now.isoformat()
            self.helper.metric.inc("run_count")
            self.helper.metric.state("running")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )
            current_state = self.helper.get_state()
            if (
                current_state is not None
                and "last_run" in current_state
                and "last_event_timestamp" in current_state
                and "last_event" in current_state
            ):
                last_run = datetime.fromisoformat(current_state["last_run"])
                last_event = datetime.fromisoformat(current_state["last_event"])
                last_event_timestamp = current_state["last_event_timestamp"]
                self.helper.connector_logger.info(
                    "Current state of the connector:",
                    {
                        "last_run": current_state["last_run"],
                        "last_event": current_state["last_event"],
                    },
                )

            elif current_state and "last_run" in current_state:
                last_run = datetime.fromisoformat(current_state["last_run"])
                last_event = last_run
                last_event_timestamp = int(last_event.timestamp())
                self.helper.connector_logger.info(
                    "Current state of the connector:",
                    {
                        "last_run": current_state["last_run"],
                        "last_event": current_state[
                            "last_run"
                        ],  # last_event == last_run
                    },
                )
            else:
                if self.config.misp.import_from_date:
                    last_event = self.config.misp.import_from_date
                    last_event_timestamp = int(last_event.timestamp())
                else:
                    last_event = now
                    last_event_timestamp = int(now.timestamp())
                self.helper.connector_logger.info("Connector has never run")

            # Put the date
            next_event_timestamp = last_event_timestamp + 1

            # Query with pagination of 10
            current_state = self.helper.get_state()
            if current_state is not None and "current_page" in current_state:
                current_page = current_state["current_page"]
            else:
                current_page = 1
            # Query all events
            self.helper.connector_logger.info(
                "Fetching MISP events with filters:",
                {
                    "date_field_filter": self.config.misp.date_filter_field,
                    "date_value_filter": next_event_date,
                    "keyword": self.config.misp.import_keyword,
                    "included_tags": self.config.misp.import_tags,
                    "excluded_tags": self.config.misp.import_tags_not,
                    "enforce_warning_list": self.config.misp.enforce_warning_list,
                    "with_attachments": self.config.misp.import_with_attachments,
                },
            )

            self.helper.connector_logger.info(
                "Fetching MISP events with filters:",
                {
                    "date_attribute_filter": self.config.misp.date_filter_field,
                    "date_value_filter": next_event_timestamp,
                    "keyword": self.config.misp.import_keyword,
                    "included_tags": self.config.misp.import_tags,
                    "excluded_tags": self.config.misp.import_tags_not,
                    "enforce_warning_list": self.config.misp.enforce_warning_list,
                    "with_attachments": self.config.misp.import_with_attachments,
                    # omit "limit" and "page" on purpose to avoid confusion about the number of expected results
                },
            )

            events = []
            try:
                events = self.client.search_events(
                    date_field_filter=self.config.misp.date_filter_field,
                    date_value_filter=next_event_date,
                    keyword=self.config.misp.import_keyword,
                    included_tags=self.config.misp.import_tags,
                    excluded_tags=self.config.misp.import_tags_not,
                    enforce_warning_list=self.config.misp.enforce_warning_list,
                    with_attachments=self.config.misp.import_with_attachments,
                    limit=10,
                    page=current_page,
                )
            except MISPClientError as err:
                self.helper.connector_logger.error(
                    f"Error fetching misp event: {err}", {"error": err}
                )
                self.helper.metric.inc("client_error_count")
                try:
                    # TODO: add a real retry mechanism
                    events = self.client.search_events(
                        date_attribute_filter=self.config.misp.date_filter_field,
                        date_value_filter=next_event_timestamp,
                        keyword=self.config.misp.import_keyword,
                        included_tags=self.config.misp.import_tags,
                        excluded_tags=self.config.misp.import_tags_not,
                        enforce_warning_list=self.config.misp.enforce_warning_list,
                        with_attachments=self.config.misp.import_with_attachments,
                        limit=10,
                        page=current_page,
                    )
                except MISPClientError as err:
                    self.helper.connector_logger.error(
                        f"Error fetching misp event again: {err}", {"error": err}
                    )
                    self.helper.metric.inc("client_error_count")
                    raise err

            self.helper.connector_logger.info(
                "MISP events found:", {"events_count": len(events)}
            )

            # Process the event
            processed_events_last_timestamp = self.process_events(work_id, events)
            if (
                processed_events_last_timestamp is not None
                and processed_events_last_timestamp > last_event_timestamp
            ):
                last_event_timestamp = processed_events_last_timestamp

            success_message = "Connector ran successfully"
            self.helper.connector_logger.info(
                success_message, {"processed_events_count": len(events)}
            )
            self.helper.api.work.to_processed(work_id, success_message)

            # Update state
            current_page = math.ceil(len(events) / 10)  # Each page contains 10 events
            if current_state is not None:
                current_state["current_page"] = current_page
            else:
                current_state = {"current_page": current_page}
            self.helper.set_state(current_state)

            # Loop is over, storing the state
            # We cannot store the state before, because MISP events are NOT ordered properly
            # and there is NO WAY to order them using their library
            current_state = {
                "last_run": now.isoformat(),
                "last_event": datetime.fromtimestamp(
                    last_event_timestamp, tz=timezone.utc
                ).isoformat(),
                "last_event_timestamp": last_event_timestamp,
                "current_page": 1,
            }
            self.helper.set_state(current_state)
            self.helper.connector_logger.info(
                "Updating connector state as:", current_state
            )

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "Connector stopped by user or system",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(
                "Unexpected error. See connector's log for more details.",
                {"error": err},
            )

        finally:
            self.helper.metric.state("idle")

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

    def process_events(self, work_id, events: list[EventRestSearchListItem]):
        last_event_timestamp = None
        for event in events:
            self.helper.connector_logger.info(
                "Processing event", {"event_uuid": event.Event.uuid}
            )
            event_timestamp = int(
                # Line below will raise if `self.config.misp.datetime_attribute`` is not a valid field (i.e. defined in MISP models)
                # This behavior is expected as it would mean that config/env vars are not validated correctly
                getattr(event.Event, self.config.misp.datetime_attribute)
            )

            # Need to check if timestamp is more recent than the previous event since
            # events are not ordered by timestamp in API response
            if last_event_timestamp is None or event_timestamp > last_event_timestamp:
                last_event_timestamp = event_timestamp

            # Check against filter
            if (
                self.config.misp.import_creator_orgs
                and event.Event.Orgc.name not in self.config.misp.import_creator_orgs
            ):
                self.helper.connector_logger.info(
                    "Event creator Organization not in `MISP_IMPORT_CREATOR_ORGS`, skipping event",
                    {"event_creator_organization": event.Event.Orgc.name},
                )
                continue
            if (
                self.config.misp.import_creator_orgs_not
                and event.Event.Orgc.name in self.config.misp.import_creator_orgs_not
            ):
                self.helper.connector_logger.info(
                    "Event creator Organization in `MISP_IMPORT_CREATOR_ORGS_NOT`, skipping event",
                    {"event_creator_organization": event.Event.Orgc.name},
                )
                continue
            if (
                self.config.misp.import_owner_orgs
                and event.Event.Org.name not in self.config.misp.import_owner_orgs
            ):
                self.helper.connector_logger.info(
                    "Event owner Organization not in `MISP_IMPORT_OWNER_ORGS`, skipping event",
                    {"event_owner_organization": event.Event.Org.name},
                )
                continue
            if (
                self.config.misp.import_owner_orgs_not
                and event.Event.Org.name in self.config.misp.import_owner_orgs_not
            ):
                self.helper.connector_logger.info(
                    "Event owner Organization in `MISP_IMPORT_OWNER_ORGS_NOT`, skipping event",
                    {"event_owner_organization": event.Event.Org.name},
                )
                continue
            if (
                self.config.misp.import_distribution_levels
                and event.Event.distribution
                not in self.config.misp.import_distribution_levels
            ):
                self.helper.connector_logger.info(
                    "Event distribution level not in `MISP_IMPORT_DISTRIBUTION_LEVELS`, skipping event",
                    {"event_distribution_level": event.Event.distribution},
                )
                continue
            if (
                self.config.misp.import_threat_levels
                and event.Event.threat_level_id
                not in self.config.misp.import_threat_levels
            ):
                self.helper.connector_logger.info(
                    "Event threat level not in `MISP_IMPORT_THREAT_LEVELS`, skipping event",
                    {"event_threat_level": event.Event.threat_level_id},
                )
                continue
            if self.config.misp.import_only_published and not event.Event.published:
                self.helper.connector_logger.info(
                    "Event not published and `MISP_IMPORT_ONLY_PUBLISHED` enabled, skipping event",
                    {"event_published": event.Event.published},
                )
                continue

            bundle_objects = self.converter.process(event)

            bundle = stix2.Bundle(objects=bundle_objects, allow_custom=True).serialize()
            self.helper.connector_logger.info("Sending event STIX2 bundle")

            sent_bundles = self.helper.send_stix2_bundle(bundle, work_id=work_id)
            self.helper.connector_logger.info(
                "Sent STIX2 bundles:", {"sent_bundles_count": len(sent_bundles)}
            )
            self.helper.metric.inc("record_send", len(bundle_objects))
        return last_event_timestamp


if __name__ == "__main__":
    try:
        mispConnector = Misp()
        mispConnector.run()
    except Exception:
        traceback.print_exc()
        sys.exit(1)
