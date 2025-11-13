import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

import tldextract
from pycti import (
    STIX_EXT_OCTI,
    STIX_EXT_OCTI_SCO,
    OpenCTIConnectorHelper,
    OpenCTIStix2,
)
from pymispwarninglists import WarningList, WarningLists
from src.connector.models import ConfigLoader


class HygieneConnector:
    def __init__(self, config: ConfigLoader, helper: OpenCTIConnectorHelper):

        self.config = config
        self.helper = helper

        # Multi-threading configuration
        self.max_workers = getattr(config.hygiene, "max_workers", 100)
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.max_workers, thread_name_prefix="HygieneWorker"
        )
        self.shutdown = False
        self.active_futures = []
        self.futures_lock = threading.Lock()

        # Statistics tracking
        self.stats = {
            "total_processed": 0,
            "total_hits": 0,
            "processing_time": 0,
            "errors": 0,
            "active_tasks": 0,
        }
        self.stats_lock = threading.Lock()

        self.enrich_subdomains = self.config.hygiene.enrich_subdomains

        self.hygiene_label_name = self.config.hygiene.label_name
        self.hygiene_label_parent_name = self.config.hygiene.label_parent_name

        self.hygiene_label_color = self.config.hygiene.label_color
        self.hygiene_label_parent_color = self.config.hygiene.label_parent_color

        self.warninglists_slow_search = self.config.hygiene.warninglists_slow_search
        self.helper.log_info(
            f"Warning lists slow search: {self.warninglists_slow_search}"
        )
        self.helper.log_info(f"Multi-threading enabled with {self.max_workers} workers")

        # Initialize warning lists with thread lock for thread safety
        self.warninglists_lock = threading.RLock()
        self.warninglists = WarningLists(slow_search=self.warninglists_slow_search)

        # Create Hygiene Tag
        self.label_hygiene = self.helper.api.label.read_or_create_unchecked(
            value=self.hygiene_label_name, color=self.hygiene_label_color
        )
        if self.label_hygiene is None:
            raise ValueError(
                "The hygiene label could not be created. If your connector does not have the permission to create labels, please create it manually before launching"
            )

        self.label_hygiene_parent = self.helper.api.label.read_or_create_unchecked(
            value=self.hygiene_label_parent_name, color=self.hygiene_label_parent_color
        )
        if self.label_hygiene_parent is None:
            raise ValueError(
                "The hygiene label could not be created. If your connector does not have the permission to create labels, please create it manually before launching"
            )

        self.helper.log_info(
            f"Thread pool initialized with {self.max_workers} max workers"
        )

    def _process_entity(self, stix_objects, stix_entity, opencti_entity) -> str:
        if opencti_entity["entity_type"] == "Indicator":
            # Extract the observable in the pattern
            observables = self._convert_indicator_to_observables(opencti_entity)

            return self._process_indicator(stix_objects, stix_entity, observables)

        else:
            return self._process_observable(stix_objects, stix_entity, opencti_entity)

    def _search_warninglists(self, value: str) -> List[WarningList]:
        """Thread-safe warning list search."""
        with self.warninglists_lock:
            return self.warninglists.search(value.lower())

    def _process_observable(
        self, stix_objects, stix_entity, opencti_entity
    ) -> Optional[str]:
        # Thread-safe warning list search
        warninglist_hits: List[WarningList] = self._search_warninglists(
            opencti_entity["observable_value"]
        )

        # If not found and the domain is a subdomain, search with the parent.
        use_parent, warninglist_hits = self.search_with_parent(
            warninglist_hits, stix_entity
        )

        # Iterate over the hits
        if warninglist_hits:
            score = self.process_result(
                warninglist_hits, stix_objects, stix_entity, opencti_entity, use_parent
            )
            warninglist_names = [
                warninglist_hit.name for warninglist_hit in warninglist_hits
            ]

            with self.stats_lock:
                self.stats["total_hits"] += 1

            return f"Observable value found on warninglists {warninglist_names} and tagged accordingly. Score set to {score}."
        return None

    def _process_indicator(
        self, stix_objects, stix_entity, observables
    ) -> Optional[str]:
        result = None
        for observable in observables:
            if observable.get("type") == "unsupported_type":
                continue
            # Thread-safe warning list search
            value = observable.get("value")
            warninglist_hits = self._search_warninglists(value) if value else []

            # If not found and the domain is a subdomain, search with the parent.
            use_parent, warninglist_hits = self.search_with_parent(
                warninglist_hits, observable
            )
            # Iterate over the hits
            if warninglist_hits:
                score = self.process_result(
                    warninglist_hits, stix_objects, stix_entity, observable, use_parent
                )
                warninglist_names = [
                    warninglist_hit.name for warninglist_hit in warninglist_hits
                ]
                # For loop with a return statement? What about the other observable values? Is it always just one observable?
                msg = f"Observable value found on warninglists {warninglist_names} and tagged. Score of {score} applied."
                self.helper.log_info(msg)

                with self.stats_lock:
                    self.stats["total_hits"] += 1

                result = msg
        return result

    def _convert_indicator_to_observables(self, data) -> Optional[list[dict]]:
        """
        Convert an OpenCTI indicator to its corresponding observables.
        :param data: OpenCTI indicator data
        :return: Observables data
        """
        try:
            observables = []

            parsed_observables = self.helper.get_attribute_in_extension(
                "x_opencti_observable_values", data
            )

            if parsed_observables:
                # Iterate over the parsed observables
                for observable in parsed_observables:
                    observable_data = {}
                    observable_data.update(data)

                    x_opencti_observable_type = observable.get("type").lower()

                    supported_attributes = [
                        "domain-name",
                        "stixfile",
                        "ipv4-addr",
                        "ipv6-addr",
                    ]
                    if x_opencti_observable_type not in supported_attributes:
                        self.helper.connector_logger.warning(
                            "[UNSUPPORTED ATTRIBUTE] Cannot scan { "
                            + x_opencti_observable_type
                            + "}"
                        )
                        observable_data["type"] = "unsupported_type"
                        observables.append(observable_data)
                    else:
                        observable_data["type"] = x_opencti_observable_type
                        observable_data["value"] = observable.get("value")
                        observables.append(observable_data)
            return observables
        except:
            indicator_opencti_id = OpenCTIConnectorHelper.get_attribute_in_extension(
                "id", data
            )
            self.helper.connector_logger.warning(
                "[CREATE] Cannot convert STIX indicator { " + indicator_opencti_id + "}"
            )
            return None

    def search_with_parent(
        self, result: List[WarningList], stix_entity: dict
    ) -> Tuple[bool, List[WarningList]]:
        use_parent = False
        if not result and self.enrich_subdomains is True:
            entity_type = (
                stix_entity.get("type", "").lower()
                if isinstance(stix_entity, dict)
                else ""
            )
            if entity_type == "domain-name":
                value = stix_entity.get("value")
                if value:
                    ext = tldextract.extract(value)
                    parent_domain = f"{ext.domain}.{ext.suffix}"
                    if value != parent_domain:
                        result = self._search_warninglists(parent_domain)
                    use_parent = True
        return use_parent, result

    def process_result(
        self,
        warninglist_hits: List[WarningList],
        stix_objects: list,
        stix_entity: dict,
        opencti_entity: dict,
        use_parent: bool,
    ) -> int:
        """Process warning list results. Returns the calculated score."""

        if opencti_entity["entity_type"] == "Indicator":
            self.helper.log_info(
                "Hit found for %s in warninglists" % (opencti_entity["value"])
            )
        else:
            self.helper.log_info(
                "Hit found for %s in warninglists"
                % (opencti_entity["observable_value"])
            )
        number_of_warninglist_hits = len(warninglist_hits)
        score = 20
        # We set the score based on the number of warning list entries
        if number_of_warninglist_hits >= 5:
            score = 5
        elif number_of_warninglist_hits >= 3:
            score = 10
        elif number_of_warninglist_hits == 1:
            score = 15

        for warninglist_hit in warninglist_hits:
            self.helper.log_info(
                "Type: %s | Name: %s | Version: %s | Descr: %s"
                % (
                    warninglist_hit.type,
                    warninglist_hit.name,
                    warninglist_hit.version,
                    warninglist_hit.description,
                )
            )

            self.helper.log_info(
                f"number of hits ({len(warninglist_hits)}) setting score to {score}"
            )

            # Add labels
            label_value = self.label_hygiene["value"]
            if use_parent:
                label_value = self.label_hygiene_parent["value"]
            self._add_label_to_entity(
                opencti_entity, stix_entity, label_value=label_value
            )

            # Update score
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity, STIX_EXT_OCTI_SCO, "score", score
            )

            if opencti_entity["entity_type"] != "Indicator":
                # Add indicators
                for indicator_id in opencti_entity["indicatorsIds"]:
                    stix_indicator = (
                        self.helper.api.stix2.get_stix_bundle_or_object_from_entity_id(
                            entity_type="Indicator",
                            entity_id=indicator_id,
                            only_entity=True,
                        )
                    )

                    # Add labels
                    if use_parent:
                        stix_indicator["labels"] = (
                            (
                                stix_indicator["labels"]
                                + [self.label_hygiene_parent["value"]]
                            )
                            if "labels" in stix_indicator
                            else [self.label_hygiene_parent["value"]]
                        )
                    else:
                        stix_indicator["labels"] = (
                            (stix_indicator["labels"] + [self.label_hygiene["value"]])
                            if "labels" in stix_indicator
                            else [self.label_hygiene["value"]]
                        )

                    # Update score
                    stix_indicator = OpenCTIStix2.put_attribute_in_extension(
                        stix_indicator, STIX_EXT_OCTI, "score", score
                    )

                    # Append
                    stix_objects.append(stix_indicator)

            serialized_bundle = self.helper.stix2_create_bundle(stix_objects)
            self.helper.send_stix2_bundle(serialized_bundle)
        return score

    def _add_label_to_entity(
        self, opencti_entity: dict, stix_entity: dict, label_value: str
    ):
        if opencti_entity["entity_type"] == "Indicator":
            if label_value not in stix_entity.get("labels", []):
                if "labels" in opencti_entity:
                    stix_entity["labels"].append(label_value)
                else:
                    stix_entity["labels"] = [label_value]
            else:
                self.helper.log_debug(
                    f"Label {label_value} already present in {stix_entity}."
                )
        else:
            OpenCTIStix2.put_attribute_in_extension(
                stix_entity,
                STIX_EXT_OCTI_SCO,
                "labels",
                label_value,
                True,
            )

    def _process_work_item(self, data: Dict) -> str:
        """Process a single work item in a thread pool worker."""
        start_time = time.time()
        thread_name = threading.current_thread().name

        try:
            stix_objects = data["stix_objects"]
            stix_entity = data["stix_entity"]
            opencti_entity = data["enrichment_entity"]

            # Process the entity
            result = self._process_entity(stix_objects, stix_entity, opencti_entity)

            # Update statistics
            with self.stats_lock:
                self.stats["total_processed"] += 1
                self.stats["processing_time"] += time.time() - start_time
                self.stats["active_tasks"] -= 1

            if self.stats["total_processed"] % 100 == 0:
                self._log_statistics()

            self.helper.log_debug(f"{thread_name} processed entity successfully")

            return result if result else "No warning list matches found."

        except Exception as e:
            self.helper.log_error(
                f"Error processing work item in {thread_name}: {str(e)}"
            )
            with self.stats_lock:
                self.stats["errors"] += 1
                self.stats["active_tasks"] -= 1
            raise

    def _process_message(self, data: Dict) -> str:
        """
        Message callback from OpenCTI connector helper.
        Submits work directly to the thread pool for parallel processing.
        """
        try:
            # Update active tasks counter
            with self.stats_lock:
                self.stats["active_tasks"] += 1

            # Submit to thread pool (non-blocking)
            future = self.thread_pool.submit(self._process_work_item, data)

            # Track the future for monitoring
            with self.futures_lock:
                # Clean up completed futures periodically
                self.active_futures = [f for f in self.active_futures if not f.done()]
                self.active_futures.append(future)
                active_count = len(self.active_futures)

            # Log current status
            self.helper.log_debug(
                f"Submitted work to thread pool. Active tasks: {active_count}/{self.max_workers}"
            )

            # Return immediately without waiting for result
            # This allows parallel processing
            return f"Message submitted to thread pool (active: {active_count})"

        except Exception as e:
            self.helper.log_error(f"Error submitting message to thread pool: {str(e)}")
            with self.stats_lock:
                self.stats["active_tasks"] -= 1
            raise

    def _log_statistics(self):
        """Log processing statistics."""
        with self.stats_lock:
            avg_time = (
                self.stats["processing_time"] / self.stats["total_processed"]
                if self.stats["total_processed"] > 0
                else 0
            )
            self.helper.log_info(
                f"Statistics: Processed={self.stats['total_processed']}, "
                f"Hits={self.stats['total_hits']}, "
                f"Errors={self.stats['errors']}, "
                f"AvgTime={avg_time:.3f}s, "
                f"Active tasks={self.stats['active_tasks']}/{self.max_workers}"
            )

    # Start the main loop
    def run(self):
        """Start the connector with multi-threaded processing using ThreadPoolExecutor."""
        self.helper.log_info(
            "Starting multi-threaded hygiene connector with ThreadPoolExecutor"
        )
        self.helper.log_info(f"Max workers: {self.max_workers}")

        try:
            # Use the standard OpenCTI helper listen method
            # Messages will be submitted to the thread pool for parallel processing
            self.helper.listen(message_callback=self._process_message)
        except Exception as e:
            self.helper.log_error(f"Fatal error in connector: {str(e)}")
            raise
        finally:
            self.stop()

    def stop(self):
        """Stop the connector gracefully."""
        self.helper.log_info("Stopping multi-threaded hygiene connector...")
        self.shutdown = True

        # Wait for all submitted tasks to complete
        with self.futures_lock:
            pending_futures = [f for f in self.active_futures if not f.done()]
            if pending_futures:
                self.helper.log_info(
                    f"Waiting for {len(pending_futures)} active tasks to complete..."
                )
                for future in pending_futures:
                    try:
                        future.result(timeout=30)
                    except Exception as e:
                        self.helper.log_error(
                            f"Error waiting for task completion: {str(e)}"
                        )

        # Shutdown the thread pool
        self.helper.log_info("Shutting down thread pool...")
        self.thread_pool.shutdown(wait=True)

        # Log final statistics
        self._log_statistics()
        self.helper.log_info("Multi-threaded hygiene connector stopped")
