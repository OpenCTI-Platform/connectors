import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pycti import OpenCTIConnectorHelper
from typing import Any
from pydantic import ValidationError
from .services import (
    ProofpointEtReputationClient,
    ProofpointEtReputationConfig,
    ConverterToStix,
)
from .models import (
    IPReputationModel,
    DomainReputationModel,
    ReputationScore,
)
from enum import Enum

class ReputationEntity(Enum):
    IP = "iprepdata"
    DOMAIN = "domainrepdata"

class ProofpointEtReputationConnector:
    """
    Specifications of the external import connector

    This class encapsulates the main actions, expected to be run by any external import connector.
    Note that the attributes defined below will be complemented per each connector type.
    This type of connector aim to fetch external data to create STIX bundle and send it in a RabbitMQ queue.
    The STIX bundle in the queue will be processed by the workers.
    This type of connector uses the basic methods of the helper.
    """

    def __init__(self):
        """
        Initialize the Connector with necessary configurations
        """

        # Load configuration file and connection helper
        self.config = ProofpointEtReputationConfig()
        self.helper = OpenCTIConnectorHelper(self.config.load)
        self.client = ProofpointEtReputationClient(self.helper, self.config)
        self.converter_to_stix = ConverterToStix(self.helper)

    def _process_initiate_work(self, collection: str, now_isoformat: str) -> str:
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting work collection...",
            {"collection": collection, "isoformat": now_isoformat},
        )
        friendly_name = f"ProofPoint ET Reputation - {collection} run @ {now_isoformat}"
        return self.helper.api.work.initiate_work(self.helper.connect_id, friendly_name)

    def _process_send_stix_to_opencti(self, work_id, prepared_objects):
        if prepared_objects is not None and len(prepared_objects) != 0:
            unique_id_objects = list(
                {getattr(obj, "id", None): obj for obj in prepared_objects if hasattr(obj, "id")}.values()
            )
            get_stix_representation_objects = [getattr(item, "stix2_representation") for item in unique_id_objects]
            stix_objects_bundle = self.helper.stix2_create_bundle(get_stix_representation_objects[:12])
            bundles_sent = self.helper.send_stix2_bundle(
                stix_objects_bundle,
                work_id=work_id,
                cleanup_inconsistent_bundle=True,
            )
            self.helper.connector_logger.info(
                "[CONNECTOR] Sending STIX objects to OpenCTI...",
                {"bundles_sent": len(bundles_sent)},
            )

    def _process_complete_work(self, collection: str, work_id: str) -> None:
        self.helper.connector_logger.info(
            "[CONNECTOR] Complete work collection...",
            {"collection": collection, "work_id": work_id},
        )
        message = "ProofPoint ET Reputation - Finished work"
        self.helper.api.work.to_processed(work_id, message)

    def _process_reputation_tasks(self) -> None:
        with ThreadPoolExecutor(max_workers=2) as executor:

            tasks = {
                executor.submit(self.client.proofpoint_get_ips_reputation, ReputationEntity.IP.value) : "IPv4-Addr",
                executor.submit(self.client.proofpoint_get_domains_reputation, ReputationEntity.DOMAIN.value): "Domain-Name"
            }

            for future in as_completed(tasks):
                collection = tasks[future]
                future_result = future.result()
                if future_result.get("error"):
                    self.helper.connector_logger.error(
                        future_result.get("message"),
                        {"collection": collection, "error": future_result.get("error")}
                    )
                    continue
                now_isoformat = datetime.now().isoformat(sep=" ", timespec="seconds")
                work_id = self._process_initiate_work(collection, now_isoformat)
                try:
                    prepared_objects = self._generate_stix_from_reputation_data(future_result, collection)
                    self._process_send_stix_to_opencti(work_id, prepared_objects)
                except Exception as err:
                    self.helper.connector_logger.error(
                        "[ERROR] An unknown error occurred during the reputation handling process",
                        {"collection": collection, "error": err},
                    )
                finally:
                    if work_id:
                        self._process_complete_work(collection, work_id)

    def _generate_reputation_model(self, data_list: dict[str, dict[str, str]], collection: str) -> IPReputationModel | DomainReputationModel | None:

        for entity, scores in data_list.items():
            try:
                reputation_score = ReputationScore(scores={category: value for category, value in scores.items()})
                if collection == "IPv4-Addr":
                    # IPv4 model example : IPReputationModel(reputation={IPv4Address('0.0.0.0'): ReputationScore(scores={'category': 50})})
                    yield IPReputationModel(reputation={entity: reputation_score})
                elif collection == "Domain-Name":
                    # Domain model example : DomainReputationModel(reputation={'example.com': ReputationScore(scores={'category': 50})})
                    yield DomainReputationModel(reputation={entity: reputation_score})
            except ValidationError as err:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Model validation: the reputation or reputation score does not conform to the schema. "
                    "The entity has been ignored.",
                    {"collection": collection, "entity": entity, "category_and_score": scores, "error": err},
                )
                continue
            except Exception as err:
                self.helper.connector_logger.error(
                    "[ERROR] An unknown error has occurred during the generation of the reputation model.",
                    {"collection": collection, "entity": entity, "category_and_score": scores, "error": err},
                )


    def _generate_stix_from_reputation_data(self, data_list: dict, collection: str) -> list:

        self.helper.connector_logger.info(
            "[CONNECTOR] Starting the generation of stix objects from the ProofPoint ET Reputation database for the collection...",
            {"collection": collection},
        )
        stix_objects: list[Any] = []

        author = self.converter_to_stix.make_author()
        stix_objects.append(author)

        marking_definition = self.converter_to_stix.make_marking_definition_tlp_amber_strict()
        stix_objects.append(marking_definition)

        for model in self._generate_reputation_model(data_list, collection):
            for entity_value, categories in model.reputation.items():

                # Recovery of the highest value in the scores
                highest_score = max(categories.scores.values())
                # Given that the maximum score for OpenCTI is 100, we have decided to limit all higher scores,
                # as defined by Proofpoint ET Reputation, to 100.
                highest_score_converted = 100 if highest_score > 100 else highest_score
                # All categories will be used to generate labels
                list_categories = list(categories.scores.keys())

                if self.config.min_score > highest_score_converted:
                    self.helper.connector_logger.debug(
                        "[CONNECTOR] The creation of the entity was ignored due to your configuration of the min_score variable",
                        {"collection": collection, "min_score_config": self.config.min_score, "entity": entity_value, "entity_score": highest_score_converted},
                    )
                    continue

                # Make observable object
                observable = self.converter_to_stix.make_observable(entity_value, highest_score_converted, list_categories, collection)
                if observable is None:
                    continue
                self.helper.connector_logger.debug(
                    "[CONNECTOR] The generation of observable in stix2 from reputation data has been a success.",
                    {"observable_id": observable.id, "observable_value": observable.value},
                )
                stix_objects.append(observable)

                if self.config.create_indicator:
                    # Make indicator object
                    indicator = self.converter_to_stix.make_indicator(entity_value, highest_score_converted, list_categories, collection)
                    self.helper.connector_logger.debug(
                        "[CONNECTOR] The generation of indicator in stix2 from reputation data has been a success.",
                        {"indicator_id": indicator.id, "indicator_name": indicator.name},
                    )
                    stix_objects.append(indicator)

                    # Make relationship object between indicator and observable
                    #
                    relationship = self.converter_to_stix.make_relationship(indicator.id, "based-on", observable.id)
                    self.helper.connector_logger.debug(
                        "[CONNECTOR] The generation of relationship in stix2 between.",
                        {
                            "relationship_id": relationship.id,
                            "source_ref": relationship.source_ref,
                            "relationship_type": relationship.relationship_type,
                            "target_ref": relationship.target_ref,
                        },
                    )
                    stix_objects.append(relationship)

        self.helper.connector_logger.info(
            "[CONNECTOR] Finalisation of the generation of stix objects from the ProofPoint ET Reputation database for the collection...",
            {"collection": collection, "generated_entities": len(stix_objects), "config_min_score": self.config.min_score},
        )
        return stix_objects

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        try:
            self.helper.connector_logger.info(
                "[CONNECTOR] Starting connector...",
                {"connector_name": self.helper.connect_name},
            )
            # Get the current state
            now_timestamp = int(datetime.timestamp(datetime.now()))
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last run",
                    {"last_run_datetime": last_run},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # Processing reputation-related collection
            self._process_reputation_tasks()

            # Store the current timestamp as a last run of the connector
            self.helper.connector_logger.debug(
                "[CONNECTOR] Getting current state and update it with last run of the connector",
                {"now_timestamp": now_timestamp},
            )
            current_state = self.helper.get_state()
            current_state_datetime = now.strftime("%Y-%m-%d %H:%M:%S")
            last_run_datetime = datetime.utcfromtimestamp(now_timestamp).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            if current_state:
                current_state["last_run"] = current_state_datetime
            else:
                current_state = {"last_run": current_state_datetime}
            self.helper.set_state(current_state)

            message = (
                f"[CONNECTOR] {self.helper.connect_name} connector successfully run, storing last_run as "
                + str(last_run_datetime)
            )
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def run(self) -> None:
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.duration_period,
        )
