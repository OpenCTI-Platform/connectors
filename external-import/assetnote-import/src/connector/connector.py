import sys
from datetime import datetime, timezone
from typing import Callable

from assetnote_import_client import AssetnoteImportClient
from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper

class AssetnoteImportConnector:
    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = AssetnoteImportClient(
            self.helper,
            base_url=self.config.assetnote_import.api_base_url,
            api_key=self.config.assetnote_import.api_key,
        )
        self.converter_to_stix = ConverterToStix(
            self.helper,
            self.config.assetnote_import,
            self._resolve_status_mapping(),
        )

    def _resolve_status_mapping(self) -> dict[str, str]:
        CASE_INCIDENT_STATUS_QUERY = """
        query CaseIncidentStatusMap {
          subType(id: "Case-Incident") {
            statuses {
              id
              template {
                name
              }
            }
          }
        }
        """
        status_template_names = {
            "UNRESOLVED": self.config.assetnote_import.unresolved_status_name,
            "TRIAGED": self.config.assetnote_import.triaged_status_name,
            "RESOLVED": self.config.assetnote_import.resolved_status_name,
            "IGNORED": self.config.assetnote_import.ignored_status_name,
        }

        #If none of the status templates were configured, return {} and the connector will run without utilising any status templates
        configured_statuses = {state: name for state, name in status_template_names.items() if name}
        if not configured_statuses:
            return {}

        #Retrieve the statuses actually attached to the Case-Incident workflow in OpenCTI, keyed by template name
        result = self.helper.api.query(CASE_INCIDENT_STATUS_QUERY)
        statuses = result["data"]["subType"]["statuses"]
        status_id_by_name = {status["template"]["name"]: status["id"] for status in statuses}

        #If any configured status name isn't attached to the workflow, raise a ValueError
        missing = [name for name in configured_statuses.values() if name not in status_id_by_name]
        if missing:
            raise ValueError(f"Case-Incident workflow status template(s) not found: {missing}. Please see the documentation for details on how to attach each to the Case Incident Workflow")
        #Return each configured triage state mapped to its resolved status id
        return {state: status_id_by_name[name] for state, name in configured_statuses.items()}


    def process_message(self) -> None: 
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        try:
            now = datetime.now(tz=timezone.utc)
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                since = current_state["last_run"]
                self.helper.connector_logger.info(
                    f"Connector last run: {since}"
                )
            # If the connector has never run, we should retrieve from the 'first run' timestamp specified in configs
            else:
                self.helper.connector_logger.info("Connector has never run...")
                since = self.config.assetnote_import.first_run_retrieval_datetime.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )

            #Retrieve Assets then Exposures sequentially
            asset_count, assets_complete = self._process_pages(
                self.client.get_assets,
                since,
                self.converter_to_stix.convert_asset,
                "assets",
            )
            exposure_count, exposures_complete = self._process_pages(
                self.client.get_exposures,
                since,
                self.converter_to_stix.convert_exposure,
                "exposures",
            )

            #Update last run timestamp only on the completion of full retrieval of both assets and exposures
            if assets_complete and exposures_complete:
                self.helper.set_state( {"last_run": now.strftime("%Y-%m-%dT%H:%M:%SZ")})
            else:
                self.helper.connector_logger.warning("[CONNECTOR] last_run not update due to error in consumption. Next run will compensate for this")
            self.helper.connector_logger.info(f"[CONNECTOR] Imported {asset_count} assets and {exposure_count} exposures")

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(str(err))

    def _process_pages(self, fetch_page: Callable[[str, int], list[dict]], since: str, convert_item: Callable[[dict], list], item_name: str,) -> tuple[int, bool]:
        total = 0
        succeeded = True
        page = 1

        while True:
            self.helper.connector_logger.info(f"[CONNECTOR] Fetching {item_name} page {page}")
            batch = fetch_page(since, page)

            if batch:
                work_name = f"Import Assetnote {item_name} page {page}"
                work_id = self.helper.api.work.initiate_work(self.helper.connect_id, work_name)

                objects = []
                failed = 0

                for item in batch:
                    #attempt to convert the item to STIX format (returning >=1 objects or raising an Exception)
                    try:
                        stix_items = convert_item(item)
                        objects.extend(stix_items)
                    except Exception as e:
                        failed += 1
                        succeeded = False
                        self.helper.connector_logger.warning(
                            f"[CONVERTER] Failed {item_name} id={item.get('id')}: {e}"
                        )

                if objects:
                    #append the 'base' objects (author and marking) to the bundle
                    objects = self.converter_to_stix.base_stix_objects() + objects
                    bundle = self.helper.stix2_create_bundle(objects)
                    self.helper.send_stix2_bundle(
                        bundle,
                        work_id=work_id,
                        cleanup_inconsistent_bundle=True,
                    )

                total += len(batch) - failed
                self.helper.api.work.to_processed(
                    work_id,
                    f"Imported {item_name} page {page}",
                )
            #if the batch size is less than the page size we are on the final page
            if len(batch) < self.client.page_size:
                return total, succeeded
            page += 1

    def run(self) -> None: 
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
