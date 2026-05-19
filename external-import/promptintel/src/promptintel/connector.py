import datetime
import sys

from pycti import OpenCTIConnectorHelper

from .client import PromptIntelClient
from .converter import PromptIntelConverter
from .settings import ConnectorSettings


class PromptIntelConnector:
    """OpenCTI external import connector for the PromptIntel platform."""

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        self.config = config
        self.helper = helper
        self.client = PromptIntelClient(helper, config)
        self.converter = PromptIntelConverter(helper, config)

    def _collect_intelligence(self) -> tuple[list, list[str]]:
        """Fetch prompts from the API, filter new ones, and convert to STIX.

        On the very first run the connector fetches up to ``import_start_limit``
        prompts (historical backfill).  On every subsequent run it fetches up to
        ``import_limit`` prompts, stopping early when it encounters IDs that
        were already imported (the API returns most-recent first).

        Returns a tuple of (stix_objects, new_prompt_ids).
        """
        state = self.helper.get_state() or {}
        imported_ids = set(state.get("imported_ids", []))

        is_first_run = "last_run" not in state
        batch_limit = (
            self.config.promptintel.import_start_limit
            if is_first_run
            else self.config.promptintel.import_limit
        )
        self.helper.connector_logger.info(
            "[PROMPTINTEL] Fetching prompts",
            {
                "first_run": is_first_run,
                "batch_limit": batch_limit,
                "already_imported": len(imported_ids),
            },
        )

        severity = self.config.promptintel.severity_filter or None
        category = self.config.promptintel.category_filter or None

        new_prompts = self.client.get_prompts_batch(
            max_items=batch_limit,
            severity=severity,
            category=category,
            known_ids=imported_ids if imported_ids else None,
        )

        if not new_prompts:
            self.helper.connector_logger.info("[PROMPTINTEL] No new prompts to import.")
            return [], []

        self.helper.connector_logger.info(
            "[PROMPTINTEL] New prompts to process",
            {"count": len(new_prompts)},
        )

        stix_objects: list = []
        new_ids: list[str] = []

        for prompt_data in new_prompts:
            prompt_id = prompt_data.get("id", "unknown")
            try:
                objects = self.converter.convert_prompt(prompt_data)
                stix_objects.extend(objects)
                new_ids.append(prompt_id)
            except Exception as e:
                self.helper.connector_logger.error(
                    "[PROMPTINTEL] Error converting prompt",
                    {"prompt_id": prompt_id, "error": str(e)},
                )

        return stix_objects, new_ids

    def process_message(self) -> None:
        """Main processing logic called by the scheduler."""
        self.helper.connector_logger.info(
            "[PROMPTINTEL] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )
        try:
            now = datetime.datetime.now(tz=datetime.UTC)
            current_state = self.helper.get_state()
            if current_state and "last_run" in current_state:
                self.helper.connector_logger.info(
                    "[PROMPTINTEL] Connector last run",
                    {"last_run": current_state["last_run"]},
                )
            else:
                self.helper.connector_logger.info(
                    "[PROMPTINTEL] Connector has never run..."
                )

            friendly_name = "PromptIntel Run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            stix_objects, new_ids = self._collect_intelligence()

            if stix_objects:
                stix_objects.append(self.converter.promptintel_identity)
                stix_objects.append(self.converter.tlp_marking)

                bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )
                self.helper.connector_logger.info(
                    "[PROMPTINTEL] Bundles sent to OpenCTI",
                    {"bundles_sent": str(len(bundles_sent))},
                )

            state = self.helper.get_state() or {}
            imported_ids = set(state.get("imported_ids", []))
            imported_ids.update(new_ids)
            self.helper.set_state(
                {
                    "imported_ids": list(imported_ids),
                    "last_run": now.isoformat(sep=" ", timespec="seconds"),
                }
            )

            message = f"Processed {len(new_ids)} new prompts ({len(stix_objects)} STIX objects)"
            self.helper.connector_logger.info(f"[PROMPTINTEL] {message}")
            self.helper.api.work.to_processed(work_id, message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("[PROMPTINTEL] Connector stopped.")
            sys.exit(0)
        except Exception as err:
            self.helper.connector_logger.error(
                "[PROMPTINTEL] Connector error", {"error": str(err)}
            )

    def run(self) -> None:
        """Run the connector on a recurring schedule."""
        self.helper.schedule_iso(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period,
        )
