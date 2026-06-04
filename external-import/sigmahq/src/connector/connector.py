import sys
from typing import Any, Optional

from connector.converter_to_stix import ConverterToStix
from connector.settings import ConnectorSettings
from pycti import OpenCTIConnectorHelper
from sigmahq_client import SigmaHQClient


class SigmaHQConnector:

    def __init__(self, config: ConnectorSettings, helper: OpenCTIConnectorHelper):
        """
        :param config:
        :param helper:
        """
        self.config = config
        self.helper = helper

        self.client = SigmaHQClient(
            self.helper,
        )
        # Pull the TLP level from the connector-specific settings
        # (``sigmahq.tlp_level`` / ``SIGMAHQ_TLP_LEVEL``) instead of
        # hardcoding ``"clear"``. The Pydantic ``Literal`` constraint on
        # ``SigmaHQConfig.tlp_level`` already restricts the value to
        # the canonical TLP labels accepted by
        # ``ConverterToStix._create_tlp_marking``, so an invalid value
        # is rejected at config load instead of crashing the first run.
        self.converter_to_stix = ConverterToStix(
            self.helper,
            tlp_level=self.config.sigmahq.tlp_level,
        )

    def _collect_intelligence(
        self,
        release_metadata: dict[str, Any],
        rule_package: str,
    ) -> list:
        """
        Collect intelligence from the source and convert into STIX object
        :return: List of STIX objects
        """
        # The connector keeps a single ``ConverterToStix`` instance for
        # its lifetime (see ``__init__``), so the converter's per-bundle
        # SDO dedup state would otherwise carry across scheduled runs:
        # later bundles would emit ``Relationship`` objects targeting
        # AttackPattern / Vulnerability SDOs that were "seen" in an
        # earlier run but are not included in the current bundle.
        # Resetting up front guarantees every emitted bundle is self-
        # contained — every ``indicates`` edge references an SDO that
        # is also in the bundle.
        self.converter_to_stix.reset_dedup_state()

        stix_objects = []
        # ``download_and_convert_package`` may return an empty list when the
        # download or zip extraction fails; iterating over the empty default
        # is safe and lets the connector log a graceful "nothing to do" run.
        rules: list[dict[str, str]] = []
        # SigmaHQ release assets are named ``<rule_package>.zip``
        # (e.g. ``sigma_core.zip`` / ``sigma_core+.zip`` /
        # ``sigma_core++.zip``). A naive ``rule_package in asset["name"]``
        # substring match would let ``sigma_core`` also match ``sigma_core+``
        # and ``sigma_core++`` assets. Matching on the full filename
        # ``<rule_package>.zip`` disambiguates the three variants; ``break``
        # on first match keeps the result deterministic regardless of the
        # order in which GitHub returns the assets.
        for asset in release_metadata["assets"]:
            if asset["name"] == f"{rule_package}.zip":
                rules = (
                    self.client.download_and_convert_package(
                        asset["browser_download_url"]
                    )
                    or []
                )
                break

        for rule in rules:
            try:
                stix_entities = self.converter_to_stix.convert_sigma_rule(rule)
                stix_objects.extend(stix_entities)
            except Exception as err:
                self.helper.connector_logger.error(
                    "An exception occurred while converting SigmaHQ rule",
                    {
                        "filename": rule.get("filename"),
                        "error": str(err),
                    },
                    exc_info=True,
                )

        # Ensure consistent bundle by adding the author and TLP marking
        if len(stix_objects):
            stix_objects.append(self.converter_to_stix.author)
            stix_objects.append(self.converter_to_stix.tlp_marking)

        return stix_objects

    def process_message(self) -> None:
        """
        Connector main process to collect intelligence
        :return: None
        """
        self.helper.connector_logger.info(
            "[CONNECTOR] Starting connector...",
            {"connector_name": self.helper.connect_name},
        )

        # ``work_id`` is created lazily below; tracking it in the outer
        # scope lets the ``except Exception`` block mark the work as
        # ``in_error=True`` so a crash mid-run does not leave a Work
        # record stuck in the "running" state in the OpenCTI UI.
        work_id: Optional[str] = None
        try:
            # Get the current state
            current_state = self.helper.get_state()

            rule_package_version = None
            if current_state and "rule_package_version" in current_state:
                rule_package_version = current_state["rule_package_version"]

                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector last ingested rule package version",
                    {"rule_package_version": rule_package_version},
                )
            else:
                self.helper.connector_logger.info(
                    "[CONNECTOR] Connector has never run..."
                )

            # Friendly name will be displayed on OpenCTI platform
            friendly_name = "Connector SigmaHQ"

            # Initiate a new work
            work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id, friendly_name
            )

            self.helper.connector_logger.info(
                "[CONNECTOR] Running connector...",
                {"connector_name": self.helper.connect_name},
            )

            # get latest rule package version
            release_metadata = self.client.get_latest_published_version()
            if release_metadata is None or not release_metadata.get("tag"):
                # GitHub unreachable / rate limited / malformed response. The
                # client already logged the underlying error; fail the work
                # explicitly so the OpenCTI UI surfaces a clean error state
                # instead of crashing on a NoneType lookup below.
                self.helper.connector_logger.warning(
                    "Could not fetch the latest SigmaHQ release metadata; "
                    "skipping this run."
                )
                self.helper.api.work.to_processed(
                    work_id,
                    "Could not fetch the latest SigmaHQ release metadata.",
                    in_error=True,
                )
                return

            latest_version = release_metadata["tag"].lower()
            if (
                rule_package_version is None
                or latest_version != rule_package_version.lower()
            ):
                stix_objects = self._collect_intelligence(
                    release_metadata, self.config.sigmahq.rule_package
                )

                # Guard against an empty bundle: ``_collect_intelligence``
                # returns ``[]`` when no asset matched the configured
                # ``rule_package`` or every rule failed to convert. Sending
                # an empty bundle would either raise (depending on the
                # platform version) or create a noisy empty Work entry;
                # closing the Work with a clean ``Nothing to do`` message
                # is what every other connector in this repo does.
                if not stix_objects:
                    self.helper.connector_logger.info(
                        "[CONNECTOR] No SigmaHQ rules to publish this run",
                        {"rule_package": self.config.sigmahq.rule_package},
                    )
                    self.helper.api.work.to_processed(
                        work_id,
                        (
                            f"{self.helper.connect_name} connector: "
                            "no rules to publish (empty bundle)."
                        ),
                    )
                    return

                stix_objects_bundle = self.helper.stix2_create_bundle(stix_objects)
                bundles_sent = self.helper.send_stix2_bundle(
                    stix_objects_bundle,
                    work_id=work_id,
                    cleanup_inconsistent_bundle=True,
                )

                # Log metadata MUST be a serialisable dict whose values are
                # primitives — the previous ``{str(len(bundles_sent))}`` was a
                # *set* containing a single string, which breaks structured
                # logging serialisation.
                self.helper.connector_logger.info(
                    "Sending STIX objects to OpenCTI...",
                    {"bundles_sent": len(bundles_sent)},
                )

                # Store the last rule package version as a last run of the connector
                self.helper.connector_logger.debug(
                    "Getting current state and update it with last rule package version",
                    {"rule_package_version": release_metadata.get("tag")},
                )
                current_state = self.helper.get_state()
                if current_state:
                    current_state["rule_package_version"] = latest_version
                else:
                    current_state = {"rule_package_version": latest_version}
                self.helper.set_state(current_state)

            else:
                self.helper.connector_logger.info(
                    "Nothing to do, latest rule package version already ingested"
                )

            message = f"{self.helper.connect_name} connector successfully run"

            self.helper.api.work.to_processed(work_id, message)
            self.helper.connector_logger.info(message)

        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info(
                "[CONNECTOR] Connector stopped...",
                {"connector_name": self.helper.connect_name},
            )
            sys.exit(0)
        except Exception as err:
            # Mark the work as ``in_error=True`` when one is open so a
            # crash mid-run does not leave a "running" Work entry stuck
            # in the OpenCTI UI. ``exc_info=True`` writes the full
            # traceback to the connector log so the failing call is
            # actually actionable for the operator.
            self.helper.connector_logger.error(
                "[CONNECTOR] Unhandled exception during run",
                {"error": str(err)},
                exc_info=True,
            )
            if work_id is not None:
                try:
                    self.helper.api.work.to_processed(
                        work_id,
                        f"Unhandled exception: {err}",
                        in_error=True,
                    )
                except Exception as close_err:  # noqa: BLE001
                    # Closing the Work is best-effort: if the platform
                    # is the underlying cause of the original failure
                    # (network partition, OpenCTI restart, …) the
                    # close call will fail too. Log and continue so
                    # the scheduler can resume on the next tick.
                    self.helper.connector_logger.error(
                        "[CONNECTOR] Failed to mark work as in_error",
                        {"work_id": work_id, "error": str(close_err)},
                    )

    def run(self) -> None:
        """
        Start the connector, schedule its runs and trigger the first run.
        It allows you to schedule the process to run at a certain interval.
        This specific scheduler from the `OpenCTIConnectorHelper` will also check the queue size of a connector.
        If `CONNECTOR_QUEUE_THRESHOLD` is set, and if the connector's queue size exceeds the queue threshold,
        the connector's main process will not run until the queue is ingested and reduced sufficiently,
        allowing it to restart during the next scheduler check. (default is 500MB)

        Example:
            - If `CONNECTOR_DURATION_PERIOD=PT5M`, then the connector is running every 5 minutes.
        """
        self.helper.schedule_process(
            message_callback=self.process_message,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
