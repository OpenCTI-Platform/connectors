import sys
import traceback
from datetime import UTC, datetime
from typing import Any

import pycti
import stix2
from pycti import OpenCTIConnectorHelper
from threatmatch.client import ThreatMatchClient
from threatmatch.config import ConnectorSettings
from threatmatch.converter import Converter


class Connector:
    def __init__(
        self,
        helper: OpenCTIConnectorHelper,
        config: ConnectorSettings,
        converter: Converter,
    ) -> None:
        self.helper = helper
        self.config = config
        self.converter = converter
        self.start_datetime = datetime.now(tz=UTC)  # redefined in _process()
        self.work_id = None

    def _get_stix_objects(self, client, item_type, item_id):
        stix_objects = client.get_stix_objects(item_type, item_id)
        self.helper.connector_logger.info(
            f"Found {len(stix_objects)} STIX objects from {item_type} {item_id}'"
        )
        return stix_objects

    @staticmethod
    def _parse_modified(stix_object: dict[str, Any]) -> tuple[int, float]:
        modified = stix_object.get("modified")
        if isinstance(modified, str) and modified:
            try:
                return (
                    1,
                    datetime.fromisoformat(modified.replace("Z", "+00:00")).timestamp(),
                )
            except ValueError:
                pass
        return (0, 0.0)

    @classmethod
    def _score_stix_object(cls, stix_object: dict[str, Any]) -> tuple[int, float, int]:
        meaningful_values = [
            value
            for key, value in stix_object.items()
            if key not in {"id", "type", "spec_version"}
            and value not in (None, "", [], {})
        ]
        has_modified, modified_ts = cls._parse_modified(stix_object)
        return (has_modified, modified_ts, len(meaningful_values))

    # Labels are not unioned by the generic scoring above: the same indicator
    # can be reported by ThreatMatch through both a profile export (carrying
    # rich context labels, e.g. TTPs/countries/malware family) and the TAXII
    # IOC feed (carrying different, e.g. alert-context, labels). Picking a
    # single "best" object by field count would silently drop the other
    # source's labels, so they are merged across all occurrences instead.
    @staticmethod
    def _merge_labels(stix_objects: list[dict[str, Any]]) -> list[str]:
        merged: list[str] = []
        for stix_object in stix_objects:
            for label in stix_object.get("labels") or []:
                if label not in merged:
                    merged.append(label)
        return merged

    _TLP_RANK_BY_ID = {
        stix2.TLP_WHITE.id: 0,
        pycti.MarkingDefinition.generate_id("TLP", "TLP:CLEAR"): 0,
        stix2.TLP_GREEN.id: 1,
        stix2.TLP_AMBER.id: 2,
        pycti.MarkingDefinition.generate_id("TLP", "TLP:AMBER+STRICT"): 3,
        stix2.TLP_RED.id: 4,
    }

    @classmethod
    def _merge_markings(cls, stix_objects: list[dict[str, Any]]) -> list[str]:
        all_markings = list(
            dict.fromkeys(
                marking
                for stix_object in stix_objects
                for marking in stix_object.get("object_marking_refs") or []
                if isinstance(marking, str) and marking
            )
        )
        tlp_markings = [m for m in all_markings if m in cls._TLP_RANK_BY_ID]
        if len(tlp_markings) <= 1:
            return all_markings

        most_restrictive_tlp = max(tlp_markings, key=cls._TLP_RANK_BY_ID.__getitem__)
        merged: list[str] = []
        for marking in all_markings:
            if marking in cls._TLP_RANK_BY_ID:
                if marking == most_restrictive_tlp and marking not in merged:
                    merged.append(marking)
            else:
                merged.append(marking)
        return merged

    def _deduplicate_processed_objects(
        self, processed_objects: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for stix_object in processed_objects:
            grouped.setdefault(stix_object["id"], []).append(stix_object)

        deduplicated = []
        for stix_objects in grouped.values():
            best = dict(max(stix_objects, key=self._score_stix_object))
            if len(stix_objects) > 1:
                for candidate in sorted(
                    stix_objects, key=self._score_stix_object, reverse=True
                ):
                    for key, value in candidate.items():
                        if best.get(key) in (None, "", [], {}) and value not in (
                            None,
                            "",
                            [],
                            {},
                        ):
                            best[key] = value
                merged_labels = self._merge_labels(stix_objects)
                if merged_labels:
                    best["labels"] = merged_labels
                merged_markings = self._merge_markings(stix_objects)
                if merged_markings:
                    best["object_marking_refs"] = merged_markings
            deduplicated.append(best)
        return deduplicated

    def _add_report_observables(
        self, processed_objects: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        indicators = {
            obj["id"]: obj for obj in processed_objects if obj["type"] == "indicator"
        }
        existing_objects = {obj["id"]: obj for obj in processed_objects}
        observables: dict[str, dict[str, Any]] = {}
        for report in processed_objects:
            if report["type"] != "report":
                continue
            refs = report.get("object_refs", [])
            additional_refs = []
            for ref in refs:
                indicator = indicators.get(ref)
                if indicator is None:
                    continue
                observable = self.converter.create_observable(indicator)
                if observable is None:
                    continue
                previous = observables.get(observable["id"]) or existing_objects.get(
                    observable["id"]
                )
                if previous:
                    previous["object_marking_refs"] = self._merge_markings(
                        [previous, observable]
                    )
                else:
                    observables[observable["id"]] = observable
                if (
                    observable["id"] not in refs
                    and observable["id"] not in additional_refs
                ):
                    additional_refs.append(observable["id"])
            report["object_refs"] = refs + additional_refs
        return processed_objects + list(observables.values())

    def _get_all_content_group_id(self, taxii_groups: list[dict[str, Any]]) -> str:
        id_by_group = {group["name"]: group["id"] for group in taxii_groups}
        if all_content_group_id := id_by_group.get("All content"):
            return all_content_group_id
        raise ValueError(
            "No 'All content' group found in TAXII groups, only %s" % id_by_group.keys()
        )

    def _get_indicators(
        self,
        client: ThreatMatchClient,
        group_id: str,
        modified_after: str,
    ) -> dict:
        self.helper.connector_logger.info(
            f"Fetching indicators modified after {modified_after} from group {group_id}."
        )
        data = client.get_taxii_objects(group_id, "indicator", modified_after)
        indicators = data.get("objects", [])
        if data.get("more") and indicators:
            return indicators + self._get_indicators(
                client=client,
                group_id=group_id,
                modified_after=indicators[-1]["modified"],
            )
        return indicators

    def _collect_intelligence(self, last_run: datetime) -> list[dict[str, Any]]:
        import_from_date = (
            last_run if last_run else self.config.threatmatch.import_from_date
        ).strftime("%Y-%m-%d %H:%M")

        stix_objects = []

        with ThreatMatchClient(
            helper=self.helper,
            base_url=self.config.threatmatch.url.encoded_string(),
            client_id=self.config.threatmatch.client_id,
            client_secret=self.config.threatmatch.client_secret,
        ) as client:
            if self.config.threatmatch.import_profiles:
                profile_ids = client.get_profile_ids(import_from_date=import_from_date)
                self.helper.connector_logger.info(
                    f"Found {len(profile_ids)} profiles to import since {import_from_date}, fetching STIX objects..."
                )
                for profile_id in profile_ids:
                    stix_objects.extend(
                        sorted(
                            self._get_stix_objects(client, "profiles", profile_id),
                            key=lambda e: e["type"] == "relationship",
                        )
                    )
            if self.config.threatmatch.import_alerts:
                alert_ids = client.get_alert_ids(import_from_date=import_from_date)
                self.helper.connector_logger.info(
                    f"Found {len(alert_ids)} alerts to import since {import_from_date}, fetching STIX objects..."
                )
                for alert_id in alert_ids:
                    stix_objects.extend(
                        sorted(
                            self._get_stix_objects(client, "alerts", alert_id),
                            key=lambda e: e["type"] == "relationship",
                        )
                    )
            if self.config.threatmatch.import_iocs:
                stix_objects.extend(
                    self._get_indicators(
                        client=client,
                        group_id=self._get_all_content_group_id(
                            client.get_taxii_groups()
                        ),
                        modified_after=(
                            datetime.strptime(
                                import_from_date, "%Y-%m-%d %H:%M"
                            ).isoformat(timespec="milliseconds")
                            + "Z"
                        ),
                    )
                )
            self.helper.connector_logger.info(
                f"Found {len(stix_objects)} STIX objects to process since {import_from_date}."
            )
        return stix_objects

    @property
    def state(self) -> dict[str, Any]:
        return self.helper.get_state() or {}

    def _get_last_run(self) -> datetime | None:
        if last_run := self.state.get("last_run"):
            last_run = (
                datetime.fromtimestamp(last_run, tz=UTC)  # For retro compatibility
                if isinstance(last_run, float | int)
                else datetime.fromisoformat(last_run)
            )
        self.helper.connector_logger.info(
            (
                "Connector last run: "
                + (last_run.isoformat(timespec="seconds") if last_run else "never")
            ),
        )
        return last_run

    def _process_data(self):
        last_run = self._get_last_run()

        if stix_objects := self._collect_intelligence(last_run):

            self.work_id = self.helper.api.work.initiate_work(
                self.helper.connect_id,
                "ThreatMatch run @ "
                + self.start_datetime.isoformat(timespec="seconds"),
            )
            processed_stix_object = self._deduplicate_processed_objects(
                [
                    processed_stix_object
                    for stix_object in stix_objects
                    for processed_stix_object in self.converter.process(stix_object)
                ]
            )
            processed_stix_object = self._add_report_observables(processed_stix_object)
            bundle = self.helper.stix2_create_bundle(
                items=[self.converter.author, self.converter.tlp_marking]
                + processed_stix_object
            )
            self.helper.send_stix2_bundle(
                bundle, work_id=self.work_id, cleanup_inconsistent_bundle=True
            )

        self.helper.set_state(
            {"last_run": self.start_datetime.isoformat(timespec="seconds")}
        )

    def _process(self):
        self.start_datetime = datetime.now(tz=UTC)
        try:
            self.helper.connector_logger.info("Running connector...")
            self._process_data()
            self.helper.connector_logger.info("Connector successfully ran")
        except (KeyboardInterrupt, SystemExit):
            self.helper.connector_logger.info("Connector stop")
            sys.exit(0)
        except Exception as e:
            traceback.print_exc()
            self.helper.connector_logger.error(str(e))
        finally:
            if self.work_id:
                self.helper.api.work.to_processed(self.work_id, "")

    def run(self):
        self.helper.connector_logger.info("Connector starting...")
        self.helper.schedule_process(
            message_callback=self._process,
            duration_period=self.config.connector.duration_period.total_seconds(),
        )
