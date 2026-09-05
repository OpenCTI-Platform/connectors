import json
import traceback
from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper
from trukno_connector.client import TruKnoClient
from trukno_connector.settings import ConnectorSettings
from trukno_connector.state import ConnectorState, next_checkpoint
from trukno_connector.transform import transform_breach_to_bundle


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _persist_checkpoint(helper, state, updated_at: str) -> ConnectorState:
    next_state = next_checkpoint(state, [updated_at])
    helper.set_state({"last_seen_updated_at": next_state.last_seen_updated_at})
    state.last_seen_updated_at = next_state.last_seen_updated_at
    return state


def _log(helper, level: str, message: str, context: dict | None = None) -> None:
    logger = getattr(helper, "connector_logger", None)
    if logger is not None and hasattr(logger, level):
        getattr(logger, level)(message, meta=context or {})
        return
    print(message, flush=True)


def _start_work(helper, connector_name: str) -> str | None:
    api = getattr(helper, "api", None)
    connect_id = getattr(helper, "connect_id", None)
    if api is None or connect_id is None:
        return None
    friendly_name = f"{connector_name} import"
    return api.work.initiate_work(connect_id, friendly_name)


def _complete_work(
    helper, work_id: str | None, message: str, in_error: bool = False
) -> None:
    if work_id is None:
        return
    helper.api.work.to_processed(work_id, message, in_error=in_error)


def build_runtime(settings: ConnectorSettings | None = None):
    if settings is None:
        settings = ConnectorSettings()
    helper = OpenCTIConnectorHelper(config=settings.to_helper_config())
    client = TruKnoClient(
        str(settings.trukno.api_base_url),
        settings.trukno.api_key.get_secret_value(),
    )
    persisted_state = helper.get_state() or {}
    if persisted_state.get("last_seen_updated_at"):
        state = ConnectorState(
            last_seen_updated_at=persisted_state["last_seen_updated_at"]
        )
    else:
        state = ConnectorState.empty(
            settings.trukno.initial_lookback_days, _utc_now_iso()
        )
    return helper, client, state, settings


def run_once(helper, client, state, connector_name: str = "TruKno"):
    items = client.list_updated_breaches(state.last_seen_updated_at)
    if not items:
        _log(
            helper,
            "info",
            "No updated TruKno breaches found for this cycle.",
            {"last_seen_updated_at": state.last_seen_updated_at},
        )
        return state

    work_id = _start_work(helper, connector_name)
    sent_count = 0
    try:
        for item in items:
            payload = client.get_breach_details(item.id)
            bundle = transform_breach_to_bundle(payload)
            # A breach with no linkable attack-pattern/malware yields an empty
            # bundle (no STIX-valid report can be built); advance the checkpoint
            # so it is not refetched, but do not send an empty bundle.
            if bundle["objects"]:
                helper.send_stix2_bundle(json.dumps(bundle), work_id=work_id)
                sent_count += 1
            _persist_checkpoint(helper, state, item.updated_at)
    except Exception as exc:
        # Don't leave the work item stuck in a running state if a breach
        # fetch/transform/send fails mid-batch: mark it errored (the per-item
        # checkpoint above means the next cycle resumes after the last
        # successfully imported breach) and re-raise so main() logs and backs off.
        _complete_work(
            helper,
            work_id,
            f"TruKno import failed after {sent_count} bundle(s): {exc}",
            in_error=True,
        )
        raise

    _complete_work(
        helper,
        work_id,
        f"Imported {sent_count} TruKno breach bundle(s).",
    )
    _log(
        helper,
        "info",
        "TruKno connector cycle completed.",
        {
            "bundles_sent": sent_count,
            "last_seen_updated_at": state.last_seen_updated_at,
        },
    )
    return state


def main():
    helper, client, state, settings = build_runtime()

    def scheduled_run():
        nonlocal state
        try:
            state = run_once(
                helper=helper,
                client=client,
                state=state,
                connector_name=settings.connector.name,
            )
        except Exception as exc:
            _log(helper, "error", f"Connector cycle failed: {exc}")
            traceback.print_exc()

    helper.schedule_process(
        message_callback=scheduled_run,
        duration_period=settings.connector.duration_period.total_seconds(),
    )
