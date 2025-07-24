from datetime import datetime, timedelta, timezone


def parse_iso_datetime(timestamp_str, field_name, alert_id, helper):
    if not timestamp_str:
        return ""
    try:
        return (
            datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f").isoformat(
                timespec="seconds"
            )
            + "Z"
        )
    except ValueError as e:
        helper.log_error(f"[{alert_id}] Failed to parse '{field_name}': {e}")
        return ""


def get_last_run(helper, historical_days):
    state = helper.get_state()
    if state and "last_run" in state:
        helper.log_info("Resuming from last run timestamp")
        return state["last_run"]

    default_start = datetime.now(timezone.utc) - timedelta(days=historical_days)
    formatted = default_start.strftime("%Y-%m-%dT%H:%M:%S")
    helper.log_info(
        f"No previous state found. Using historical polling window: {formatted}"
    )
    return formatted


def set_last_run(helper):
    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    helper.set_state({"last_run": current_time})
    helper.log_info(f"Updated last run timestamp to: {current_time}")
