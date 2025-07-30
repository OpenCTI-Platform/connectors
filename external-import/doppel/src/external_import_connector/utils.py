from datetime import datetime, timedelta, timezone


def parse_iso_datetime(
    timestamp_str: str, field_name: str, alert_id: str, helper
) -> str:
    """
    Parse string to datetime iso format
    :return: string
    """
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
        helper.connector_logger.error(
            f"[{alert_id}] Failed to parse '{field_name}': {e}"
        )
        return ""


def get_last_run(helper, historical_days: int) -> str:
    """
    Retrieve last_run datetime
    :return: string
    """
    state = helper.get_state()
    if state and "last_run" in state:
        helper.connector_logger.info("Resuming from last run timestamp")
        return state["last_run"]

    default_start = datetime.now(timezone.utc) - timedelta(days=historical_days)
    formatted = default_start.strftime("%Y-%m-%dT%H:%M:%S")
    helper.connector_logger.info(
        f"No previous state found. Using historical polling window: {formatted}"
    )
    return formatted


def set_last_run(helper):
    """
    Set last_run datetime in helper state
    """
    current_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    helper.set_state({"last_run": current_time})
    helper.connector_logger.info(f"Updated last run timestamp to: {current_time}")
