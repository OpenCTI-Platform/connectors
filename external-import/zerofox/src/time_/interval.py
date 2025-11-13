from datetime import timedelta


def seconds_from_interval(interval: str):
    """Returns the interval to use for the connector

    This SHOULD always return the interval in seconds. If the connector expects
    the parameter to be received as hours uncomment as necessary.
    """
    unit = interval[-1:]
    value = interval[:-1]

    try:
        if unit == "d":
            # In days:
            return int(value) * 60 * 60 * 24
        if unit == "h":
            # In hours:
            return int(value) * 60 * 60
        if unit == "m":
            # In minutes:
            return int(value) * 60
        if unit == "s":
            # In seconds:
            return int(value)
    except Exception as ex:
        raise ValueError(
            f"Error when converting CONNECTOR_RUN_EVERY environment variable: '{interval}'. {str(ex)}"
        ) from ex
    return 0


def delta_from_interval(interval):
    """Converts a string of the form '1d' to a timedelta object of 1 day, or '1h' to 1 hour, etc."""
    unit = interval[-1]
    value = int(interval[:-1])
    unit_to_timedelta = {
        "d": dict(days=value),
        "h": dict(hours=value),
        "m": dict(minutes=value),
        "s": dict(seconds=value),
    }
    return timedelta(**unit_to_timedelta[unit])
