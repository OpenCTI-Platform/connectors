from datetime import datetime


def parse_iso_datetime(timestamp_str: str) -> datetime:
    """
    Parse string to datetime format
    :return: datetime
    """
    try:
        return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        return None
