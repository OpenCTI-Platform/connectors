from datetime import datetime


def parse_iso_datetime(timestamp_str: str) -> datetime:
    """
    Parse string to datetime format
    :return: datetime
    """
    try:
        return datetime.fromisoformat(timestamp_str)
    except ValueError:
        return None
