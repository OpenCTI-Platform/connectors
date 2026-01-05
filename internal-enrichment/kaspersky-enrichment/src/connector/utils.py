from datetime import datetime, timedelta, timezone

from connector.constants import DATETIME_FORMAT


def is_quota_exceeded(entity_info: dict) -> bool:
    """
    Return True if quota is exceeded.
    """
    return entity_info["DayRequests"] >= entity_info["DayQuota"]


def entity_in_scope(connect_scope: bool | int | str | None, obs_type: str) -> bool:
    """
    Security to limit playbook triggers to something other than the initial scope
    """
    scopes = connect_scope.lower().replace(" ", "").split(",")
    entity_split = obs_type.split("--")
    entity_type = entity_split[0].lower()

    return entity_type in scopes


def resolve_file_hash(observable: dict) -> str:
    """Retrieve hash from observable in this order:
    sha-256 then sha-1 and at last md5.
    """
    hashes = observable.get("hashes", {})
    for hash in ("SHA-256", "SHA-1", "MD5"):
        if hash in hashes:
            return hashes[hash]
    raise ValueError(
        "Unable to enrich the observable, the observable does not have an SHA256, SHA1, or MD5"
    )


def string_to_datetime(value: str, format: str) -> datetime:
    """Format string to a datetime with specific timezone"""
    return datetime.strptime(value, format).replace(tzinfo=timezone.utc)


def is_last_seen_equal_to_first_seen(first_seen: datetime, last_seen: datetime) -> bool:
    """Check if last_seen datetime is same as first_seen"""
    return last_seen == first_seen


def get_first_and_last_seen_datetime(first_seen: str, last_seen: str) -> datetime:
    """
    Convert first and last seen string to datetime.
    If last==first, add one minute to last seen value.
    """
    first_seen_datetime = string_to_datetime(first_seen, DATETIME_FORMAT)
    last_seen_datetime = string_to_datetime(last_seen, DATETIME_FORMAT)
    if is_last_seen_equal_to_first_seen(first_seen_datetime, last_seen_datetime):
        last_seen_datetime = last_seen_datetime + timedelta(minutes=1)

    return first_seen_datetime, last_seen_datetime
