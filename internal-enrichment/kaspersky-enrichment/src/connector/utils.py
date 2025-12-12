from datetime import datetime, timezone


def check_quota(entity_info: dict) -> bool:
    """
    Return True if quota is exceeded.
    """
    if entity_info["DayRequests"] >= entity_info["DayQuota"]:
        return True
    return False


def entity_in_scope(connect_scope, obs_type: str) -> bool:
    """
    Security to limit playbook triggers to something other than the initial scope
    :param data: Dictionary of data
    :return: boolean
    """
    scopes = connect_scope.lower().replace(" ", "").split(",")
    entity_split = obs_type.split("--")
    entity_type = entity_split[0].lower()

    if entity_type in scopes:
        return True
    else:
        return False


def resolve_file_hash(observable: dict) -> str:
    if "hashes" in observable and "SHA-256" in observable["hashes"]:
        return observable["hashes"]["SHA-256"]
    if "hashes" in observable and "SHA-1" in observable["hashes"]:
        return observable["hashes"]["SHA-1"]
    if "hashes" in observable and "MD5" in observable["hashes"]:
        return observable["hashes"]["MD5"]
    raise ValueError(
        "Unable to enrich the observable, the observable does not have an SHA256, SHA1, or MD5"
    )


def string_to_datetime(value: str, format: str) -> datetime:
    return datetime.strptime(value, format).replace(tzinfo=timezone.utc)
