def normalize_connector_log_level(connector_log_level: str) -> str:
    """Normalize connector log level strings read from environment variables.

    Removes surrounding whitespace and strips matching single or double quotes
    around the whole value.
    """
    normalized_connector_log_level = connector_log_level.strip()
    if (
        len(normalized_connector_log_level) >= 2
        and normalized_connector_log_level[0] == normalized_connector_log_level[-1]
        and normalized_connector_log_level[0] in {"'", '"'}
    ):
        normalized_connector_log_level = normalized_connector_log_level[1:-1].strip()
    return normalized_connector_log_level
