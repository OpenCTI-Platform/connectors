from stix_shifter.stix_translation import stix_translation
from validators import hashes

stix_translater = stix_translation.StixTranslation()


def parse_stix_pattern(stix_pattern: str) -> list[dict]:
    """
    Parse observation expressions of a STIX pattern.
    :param stix_pattern: STIX pattern to parse
    :return: List of parsed observation expressions
    """
    try:
        translation_result = stix_translater.translate(
            "splunk",
            "parse",
            None,
            stix_pattern,
        )
        if translation_result:
            parsed_patterns = translation_result["parsed_stix"]
            return parsed_patterns
    except:
        raise RuntimeError(f"Cannot parse STIX pattern {stix_pattern}")


def get_context_former_value(context: dict, key: str) -> str:
    """
    Get former value of given key in event context.
    :param context: Event context (e.g. operations occured during an update)
    :param key: Key to get value for
    :return: Previous value found in context
    """
    if context and "reverse_patch" in context:
        value = next(
            (
                patch["value"]
                for patch in context["reverse_patch"]
                if patch["path"] == f"/{key}"
            ),
            None,
        )
        return value


def is_file_hash(string: str) -> bool:
    """
    Check if a string is a valid hash. Checked hash algorithms are MD5, SHA-1, SHA-256 and SHA-512.
    :param string: String to validate
    :return: `True` if string is a valid hash, otherwise `False`
    """
    return (
        hashes.md5(string) is True
        or hashes.sha1(string) is True
        or hashes.sha256(string) is True
        or hashes.sha512(string) is True
    )
