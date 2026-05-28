from stix_shifter.stix_translation import stix_translation

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
        return []
    except Exception:
        raise RuntimeError(f"Cannot parse STIX pattern {stix_pattern}")
