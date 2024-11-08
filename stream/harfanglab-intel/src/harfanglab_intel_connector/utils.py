from stix_shifter.stix_translation import stix_translation
from validators import hashes

stix_translater = stix_translation.StixTranslation()


def parse_stix_pattern(stix_pattern: str) -> list[dict]:
    """
    Parse observation expressions of a STIX pattern.
    :param stix_pattern: STIX pattern to parse
    :return: List of parsed observation expressions
    """
    translation_result = stix_translater.translate(
        "splunk",
        "parse",
        None,
        stix_pattern,
    )
    if translation_result:
        parsed_patterns = translation_result["parsed_stix"]
        return parsed_patterns


def build_observable_query_filters(stix_pattern: str) -> list[dict]:
    """
    Build GraphQL query filters based on STIX pattern to get observables.
    :param stix_pattern: STIX pattern to build filters from
    :return: List of observables filters
    """
    parsed_patterns = parse_stix_pattern(stix_pattern)
    if parsed_patterns:
        observables_filters = []
        for parsed_pattern in parsed_patterns:
            filter_key = parsed_pattern["attribute"].split(":")[1]
            filter_value = parsed_pattern["value"]
            observables_filter = {
                "key": filter_key.replace("'", ""),
                "operator": "eq",
                "values": [filter_value],
            }
            observables_filters.append(observables_filter)

def is_file_hash(string: str) -> bool:
    return (
        hashes.md5(string) is True
        or hashes.sha1(string) is True
        or hashes.sha256(string) is True
        or hashes.sha512(string) is True
    )
