"""The module contains the PatternTypeOV enum class for OpenCTI pattern types."""

from enum import Enum


class PatternTypeOV(str, Enum):
    """Pattern Type Open Vocabulary.

    See https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_9lfdvxnyofxw
    """

    STIX = "stix"
    EQL = "eql"
    PCRE = "pcre"
    SHODAN = "shodan"
    SIGMA = "sigma"
    SNORT = "snort"
    SPL = "spl"
    SURICATA = "suricata"
    TANIUM_SIGNAL = "tanium-signal"
    YARA = "yara"
