#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase

from connector.settings import TLPLevel


def to_canonical_tlp_marking(tlp_level: TLPLevel) -> str:
    """
    Convert a configured TLP level into its canonical ``TLP:XXX`` marking name.

    ``visionheight.max_tlp_level`` is stored lowercase (e.g. ``"amber+strict"``)
    because that is the form the connectors-sdk ``TLPMarking`` model expects.
    ``OpenCTIConnectorHelper.check_max_tlp`` however looks the maximum up in a
    table keyed by the canonical names (``"TLP:AMBER+STRICT"``, ...) and raises
    ``KeyError`` for anything else, so the value must be converted at that call
    boundary — and only there.

    The whole ``TLPLevel`` domain (``clear``, ``green``, ``amber``,
    ``amber+strict``, ``red``) maps by simple upper-casing: ``"amber+strict"``
    becomes ``"TLP:AMBER+STRICT"``, which is exactly how ``pycti`` and the
    connectors-sdk spell it.

    :param tlp_level: The configured TLP level, lowercase.
    :return: The canonical TLP marking name, e.g. ``"TLP:AMBER+STRICT"``.
    """
    return f"TLP:{tlp_level.upper()}"
