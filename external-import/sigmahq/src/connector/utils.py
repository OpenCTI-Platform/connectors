#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
import re

# MITRE ATT&CK technique identifiers are conventionally upper-case (``T1059``,
# ``T1059.001``), but Sigma rules in the wild ship them in mixed casing.
# ``re.IGNORECASE`` makes the validator accept both ``t1059`` and ``T1059``
# without requiring the caller to normalise the input first; the caller is
# responsible for upper-casing the value before persisting it as the
# Attack-Pattern name / ``x_mitre_id``.
_TECHNIQUE_ID_RE = re.compile(r"^t\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def is_valid_technique_id(id_string):
    return bool(_TECHNIQUE_ID_RE.match(id_string or ""))
