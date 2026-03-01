#  Utilities: helper functions, classes, or modules that provide common, reusable functionality across a codebase
import re


def is_valid_technique_id(id_string):
    return bool(re.match(r"^t\d{4}(?:\.\d{3})?$", id_string))
