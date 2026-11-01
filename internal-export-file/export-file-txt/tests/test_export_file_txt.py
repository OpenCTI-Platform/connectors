import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# The connector module name contains dashes, so it is loaded from its path.
_MODULE_PATH = Path(__file__).parent.parent / "src" / "export-file-txt.py"
_SPEC = importlib.util.spec_from_file_location("export_file_txt", _MODULE_PATH)
export_file_txt = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(export_file_txt)


def test_extract_values_skips_missing_null_and_blank_values():
    entities = [
        {"name": "APT28"},
        {"name": None},
        {"name": ""},
        {"name": "   "},
        {"other": "x"},
        {"name": "Lazarus"},
    ]

    assert export_file_txt.extract_values(entities, "name") == ["APT28", "Lazarus"]


def test_extract_values_converts_non_string_values():
    assert export_file_txt.extract_values([{"name": 64512}], "name") == ["64512"]


def _connector():
    connector = export_file_txt.ExportFileTxt.__new__(export_file_txt.ExportFileTxt)
    connector.helper = MagicMock()
    return connector


def _selection_data(entity_type):
    return {
        "file_name": "export.txt",
        "file_markings": [],
        "entity_id": None,
        "entity_type": entity_type,
        "export_scope": "selection",
        "main_filter": {"mode": "and", "filters": [], "filterGroups": []},
        "access_filter": None,
    }


def test_process_message_exports_observables_with_a_null_value():
    """A null observable_value no longer raises TypeError in the join (#7356)."""
    connector = _connector()
    api = connector.helper.api_impersonate
    api.stix_domain_object.list.return_value = []
    api.stix_cyber_observable.list.return_value = [
        {"observable_value": "1.2.3.4"},
        {"observable_value": None},
        {"observable_value": "evil.example"},
    ]
    api.stix_core_relationship.list.return_value = []

    result = connector._process_message(_selection_data("Stix-Cyber-Observable"))

    assert result == "Export done"
    push = connector.helper.api.stix_cyber_observable.push_list_export
    assert push.call_args.args[4] == "1.2.3.4\nevil.example"


@pytest.mark.parametrize("entity_type", ["Stix-Core-Object", "Malware-Analysis"])
def test_process_message_exports_names_with_a_null_value(entity_type):
    connector = _connector()
    api = connector.helper.api_impersonate
    if entity_type == "Malware-Analysis":
        entities = [{"result_name": "Emotet"}, {"result_name": None}]
    else:
        entities = [{"name": "Emotet"}, {"name": None}]
    api.stix_domain_object.list.return_value = entities
    api.stix_cyber_observable.list.return_value = []
    api.stix_core_relationship.list.return_value = []

    result = connector._process_message(_selection_data(entity_type))

    assert result == "Export done"
    if entity_type == "Stix-Core-Object":
        push = connector.helper.api.stix_core_object.push_list_export
    else:
        push = connector.helper.api.stix_domain_object.push_list_export
    assert push.call_args.args[4] == "Emotet"
