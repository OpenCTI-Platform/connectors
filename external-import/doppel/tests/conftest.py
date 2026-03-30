import logging
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Add src to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from doppel.converter_to_stix import ConverterToStix


@pytest.fixture(autouse=True)
def fake_helper():
    helper = MagicMock()
    helper.api.label.create.return_value = {"id": "label_id"}
    helper.connector_logger = logging.getLogger("doppel.converter_to_stix")

    return helper


@pytest.fixture(autouse=True)
def converter(fake_helper):
    return ConverterToStix(helper=fake_helper, tlp_level="clear")


@pytest.fixture(autouse=True)
def patch_logger_for_tests(monkeypatch):
    """Patch logger methods to format logs with dictionary data for tests."""
    import logging

    def create_enhanced_log_method(original_method):
        def enhanced_log(self, msg, *args, **kwargs):
            if args and len(args) == 1 and isinstance(args[0], dict):
                log_dict = args[0]
                formatted_msg = f"{msg} - {log_dict}"
                return original_method(self, formatted_msg)
            else:
                return original_method(self, msg, *args, **kwargs)

        return enhanced_log

    orig_info = logging.Logger.info
    orig_debug = logging.Logger.debug
    orig_warning = logging.Logger.warning
    orig_error = logging.Logger.error

    monkeypatch.setattr(logging.Logger, "info", create_enhanced_log_method(orig_info))
    monkeypatch.setattr(logging.Logger, "debug", create_enhanced_log_method(orig_debug))
    monkeypatch.setattr(
        logging.Logger, "warning", create_enhanced_log_method(orig_warning)
    )
    monkeypatch.setattr(logging.Logger, "error", create_enhanced_log_method(orig_error))
