import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

if "pycti" not in sys.modules:
    pycti = ModuleType("pycti")
    pycti.OpenCTIConnectorHelper = object
    sys.modules["pycti"] = pycti

if "stix2slider" not in sys.modules:
    stix2slider = ModuleType("stix2slider")
    stix2slider.slide_string = lambda *_args, **_kwargs: ""
    sys.modules["stix2slider"] = stix2slider

if "stix2slider.options" not in sys.modules:
    stix2slider_options = ModuleType("stix2slider.options")
    stix2slider_options.initialize_options = lambda *_args, **_kwargs: None
    sys.modules["stix2slider.options"] = stix2slider_options

api_handler_path = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "tanium_intel_connector"
    / "api_handler.py"
)
api_handler_spec = importlib.util.spec_from_file_location(
    "tanium_intel_connector.api_handler", api_handler_path
)
api_handler_module = importlib.util.module_from_spec(api_handler_spec)
api_handler_spec.loader.exec_module(api_handler_module)
TaniumApiHandler = api_handler_module.TaniumApiHandler


def _new_handler(deploy_enabled: bool):
    handler = TaniumApiHandler.__new__(TaniumApiHandler)
    handler.config = SimpleNamespace(tanium_deploy_intel=deploy_enabled)
    handler._request_data = MagicMock()
    return handler


def test_deploy_intel_posts_empty_json_payload_when_enabled():
    handler = _new_handler(deploy_enabled=True)

    handler.deploy_intel()

    handler._request_data.assert_called_once_with(
        "POST",
        "/plugin/products/threat-response/api/v1/intel/deploy",
        json={},
    )


def test_deploy_intel_does_nothing_when_disabled():
    handler = _new_handler(deploy_enabled=False)

    handler.deploy_intel()

    handler._request_data.assert_not_called()
