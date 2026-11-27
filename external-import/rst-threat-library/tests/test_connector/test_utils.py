import importlib.util
import sys
import types
from pathlib import Path


def _load_with_sync_labels():
    try:
        from connector.utils import with_sync_labels

        return with_sync_labels
    except ModuleNotFoundError as exc:
        if getattr(exc, "name", None) != "connectors_sdk":
            raise

    src_connector = Path(__file__).resolve().parents[2] / "src" / "connector"
    if "connector" not in sys.modules:
        pkg = types.ModuleType("connector")
        pkg.__path__ = [str(src_connector)]
        sys.modules["connector"] = pkg

    full_name = "connector.utils"
    if full_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(
            full_name, src_connector / "utils.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[full_name] = module
        spec.loader.exec_module(module)
    return sys.modules[full_name].with_sync_labels


with_sync_labels = _load_with_sync_labels()


def test_with_sync_labels_noop_when_empty():
    item = {"name": "X", "objectLabel": ["existing"]}
    assert with_sync_labels(item, []) is item


def test_with_sync_labels_appends_missing_labels():
    item = {"name": "X", "objectLabel": ["existing"]}
    out = with_sync_labels(item, ["rst-threat-library", "existing"])
    assert out is not item
    assert out["objectLabel"] == ["existing", "rst-threat-library"]


def test_with_sync_labels_creates_label_list_when_absent():
    out = with_sync_labels({"name": "X"}, ["rst-threat-library"])
    assert out["objectLabel"] == ["rst-threat-library"]
