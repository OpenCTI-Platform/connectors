import os
from pathlib import Path

import yaml

_PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_config() -> dict[str, object]:
    config_path = (
        os.environ["OPENCTI_CONFIG_FILE"]
        if "OPENCTI_CONFIG_FILE" in os.environ
        else _PROJECT_ROOT / "config.yml"
    )
    config_path = Path(config_path)
    if not config_path.exists():
        return {}

    with config_path.open(encoding="utf-8") as config_file:
        loaded = yaml.safe_load(config_file) or {}

    if not isinstance(loaded, dict):
        error = "Configuration root must be a mapping"
        raise TypeError(error)

    return loaded
