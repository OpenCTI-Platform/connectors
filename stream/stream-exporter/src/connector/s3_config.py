"""S3 settings, read under their ``STREAM_EXPORTER_S3_*`` / ``stream_exporter.s3_*``
names or their former ``MINIO_*`` / ``minio.*`` names.

The names carry the connector's section: pycti already reads ``S3_*`` and the ``s3``
section of ``config.yml`` for its own bundle upload to OpenCTI's storage.

The environment beats ``config.yml``, as for any other setting: the first of the
two that sets a setting under either name decides, and inside one of them the new
name wins over the former one. Each connector builds its own image, so this module
is not shared with the stream-importer connector, which has its own copy.
"""

import os

from pycti import get_config_variable

SECTION = "stream_exporter"
FORMER_SECTION = "minio"
FIELDS = (
    "endpoint",
    "port",
    "bucket",
    "folder",
    "access_key",
    "secret_key",
    "secure",
    "cert_check",
)


def _in_section(config: dict, section: str, key: str) -> bool:
    values = config.get(section)
    return isinstance(values, dict) and key in values


def resolve_s3_setting(field: str, config: dict):
    """Tell where ``field`` is read from.

    Returns the ``(env_var, yaml_path)`` pair to hand to ``get_config_variable``,
    the former name the value comes from (or None), and the names set under the
    other naming (former or new) that are not used.
    """
    new_env = f"{SECTION.upper()}_S3_{field.upper()}"
    former_env = f"{FORMER_SECTION.upper()}_{field.upper()}"
    new_yaml = [SECTION, f"s3_{field}"]
    former_yaml = [FORMER_SECTION, field]
    # In precedence order: environment before config.yml, new name before former.
    candidates = [
        (new_env, (new_env, None), False, new_env in os.environ),
        (former_env, (former_env, None), True, former_env in os.environ),
        (
            ".".join(new_yaml),
            (new_env, new_yaml),
            False,
            _in_section(config, *new_yaml),
        ),
        (
            ".".join(former_yaml),
            (former_env, former_yaml),
            True,
            _in_section(config, *former_yaml),
        ),
    ]
    set_candidates = [c for c in candidates if c[3]]
    if not set_candidates:
        return (new_env, None), None, []
    name, source, former, _ = set_candidates[0]
    ignored = [c[0] for c in set_candidates if c[2] != former]
    return source, name if former else None, ignored


class S3Settings:
    """Reads the S3 settings.

    Every setting is resolved up front, so that the names met can be logged before
    a value is parsed and possibly refused.
    """

    def __init__(self, config: dict | None):
        self.config = config if isinstance(config, dict) else {}
        self.former_names_used: list[str] = []
        self.names_ignored: list[str] = []
        self.sources = {}
        for field in FIELDS:
            source, used, ignored = resolve_s3_setting(field, self.config)
            self.sources[field] = source
            if used:
                self.former_names_used.append(used)
            self.names_ignored.extend(ignored)

    def get(self, field: str, **kwargs):
        env_var, yaml_path = self.sources[field]
        return get_config_variable(env_var, yaml_path, self.config, **kwargs)
