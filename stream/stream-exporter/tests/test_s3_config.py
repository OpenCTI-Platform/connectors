from unittest.mock import MagicMock, call

import pytest
import yaml
from connector import connector as connector_module
from connector.s3_config import S3Settings

FIELDS = [
    "ENDPOINT",
    "PORT",
    "BUCKET",
    "FOLDER",
    "ACCESS_KEY",
    "SECRET_KEY",
    "SECURE",
    "CERT_CHECK",
]


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for field in FIELDS:
        for prefix in ("STREAM_EXPORTER_S3_", "MINIO_", "S3_"):
            monkeypatch.delenv(f"{prefix}{field}", raising=False)
    for name in ("QUEUE_SIZE", "WRITE_EVERY_SEC"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def build_exporter(monkeypatch, tmp_path):
    """Builds the connector with the given config.yml content (None: no file)."""
    # The connector reads config.yml next to its package: point it to tmp_path,
    # so that a developer's src/config.yml never reaches the test.
    package = tmp_path / "connector"
    package.mkdir()
    monkeypatch.setattr(connector_module, "__file__", str(package / "connector.py"))
    helper = MagicMock()
    helper.get_state.return_value = None
    monkeypatch.setattr(connector_module, "OpenCTIConnectorHelper", lambda c: helper)
    monkeypatch.setattr(connector_module, "Metrics", MagicMock())
    minio = MagicMock()
    monkeypatch.setattr(connector_module, "Minio", minio)
    monkeypatch.setattr(
        connector_module.StreamExporterConnector, "write_events", lambda self: None
    )

    def build(config=None):
        if config is not None:
            (tmp_path / "config.yml").write_text(yaml.dump(config))
        exporter = connector_module.StreamExporterConnector()
        return exporter, minio, helper.connector_logger.warning

    build.warning = helper.connector_logger.warning
    return build


def set_environment(monkeypatch, values):
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_the_new_variable_is_read(monkeypatch):
    monkeypatch.setenv("STREAM_EXPORTER_S3_BUCKET", "export")
    settings = S3Settings({})

    assert settings.get("bucket") == "export"
    assert settings.former_names_used == []
    assert settings.names_ignored == []


def test_the_s3_settings_of_pycti_are_not_read(monkeypatch):
    monkeypatch.setenv("S3_ENDPOINT", "opencti-storage")
    settings = S3Settings({"s3": {"endpoint": "opencti-storage"}})

    assert settings.get("endpoint") is None


def test_the_former_minio_variable_is_still_read(monkeypatch):
    monkeypatch.setenv("MINIO_BUCKET", "export")
    settings = S3Settings({})

    assert settings.get("bucket") == "export"
    assert settings.former_names_used == ["MINIO_BUCKET"]
    assert settings.names_ignored == []


def test_the_new_variable_wins_over_the_minio_variable(monkeypatch):
    monkeypatch.setenv("STREAM_EXPORTER_S3_BUCKET", "new")
    monkeypatch.setenv("MINIO_BUCKET", "former")
    settings = S3Settings({})

    assert settings.get("bucket") == "new"
    assert settings.former_names_used == []
    assert settings.names_ignored == ["MINIO_BUCKET"]


def test_a_minio_variable_wins_over_the_new_section_of_the_config_file(monkeypatch):
    monkeypatch.setenv("MINIO_BUCKET", "from-env")
    settings = S3Settings({"stream_exporter": {"s3_bucket": "from-file"}})

    assert settings.get("bucket") == "from-env"
    assert settings.former_names_used == ["MINIO_BUCKET"]
    assert settings.names_ignored == ["stream_exporter.s3_bucket"]


def test_a_variable_wins_over_the_config_file_under_the_same_naming(monkeypatch):
    monkeypatch.setenv("MINIO_BUCKET", "from-env")
    settings = S3Settings({"minio": {"bucket": "from-file"}})

    assert settings.get("bucket") == "from-env"
    assert settings.former_names_used == ["MINIO_BUCKET"]
    assert settings.names_ignored == []


def test_the_new_section_wins_over_the_minio_section():
    settings = S3Settings(
        {"stream_exporter": {"s3_bucket": "new"}, "minio": {"bucket": "former"}}
    )

    assert settings.get("bucket") == "new"
    assert settings.former_names_used == []
    assert settings.names_ignored == ["minio.bucket"]


def test_the_former_minio_section_is_still_read_and_parsed():
    settings = S3Settings({"minio": {"port": "09000"}})

    assert settings.get("port", isNumber=True) == 9000
    assert settings.former_names_used == ["minio.port"]


def test_a_setting_set_nowhere_takes_its_raw_default():
    settings = S3Settings({})

    assert settings.get("cert_check", default="true") == "true"
    assert settings.former_names_used == []
    assert settings.names_ignored == []


def test_an_empty_new_variable_counts_as_set(monkeypatch):
    # As for any setting read by get_config_variable, an empty variable gives
    # the default and hides config.yml: it hides the former names the same way.
    monkeypatch.setenv("STREAM_EXPORTER_S3_FOLDER", "")
    monkeypatch.setenv("MINIO_FOLDER", "stream")
    settings = S3Settings({"minio": {"folder": "stream"}})

    assert settings.get("folder") is None
    assert settings.names_ignored == ["MINIO_FOLDER", "minio.folder"]


def test_an_empty_minio_variable_counts_as_set(monkeypatch):
    monkeypatch.setenv("MINIO_FOLDER", "")
    settings = S3Settings({"stream_exporter": {"s3_folder": "stream"}})

    assert settings.get("folder") is None
    assert settings.former_names_used == ["MINIO_FOLDER"]
    assert settings.names_ignored == ["stream_exporter.s3_folder"]


def test_a_key_without_value_in_the_minio_section_counts_as_set():
    settings = S3Settings({"minio": {"cert_check": None}})

    assert settings.get("cert_check", default="true") is None
    assert settings.former_names_used == ["minio.cert_check"]


def test_a_key_without_value_in_the_new_section_hides_the_minio_section():
    settings = S3Settings(
        {"stream_exporter": {"s3_bucket": None}, "minio": {"bucket": "former"}}
    )

    assert settings.get("bucket") is None
    assert settings.former_names_used == []
    assert settings.names_ignored == ["minio.bucket"]


def test_an_empty_key_in_the_new_section_hides_the_minio_section():
    settings = S3Settings(
        {"stream_exporter": {"s3_bucket": ""}, "minio": {"bucket": "former"}}
    )

    assert settings.get("bucket") is None
    assert settings.former_names_used == []
    assert settings.names_ignored == ["minio.bucket"]


@pytest.mark.parametrize(
    "config",
    [
        None,
        ["minio"],
        {"stream_exporter": None, "minio": {"port": 9000}},
        {"minio": None},
        {"stream_exporter": "s3_cert_check"},
        {"minio": ["cert_check"]},
    ],
)
def test_an_empty_or_odd_config_file_gives_the_default(config):
    assert S3Settings(config).get("cert_check", default="true") == "true"


def test_the_new_names_reach_the_client_without_warning(monkeypatch, build_exporter):
    set_environment(
        monkeypatch,
        {
            "STREAM_EXPORTER_S3_ENDPOINT": "storage",
            "STREAM_EXPORTER_S3_PORT": "09000",
            "STREAM_EXPORTER_S3_BUCKET": "export",
            "STREAM_EXPORTER_S3_FOLDER": "stream",
            "STREAM_EXPORTER_S3_ACCESS_KEY": "access",
            "STREAM_EXPORTER_S3_SECRET_KEY": "secret",
            "STREAM_EXPORTER_S3_SECURE": "true",
            "STREAM_EXPORTER_S3_CERT_CHECK": "false",
        },
    )

    exporter, minio, warning = build_exporter()

    minio.assert_called_once_with(
        "storage:9000", "access", "secret", secure=True, cert_check=False
    )
    assert (exporter.minio_bucket, exporter.minio_folder) == ("export", "stream")
    warning.assert_not_called()


def test_the_new_section_of_the_config_file_reaches_the_client(build_exporter):
    exporter, minio, warning = build_exporter(
        {
            "stream_exporter": {
                "s3_endpoint": "storage",
                "s3_port": 9000,
                "s3_bucket": "export",
                "s3_folder": "stream",
                "s3_access_key": "access",
                "s3_secret_key": "secret",
                "s3_secure": True,
                "s3_cert_check": False,
            }
        }
    )

    minio.assert_called_once_with(
        "storage:9000", "access", "secret", secure=True, cert_check=False
    )
    assert minio.call_args.kwargs["secure"] is True
    assert minio.call_args.kwargs["cert_check"] is False
    assert (exporter.minio_bucket, exporter.minio_folder) == ("export", "stream")
    warning.assert_not_called()


def test_the_defaults_are_unchanged(monkeypatch, build_exporter):
    set_environment(
        monkeypatch,
        {
            "STREAM_EXPORTER_S3_ENDPOINT": "storage",
            "STREAM_EXPORTER_S3_PORT": "9000",
            "STREAM_EXPORTER_S3_ACCESS_KEY": "access",
            "STREAM_EXPORTER_S3_SECRET_KEY": "secret",
        },
    )

    exporter, minio, _ = build_exporter()

    minio.assert_called_once_with(
        "storage:9000", "access", "secret", secure=None, cert_check="true"
    )
    assert (exporter.minio_bucket, exporter.minio_folder) == (None, None)


def test_the_former_names_reach_the_client_and_are_logged_without_values(
    monkeypatch, build_exporter
):
    set_environment(
        monkeypatch,
        {
            "MINIO_ENDPOINT": "storage",
            "MINIO_PORT": "9000",
            "MINIO_BUCKET": "export",
            "MINIO_FOLDER": "stream",
            "MINIO_ACCESS_KEY": "access",
            "MINIO_SECRET_KEY": "secret",
            "STREAM_EXPORTER_S3_SECURE": "false",
            "MINIO_SECURE": "true",
        },
    )

    exporter, minio, warning = build_exporter()

    minio.assert_called_once_with(
        "storage:9000", "access", "secret", secure=False, cert_check="true"
    )
    assert (exporter.minio_bucket, exporter.minio_folder) == ("export", "stream")
    assert warning.call_args_list == [
        call(
            "Deprecated MinIO setting names, rename them to their "
            "STREAM_EXPORTER_S3_* / stream_exporter.s3_* names",
            meta={
                "names": [
                    "MINIO_ENDPOINT",
                    "MINIO_PORT",
                    "MINIO_BUCKET",
                    "MINIO_FOLDER",
                    "MINIO_ACCESS_KEY",
                    "MINIO_SECRET_KEY",
                ]
            },
        ),
        call(
            "S3 setting names ignored, the setting is read from its other name",
            meta={"names": ["MINIO_SECURE"]},
        ),
    ]


def test_the_minio_section_of_the_config_file_reaches_the_client(build_exporter):
    exporter, minio, warning = build_exporter(
        {
            "minio": {
                "endpoint": "storage",
                "port": 9000,
                "bucket": "export",
                "folder": "stream",
                "access_key": "access",
                "secret_key": "secret",
                "secure": True,
                "cert_check": False,
            }
        }
    )

    minio.assert_called_once_with(
        "storage:9000", "access", "secret", secure=True, cert_check=False
    )
    assert (exporter.minio_bucket, exporter.minio_folder) == ("export", "stream")
    warning.assert_called_once_with(
        "Deprecated MinIO setting names, rename them to their "
        "STREAM_EXPORTER_S3_* / stream_exporter.s3_* names",
        meta={
            "names": [
                "minio.endpoint",
                "minio.port",
                "minio.bucket",
                "minio.folder",
                "minio.access_key",
                "minio.secret_key",
                "minio.secure",
                "minio.cert_check",
            ]
        },
    )


def test_the_warnings_come_before_an_invalid_port(monkeypatch, build_exporter):
    set_environment(
        monkeypatch,
        {"STREAM_EXPORTER_S3_PORT": "", "MINIO_PORT": "9000", "MINIO_BUCKET": "export"},
    )

    with pytest.raises(ValueError):
        build_exporter()
    assert build_exporter.warning.call_args_list == [
        call(
            "Deprecated MinIO setting names, rename them to their "
            "STREAM_EXPORTER_S3_* / stream_exporter.s3_* names",
            meta={"names": ["MINIO_BUCKET"]},
        ),
        call(
            "S3 setting names ignored, the setting is read from its other name",
            meta={"names": ["MINIO_PORT"]},
        ),
    ]
