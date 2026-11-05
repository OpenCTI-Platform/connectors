import re
from unittest.mock import MagicMock, call

import pytest
from importer import connector as connector_module
from importer.lib.external_import import ExternalImportConnector
from importer.s3_config import S3Settings

FIELDS = [
    "ENDPOINT",
    "PORT",
    "SRC_PATH",
    "SRC_RECURSE",
    "DST_PATH",
    "ACCESS_KEY",
    "SECRET_KEY",
    "SECURE",
    "CERT_CHECK",
]


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for field in FIELDS:
        for prefix in ("STREAM_IMPORTER_S3_", "MINIO_", "S3_"):
            monkeypatch.delenv(f"{prefix}{field}", raising=False)
    for name in (
        "PERFECT_SYNC",
        "METRICS_NAMESPACE",
        "METRICS_SUBSYSTEM",
        "METRICS_SUBSYTEM",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def helper(monkeypatch):
    helper = MagicMock()
    monkeypatch.setattr(
        ExternalImportConnector,
        "__init__",
        lambda self: setattr(self, "helper", helper),
    )
    monkeypatch.setattr(connector_module, "Metrics", MagicMock())
    return helper


@pytest.fixture
def minio(monkeypatch):
    minio = MagicMock()
    monkeypatch.setattr(connector_module, "Minio", minio)
    return minio


def set_environment(monkeypatch, values):
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_the_new_variable_is_read():
    settings = S3Settings({"STREAM_IMPORTER_S3_DST_PATH": "done"})

    assert settings.get("DST_PATH") == "done"
    assert settings.former_names_used == []
    assert settings.names_ignored == []


def test_the_s3_variables_of_pycti_are_not_read():
    assert S3Settings({"S3_DST_PATH": "opencti-storage"}).get("DST_PATH") is None


def test_the_former_minio_variable_is_still_read():
    settings = S3Settings({"MINIO_DST_PATH": "done"})

    assert settings.get("DST_PATH") == "done"
    assert settings.former_names_used == ["MINIO_DST_PATH"]
    assert settings.names_ignored == []


def test_the_new_variable_wins_over_the_minio_variable():
    settings = S3Settings(
        {"STREAM_IMPORTER_S3_DST_PATH": "new", "MINIO_DST_PATH": "former"}
    )

    assert settings.get("DST_PATH") == "new"
    assert settings.former_names_used == []
    assert settings.names_ignored == ["MINIO_DST_PATH"]


def test_a_setting_set_nowhere_takes_its_default():
    assert S3Settings({}).get("SECURE", default="true") == "true"


def test_an_empty_new_variable_counts_as_set():
    settings = S3Settings(
        {"STREAM_IMPORTER_S3_SRC_RECURSE": "", "MINIO_SRC_RECURSE": "true"}
    )

    assert settings.get("SRC_RECURSE", default="false") == ""


def test_an_empty_minio_variable_counts_as_set():
    settings = S3Settings({"MINIO_SRC_RECURSE": ""})

    assert settings.get("SRC_RECURSE", default="false") == ""
    assert settings.former_names_used == ["MINIO_SRC_RECURSE"]


def test_the_new_names_reach_the_client_without_warning(monkeypatch, helper, minio):
    set_environment(
        monkeypatch,
        {
            "STREAM_IMPORTER_S3_ENDPOINT": "storage",
            "STREAM_IMPORTER_S3_PORT": "9000",
            "STREAM_IMPORTER_S3_SRC_PATH": "export/stream/2024",
            "STREAM_IMPORTER_S3_SRC_RECURSE": "true",
            "STREAM_IMPORTER_S3_DST_PATH": "done/processed/2024",
            "STREAM_IMPORTER_S3_ACCESS_KEY": "access",
            "STREAM_IMPORTER_S3_SECRET_KEY": "secret",
            "STREAM_IMPORTER_S3_SECURE": "true",
            "STREAM_IMPORTER_S3_CERT_CHECK": "false",
        },
    )

    importer = connector_module.StreamImporterConnector()

    minio.assert_called_once_with(
        "storage:9000", "access", "secret", secure=True, cert_check=False
    )
    assert (importer.minio_src_bucket, importer.minio_src_path) == (
        "export",
        "stream/2024",
    )
    assert importer.minio_src_recurse is True
    assert (importer.minio_dst_bucket, importer.minio_dst_path) == (
        "done",
        "processed/2024",
    )
    helper.connector_logger.warning.assert_not_called()


def test_the_defaults_are_unchanged(monkeypatch, helper, minio):
    set_environment(
        monkeypatch,
        {
            "STREAM_IMPORTER_S3_ENDPOINT": "storage",
            "STREAM_IMPORTER_S3_PORT": "9000",
            "STREAM_IMPORTER_S3_SRC_PATH": "export",
            "STREAM_IMPORTER_S3_DST_PATH": "done",
        },
    )

    importer = connector_module.StreamImporterConnector()

    minio.assert_called_once_with(
        "storage:9000", None, None, secure=True, cert_check=True
    )
    assert importer.minio_src_recurse is False


def test_the_former_names_reach_the_client_and_are_logged_without_values(
    monkeypatch, helper, minio
):
    set_environment(
        monkeypatch,
        {
            "MINIO_ENDPOINT": "storage",
            "MINIO_PORT": "9000",
            "MINIO_SRC_PATH": "export/stream",
            "MINIO_SRC_RECURSE": "true",
            "MINIO_DST_PATH": "done",
            "MINIO_ACCESS_KEY": "access",
            "MINIO_SECRET_KEY": "secret",
            "MINIO_CERT_CHECK": "false",
            "STREAM_IMPORTER_S3_SECURE": "false",
            "MINIO_SECURE": "true",
        },
    )

    importer = connector_module.StreamImporterConnector()

    minio.assert_called_once_with(
        "storage:9000", "access", "secret", secure=False, cert_check=False
    )
    assert (importer.minio_src_bucket, importer.minio_src_path) == ("export", "stream")
    assert importer.minio_src_recurse is True
    assert (importer.minio_dst_bucket, importer.minio_dst_path) == ("done", "")
    assert helper.connector_logger.warning.call_args_list == [
        call(
            "Deprecated MinIO setting names, rename them to their "
            "STREAM_IMPORTER_S3_* names",
            meta={
                "names": [
                    "MINIO_ENDPOINT",
                    "MINIO_PORT",
                    "MINIO_SRC_PATH",
                    "MINIO_SRC_RECURSE",
                    "MINIO_DST_PATH",
                    "MINIO_ACCESS_KEY",
                    "MINIO_SECRET_KEY",
                    "MINIO_CERT_CHECK",
                ]
            },
        ),
        call(
            "S3 setting names ignored, the setting is read from its new name",
            meta={"names": ["MINIO_SECURE"]},
        ),
    ]


@pytest.mark.parametrize(
    "src_name, dst_name",
    [
        ("STREAM_IMPORTER_S3_SRC_PATH", "STREAM_IMPORTER_S3_DST_PATH"),
        ("MINIO_SRC_PATH", "MINIO_DST_PATH"),
        ("STREAM_IMPORTER_S3_SRC_PATH", "MINIO_DST_PATH"),
        ("MINIO_SRC_PATH", "STREAM_IMPORTER_S3_DST_PATH"),
    ],
)
@pytest.mark.parametrize("src_path", ["export/stream", "export"])
def test_one_bucket_without_a_destination_folder_is_refused(
    monkeypatch, helper, minio, src_name, dst_name, src_path
):
    monkeypatch.setenv(src_name, src_path)
    monkeypatch.setenv(dst_name, "export")

    with pytest.raises(
        ValueError,
        match=re.escape(
            "STREAM_IMPORTER_S3_SRC_PATH and STREAM_IMPORTER_S3_DST_PATH "
            "(formerly MINIO_SRC_PATH and MINIO_DST_PATH)"
        ),
    ):
        connector_module.StreamImporterConnector()
    minio.assert_not_called()


def test_one_bucket_with_a_destination_folder_is_accepted(monkeypatch, helper, minio):
    monkeypatch.setenv("MINIO_SRC_PATH", "export/stream")
    monkeypatch.setenv("STREAM_IMPORTER_S3_DST_PATH", "export/processed")

    importer = connector_module.StreamImporterConnector()

    minio.assert_called_once()
    assert (importer.minio_dst_bucket, importer.minio_dst_path) == (
        "export",
        "processed",
    )


@pytest.mark.parametrize("field", ["SECURE", "CERT_CHECK"])
def test_the_deprecation_warning_and_the_refusal_come_before_parsing(
    monkeypatch, helper, minio, field
):
    monkeypatch.setenv("MINIO_SRC_PATH", "export/stream")
    monkeypatch.setenv("MINIO_DST_PATH", "export")
    monkeypatch.setenv(f"MINIO_{field}", "maybe")

    with pytest.raises(ValueError, match="Unsafe S3 configuration"):
        connector_module.StreamImporterConnector()
    helper.connector_logger.warning.assert_called_once_with(
        "Deprecated MinIO setting names, rename them to their "
        "STREAM_IMPORTER_S3_* names",
        meta={"names": ["MINIO_SRC_PATH", "MINIO_DST_PATH", f"MINIO_{field}"]},
    )


def test_the_deprecation_warning_comes_before_an_invalid_value(
    monkeypatch, helper, minio
):
    monkeypatch.setenv("MINIO_SRC_PATH", "export/stream")
    monkeypatch.setenv("MINIO_SRC_RECURSE", "maybe")
    monkeypatch.setenv("MINIO_DST_PATH", "done")

    with pytest.raises(ValueError, match="invalid truth value"):
        connector_module.StreamImporterConnector()
    helper.connector_logger.warning.assert_called_once_with(
        "Deprecated MinIO setting names, rename them to their "
        "STREAM_IMPORTER_S3_* names",
        meta={"names": ["MINIO_SRC_PATH", "MINIO_SRC_RECURSE", "MINIO_DST_PATH"]},
    )


def test_the_deprecation_warning_comes_before_a_missing_path(
    monkeypatch, helper, minio
):
    monkeypatch.setenv("MINIO_DST_PATH", "done")

    with pytest.raises(Exception):
        connector_module.StreamImporterConnector()
    helper.connector_logger.warning.assert_called_once_with(
        "Deprecated MinIO setting names, rename them to their "
        "STREAM_IMPORTER_S3_* names",
        meta={"names": ["MINIO_DST_PATH"]},
    )
