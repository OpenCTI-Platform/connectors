from typing import Any

import pytest
from connector import ConnectorSettings
from connectors_sdk import BaseConfigModel, ConfigValidationError


@pytest.mark.parametrize(
    "settings_dict",
    [
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "config": {
                    "sectors_file_url": "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/sectors.json",
                    "geography_file_url": "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/geography.json",
                    "companies_file_url": "https://raw.githubusercontent.com/OpenCTI-Platform/datasets/master/data/companies.json",
                    "remove_creator": False,
                    "interval": 7,
                },
            },
            id="full_valid_settings_dict",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                # ``id`` is required by ``BaseExternalImportConnectorConfig`` — the
                # connector no longer pins a hardcoded default UUID (sharing one
                # across deployments collides on the platform side), so the
                # "minimal valid" dict still has to supply a unique connector id.
                "connector": {"id": "connector-id"},
                "config": {},
            },
            id="minimal_valid_settings_dict",
        ),
    ],
)
def test_settings_should_accept_valid_input(settings_dict):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) accepts valid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake but valid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    settings = FakeConnectorSettings()
    assert isinstance(settings.opencti, BaseConfigModel) is True
    assert isinstance(settings.connector, BaseConfigModel) is True
    assert isinstance(settings.config, BaseConfigModel) is True


@pytest.mark.parametrize(
    "settings_dict, expected_field",
    [
        # Empty input — Pydantic walks into the required ``opencti``
        # subtree and surfaces the leaf-level required fields (``url``
        # and ``token``) rather than a generic top-level message. Pin
        # the assertion on ``url`` so the test ties the failure back
        # to the actual missing input instead of a generic "validation
        # failed" check.
        pytest.param({}, "url", id="empty_settings_dict"),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080"},
                "connector": {
                    "id": "connector-id",
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "config": {},
            },
            "token",
            id="missing_opencti_token",
        ),
        pytest.param(
            {
                "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                "connector": {
                    "id": 123456,
                    "name": "Test Connector",
                    "scope": "test, connector",
                    "log_level": "error",
                    "duration_period": "PT5M",
                },
                "config": {},
            },
            "id",
            id="invalid_connector_id",
        ),
    ],
)
def test_settings_should_raise_when_invalid_input(settings_dict, expected_field):
    """
    Test that `ConnectorSettings` (implementation of `BaseConnectorSettings` from `connectors-sdk`) raises on invalid input.
    For the test purpose, `BaseConnectorSettings._load_config_dict` is overridden to return
    a fake and invalid dict (instead of the env/config vars parsed from `config.yml`, `.env` or env vars).

    :param settings_dict: The dict to use as `ConnectorSettings` input
    :param expected_field: A token from the offending field path that the
        wrapped Pydantic error message MUST mention — pins the failure
        back to the input that actually triggered it, so a future
        refactor that flips the error type but keeps the wrapped class
        cannot pass by accident.
    """

    class FakeConnectorSettings(ConnectorSettings):
        """
        Subclass of `ConnectorSettings` (implementation of `BaseConnectorSettings`) for testing purpose.
        It overrides `BaseConnectorSettings._load_config_dict` to return a fake but valid config dict.
        """

        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(settings_dict)

    # ``match=`` checks the exception message via ``re.search``, which is the
    # idiomatic way to assert content on a ``pytest.raises`` block; the previous
    # ``str("Error validating configuration") in str(err)`` was brittle because
    # ``err`` is a ``pytest.ExceptionInfo`` whose ``str`` form is just the
    # repr of the wrapped exception class, not the exception message — the
    # assertion would have passed for unrelated ``ConfigValidationError``
    # messages too.
    with pytest.raises(
        ConfigValidationError, match="Error validating configuration"
    ) as exc_info:
        FakeConnectorSettings()

    # Tie the failure back to the offending field. ``ConfigValidationError``
    # wraps the underlying Pydantic ``ValidationError`` (chained via
    # ``__cause__`` / ``__context__``); the input field name appears in the
    # wrapped message regardless of which layer formats it. Asserting on a
    # token here turns each parametrised case into an end-to-end pin: the
    # ``missing_opencti_token`` case fails for the right reason
    # (missing ``token``), not because some other unrelated field
    # happened to be invalid too.
    raised = exc_info.value
    wrapped = "\n".join(
        str(e) for e in (raised, raised.__cause__, raised.__context__) if e is not None
    )
    assert expected_field in wrapped, (
        f"expected the validation error to mention {expected_field!r}, "
        f"got: {wrapped!r}"
    )


@pytest.mark.parametrize(
    "raw_value,expected",
    [
        # Real YAML boolean (from ``config.yml``) is normalised to the
        # empty-string sentinel that disables the dataset downstream.
        pytest.param(False, "", id="real_bool_false"),
        # Env-var / Docker-compose string "false" (case-insensitive +
        # surrounding whitespace) is coerced to ``""`` so the README's
        # "set to ``false`` to disable" UX works end-to-end no matter
        # how the value arrives.
        pytest.param("false", "", id="literal_string_false"),
        pytest.param("FALSE", "", id="uppercase_string_false"),
        pytest.param("  false  ", "", id="whitespace_string_false"),
        # YAML ``null`` / a missing key (``sectors_file_url:`` with no
        # value in ``config.yml``) surfaces as Python ``None`` after the
        # YAML loader runs. Without normalisation Pydantic would reject
        # ``None`` against the ``str`` field at validation time, which
        # would block the connector from starting instead of honouring
        # the README's "leave empty to disable" contract.
        pytest.param(None, "", id="real_none"),
        # The empty / whitespace-only strings are the operator-friendly
        # disable sentinels (UI input, env-var trimmed to nothing). All
        # of them collapse to ``""`` so the connector filters them out
        # the same way as the explicit ``false`` form. Without this a
        # value like ``"   "`` would survive validation, pass the
        # truthy filter, and crash the connector with
        # ``urllib.request.urlopen("   ")`` on the first scheduled run.
        pytest.param("", "", id="empty_string"),
        pytest.param("   ", "", id="whitespace_only_string"),
        pytest.param("\t\n  ", "", id="tab_newline_whitespace_string"),
        # Any other string is preserved as-is (still a real URL).
        pytest.param(
            "https://example.invalid/x.json",
            "https://example.invalid/x.json",
            id="url_string",
        ),
    ],
)
def test_dataset_url_disable_sentinels_are_normalised(raw_value, expected):
    """Disable sentinels normalise to ``""`` (the connector then filters truthy).

    Pins the full disable-via-config contract so a future refactor of
    the ``BeforeValidator`` cannot silently re-introduce one of the
    historical bugs:

    - typed ``str`` field stored the literal string ``"false"`` and the
      downstream URL filter never matched, so the connector issued an
      HTTP GET for the URL ``"false"`` and logged an error;
    - YAML ``null`` (``sectors_file_url:`` with no value) raised a
      ``ConfigValidationError`` instead of honouring the README's
      "leave empty to disable" UX;
    - a whitespace-only string survived validation and crashed
      ``urllib.request.urlopen`` on the first scheduled run.

    Also pins that we expose a plain ``str`` field to the JSON schema
    generator - the previous ``str | Literal[False]`` union produced an
    ``anyOf`` schema that the OpenCTI Manager / XTM Composer UI tags as
    "Unsupported" and refuses to render.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id"},
                    "config": {"sectors_file_url": raw_value},
                }
            )

    settings = FakeConnectorSettings()
    assert settings.config.sectors_file_url == expected


@pytest.mark.parametrize(
    "raw_value",
    [
        # Real YAML boolean ``True`` is meaningless for a URL field
        # ("enable the URL" is not a thing - either set a URL or leave
        # the default) and would otherwise survive any laxer typing all
        # the way to ``urllib.request.urlopen(True)`` which raises
        # ``TypeError`` at runtime. With the plain ``str`` typing on
        # ``DatasetUrl`` Pydantic rejects ``True`` at validation time
        # (``True`` is not a string, and the ``BeforeValidator`` only
        # normalises ``False``), so the operator sees a clear
        # ``ConfigValidationError`` at startup instead of a runtime
        # crash on the first scheduled run.
        pytest.param(True, id="real_bool_true"),
    ],
)
def test_dataset_url_rejects_true(raw_value):
    """Real ``True`` is rejected at validation time.

    Pins the ``DatasetUrl`` contract so a future refactor that swaps
    the field back to a permissive ``str | bool`` (or drops the
    ``BeforeValidator``) cannot silently let ``True`` flow into the
    URL list and crash the connector on the first run with a confusing
    ``TypeError`` from inside ``urllib.request.urlopen``.
    """
    from connectors_sdk import ConfigValidationError as _CVE

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id"},
                    "config": {"sectors_file_url": raw_value},
                }
            )

    with pytest.raises(_CVE, match="Error validating configuration"):
        FakeConnectorSettings()


def test_dataset_url_literal_string_true_is_kept_as_url_string():
    """``"true"`` (string) lands verbatim - the disable contract is one-way.

    The ``BeforeValidator`` only normalises ``False`` / ``"false"`` so
    the operator-friendly disable sentinel is unambiguous. ``"true"``
    is not a disable sentinel and there is no ``"enable"`` semantics
    on a URL field - it is treated as a (broken) URL string and round
    trips verbatim. Documenting it here makes the contract explicit;
    if the disable-only contract is ever extended both ways, flip this
    case to ``pytest.raises``.
    """

    class FakeConnectorSettings(ConnectorSettings):
        @classmethod
        def _load_config_dict(cls, _, handler) -> dict[str, Any]:
            return handler(
                {
                    "opencti": {"url": "http://localhost:8080", "token": "test-token"},
                    "connector": {"id": "connector-id"},
                    "config": {"sectors_file_url": "true"},
                }
            )

    settings = FakeConnectorSettings()
    assert settings.config.sectors_file_url == "true"


def test_dataset_url_schema_is_plain_string():
    """The dataset URL fields MUST expose ``{"type": "string"}`` in the JSON schema.

    Pins the fix for the OpenCTI Manager / XTM Composer
    "CONFIG_*_FILE_URL - Unsupported" regression: the previous
    ``str | Literal[False]`` typing emitted an
    ``anyOf: [{"type": "string"}, {"const": false, "type": "boolean"}]``
    that those UIs reject. The contract we ship to the Manager
    therefore MUST be a plain string type - the disable sentinel is
    enforced at the Pydantic validator level, not the JSON Schema
    level.
    """
    from connector.settings import OpenctiConfig

    schema = OpenctiConfig.model_json_schema()
    for field in ("sectors_file_url", "geography_file_url", "companies_file_url"):
        field_schema = schema["properties"][field]
        assert (
            field_schema.get("type") == "string"
        ), f"{field} must be a plain string in JSON Schema, got {field_schema!r}"
        assert "anyOf" not in field_schema, (
            f"{field} must NOT expose an anyOf schema (UI renders it as "
            f"Unsupported), got {field_schema!r}"
        )
