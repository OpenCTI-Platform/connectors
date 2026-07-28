from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch


def _stub_cfg():
    cfg = SimpleNamespace(
        connector_duration_period="PT4H",
        connector_update_existing_data=True,
        ti_api_proxy_ip=None,
        ti_api_proxy_port=None,
        ti_api_proxy_protocol=None,
        ti_api_proxy_username=None,
        ti_api_proxy_password=None,
        ti_api_token="tok",
        ti_api_username="u",
        ti_api_url="https://tap.group-ib.com/api/v2/",
        collection_mapping_config={},
        get_collection_settings=MagicMock(return_value=None),
        get_extra_settings_by_name=MagicMock(return_value=None),
        get_extra_settings_bool=MagicMock(return_value=False),
        get_file_logging_config=MagicMock(return_value=SimpleNamespace()),
    )
    return cfg


def _stub_helper():
    helper = MagicMock()
    helper.connect_name = "Group-IB Connector"
    helper.connect_id = "connector--abc"
    helper.get_state = MagicMock(return_value={})
    helper.api = MagicMock()
    helper.metric = MagicMock()
    return helper


def _construct():
    """Construct an ExternalImportConnector with every external dependency
    stubbed. Preserves the real ``COLLECTION_MAP`` on the mock class so the
    enabled-collections comprehension finds the 31 slugs to iterate over."""
    from connector.settings import ConfigConnector as RealConfigConnector

    cfg = _stub_cfg()
    helper = _stub_helper()
    ti_adapter = MagicMock()
    mock_cls = MagicMock(return_value=cfg)
    mock_cls.COLLECTION_MAP = RealConfigConnector.COLLECTION_MAP

    with (
        patch("connector.connector.ConfigConnector", mock_cls),
        patch("connector.connector.OpenCTIConnectorHelper", return_value=helper),
        patch("connector.connector.setup_file_logging"),
        patch("connector.connector.build_ti_adapter", return_value=ti_adapter),
    ):
        from connector.connector import ExternalImportConnector

        return ExternalImportConnector(), cfg, helper, ti_adapter


class TestExternalImportConnectorInit:
    def test_attributes_initialised(self):
        conn, cfg, helper, ti_adapter = _construct()
        assert conn.cfg is cfg
        assert conn.helper is helper
        assert conn.ti_adapter is ti_adapter
        # ``validation_interval`` is called → ``self.interval`` set.
        assert conn.interval == "PT4H"
        # Defaults stamped in.
        assert conn.ttl is None
        assert conn.IGNORE_NON_MALWARE_DDOS is False
        assert conn.IGNORE_NON_INDICATOR_THREATS is False
        assert conn.INTRUSION_SET_INSTEAD_OF_THREAT_ACTOR is False

    def test_enabled_collections_filtered_via_config(self):
        # Only collections whose ``enable`` setting is exactly ``True``
        # land in ``enabled_collections``. Patching ``ConfigConnector``
        # replaces the class object — both the instance constructor AND
        # the class-attribute ``COLLECTION_MAP`` lookup. Preserve the
        # real ``COLLECTION_MAP`` on the mock so the comprehension still
        # has the 31 slugs to iterate over.
        from connector.settings import ConfigConnector as RealConfigConnector

        cfg = _stub_cfg()
        cfg.get_collection_settings = MagicMock(
            side_effect=lambda name, key: name == "apt_threat" and key == "enable"
        )
        mock_cls = MagicMock(return_value=cfg)
        mock_cls.COLLECTION_MAP = RealConfigConnector.COLLECTION_MAP
        with (
            patch("connector.connector.ConfigConnector", mock_cls),
            patch(
                "connector.connector.OpenCTIConnectorHelper",
                return_value=_stub_helper(),
            ),
            patch("connector.connector.setup_file_logging"),
            patch("connector.connector.build_ti_adapter", return_value=MagicMock()),
        ):
            from connector.connector import ExternalImportConnector

            conn = ExternalImportConnector()
        assert conn.enabled_collections == ["apt/threat"]

    def test_ti_adapter_constructed_with_creds(self):
        # Capture the build_ti_adapter mock so we can inspect the kwargs the
        # constructor passed (identity of the return value is covered by
        # test_attributes_initialised).
        from connector.settings import ConfigConnector as RealConfigConnector

        cfg = _stub_cfg()
        mock_cls = MagicMock(return_value=cfg)
        mock_cls.COLLECTION_MAP = RealConfigConnector.COLLECTION_MAP

        with (
            patch("connector.connector.ConfigConnector", mock_cls),
            patch(
                "connector.connector.OpenCTIConnectorHelper",
                return_value=_stub_helper(),
            ),
            patch("connector.connector.setup_file_logging"),
            patch(
                "connector.connector.build_ti_adapter", return_value=MagicMock()
            ) as mock_tiadapter,
        ):
            from connector.connector import ExternalImportConnector

            ExternalImportConnector()

        # ti_creds_dict is built from cfg.ti_api_token / ti_api_username.
        creds = mock_tiadapter.call_args.kwargs["ti_creds_dict"]
        assert creds == {"api_key": "tok", "username": "u"}

    def test_update_existing_data_resolved_from_helper(self):
        conn, cfg, helper, ti_adapter = _construct()
        # ``ExternalImportHelper.validation_update_existing_data`` reads
        # the cfg attribute; with our stub it's ``True``.
        assert conn.update_existing_data is True

    def test_proxies_dict_populated_from_cfg(self):
        from connector.settings import ConfigConnector as RealConfigConnector

        cfg = _stub_cfg()
        cfg.ti_api_proxy_ip = "10.99.0.1"
        cfg.ti_api_proxy_port = "3128"
        cfg.ti_api_proxy_protocol = "http"
        mock_cls = MagicMock(return_value=cfg)
        mock_cls.COLLECTION_MAP = RealConfigConnector.COLLECTION_MAP
        with (
            patch("connector.connector.ConfigConnector", mock_cls),
            patch(
                "connector.connector.OpenCTIConnectorHelper",
                return_value=_stub_helper(),
            ),
            patch("connector.connector.setup_file_logging"),
            patch("connector.connector.build_ti_adapter", return_value=MagicMock()),
        ):
            from connector.connector import ExternalImportConnector

            conn = ExternalImportConnector()
        assert conn.proxies["proxy_ip"] == "10.99.0.1"
        assert conn.proxies["proxy_port"] == "3128"
        assert conn.proxies["proxy_protocol"] == "http"
