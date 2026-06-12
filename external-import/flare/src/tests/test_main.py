from collections.abc import Generator
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from main import main


@pytest.fixture
def mocks() -> Generator[SimpleNamespace, None, None]:
    with (
        patch("main.ConnectorSettings") as m_settings,
        patch("main.OpenCTIConnectorHelper") as m_helper,
        patch("main.FlareClient") as m_client,
        patch("main.stix2") as m_stix2,
        patch("main.PyctiIdentity") as m_pycti,
        patch("main.FlareToStixMapper") as m_mapper,
        patch("main.FlareConnector") as m_connector,
        patch("main.traceback") as m_traceback,
        patch("main.sys") as m_sys,
    ):
        yield SimpleNamespace(
            settings_cls=m_settings,
            settings=m_settings.return_value,
            helper_cls=m_helper,
            helper=m_helper.return_value,
            client_cls=m_client,
            client=m_client.return_value,
            stix2=m_stix2,
            author_identity=m_stix2.Identity.return_value,
            pycti=m_pycti,
            mapper_cls=m_mapper,
            mapper=m_mapper.return_value,
            connector_cls=m_connector,
            connector=m_connector.return_value,
            traceback=m_traceback,
            sys=m_sys,
        )


class TestMain:
    def test_creates_and_runs_connector(self, mocks: SimpleNamespace) -> None:
        main()

        mocks.settings_cls.assert_called_once_with()
        mocks.helper_cls.assert_called_once_with(
            config=mocks.settings.to_helper_config.return_value
        )
        mocks.client_cls.assert_called_once_with(
            helper=mocks.helper,
            api_key=mocks.settings.flare.api_key,
            base_url=mocks.settings.flare.api_base_url,
            tenant_id=mocks.settings.flare.tenant_id,
        )
        mocks.pycti.generate_id.assert_called_once_with("Flare", "organization")
        mocks.stix2.Identity.assert_called_once_with(
            id=mocks.pycti.generate_id.return_value,
            name="Flare",
            identity_class="organization",
            description="Cyber Threat Intelligence Platform",
            object_marking_refs=[mocks.stix2.TLP_WHITE.id],
        )
        mocks.mapper_cls.assert_called_once_with(
            config=mocks.settings,
            author_identity=mocks.author_identity,
        )
        mocks.connector_cls.assert_called_once_with(
            config=mocks.settings,
            helper=mocks.helper,
            flare_client=mocks.client,
            mapper=mocks.mapper,
        )
        mocks.connector.run.assert_called_once_with()
        mocks.sys.exit.assert_not_called()
        mocks.traceback.print_exc.assert_not_called()

    @pytest.mark.parametrize(
        "attr_path",
        [
            pytest.param("settings_cls.side_effect", id="settings_init_fails"),
            pytest.param("helper_cls.side_effect", id="helper_init_fails"),
            pytest.param("client_cls.side_effect", id="client_init_fails"),
            pytest.param("stix2.Identity.side_effect", id="identity_creation_fails"),
            pytest.param("pycti.generate_id.side_effect", id="generate_id_fails"),
            pytest.param("mapper_cls.side_effect", id="mapper_init_fails"),
            pytest.param("connector_cls.side_effect", id="connector_init_fails"),
            pytest.param("connector.run.side_effect", id="connector_run_fails"),
        ],
    )
    def test_exception_prints_traceback_and_exits(
        self, mocks: SimpleNamespace, attr_path: str
    ) -> None:
        obj = mocks
        *parents, attr = attr_path.split(".")
        for part in parents:
            obj = getattr(obj, part)
        setattr(obj, attr, RuntimeError("failure"))

        main()

        mocks.traceback.print_exc.assert_called_once()
        mocks.sys.exit.assert_called_once_with(1)
