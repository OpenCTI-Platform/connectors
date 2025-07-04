from main import main
from pytest_mock import MockerFixture


def test_main(mocker: MockerFixture) -> None:
    # Make sure the main starts without errors
    mocker.patch("main.OpenCTIConnectorHelper")
    mocker.patch("export_report_pdf.connector.Connector._set_colors")
    main()
