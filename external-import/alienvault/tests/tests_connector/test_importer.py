from unittest.mock import MagicMock

from alienvault.importer import PulseImporter


def test_send_bundle_uses_cleanup_inconsistent_bundle() -> None:
    importer = PulseImporter.__new__(PulseImporter)
    importer.helper = MagicMock()
    importer.work_id = "work-id"

    bundle = MagicMock()
    bundle.serialize.return_value = '{"type":"bundle","objects":[]}'

    importer._send_bundle(bundle)

    bundle.serialize.assert_called_once_with()
    importer.helper.send_stix2_bundle.assert_called_once_with(
        '{"type":"bundle","objects":[]}',
        work_id="work-id",
        cleanup_inconsistent_bundle=True,
    )
