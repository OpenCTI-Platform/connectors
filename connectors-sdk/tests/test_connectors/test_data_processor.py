# pragma: no cover
# type: ignore
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

from connectors_sdk.connectors.external_import.base_data_processor import (
    BaseDataProcessor,
)
from connectors_sdk.logging.logger import Logger


class ListProcessor(BaseDataProcessor):
    """Processor that returns a list from transform."""

    work_name = "List Import"

    def collect(self) -> list[str]:
        return ["raw1", "raw2"]

    def transform(self, data: Any) -> list[Any]:
        return [f"stix-{d}" for d in data]


class GeneratorProcessor(BaseDataProcessor):
    """Processor that yields chunks from transform."""

    work_name = "Generator Import"

    def collect(self) -> list[str]:
        return ["a", "b", "c"]

    def transform(self, data: Any) -> Generator[list[Any], None, None]:
        for item in data:
            yield [f"stix-{item}"]


class EmptyListProcessor(BaseDataProcessor):
    """Processor that returns an empty list from transform."""

    work_name = "Empty Import"

    def collect(self) -> list:
        return []

    def transform(self, data: Any) -> list[Any]:
        return []


class EmptyChunkGeneratorProcessor(BaseDataProcessor):
    """Processor that yields some empty chunks."""

    work_name = "Mixed Import"

    def collect(self) -> list:
        return ["a", "", "b"]

    def transform(self, data: Any) -> Generator[list[Any], None, None]:
        for item in data:
            if item:
                yield [f"stix-{item}"]
            else:
                yield []


class TestBaseDataProcessor:

    def _attach_deps(
        self,
        processor: BaseDataProcessor,
        mock_helper: MagicMock,
    ) -> None:
        processor.inject_dependencies(
            settings=MagicMock(),
            helper=mock_helper,
            state=MagicMock(),
        )
        processor.post_init()

    def test_init_subclass(self):
        assert isinstance(ListProcessor.logger, Logger)
        assert ListProcessor.logger._logger.name.endswith(".ListProcessor")

    def test_process_list(self, mock_helper: MagicMock):
        proc = ListProcessor()
        self._attach_deps(proc, mock_helper)
        proc.process()
        mock_helper.api.work.initiate_work.assert_called_once()
        mock_helper.send_stix2_bundle.assert_called_once()

    def test_process_generator(self, mock_helper: MagicMock):
        proc = GeneratorProcessor()
        self._attach_deps(proc, mock_helper)
        proc.process()
        mock_helper.api.work.initiate_work.assert_called_once()
        # 3 chunks → 3 send calls
        assert mock_helper.send_stix2_bundle.call_count == 3

    def test_process_empty_list(self, mock_helper: MagicMock):
        proc = EmptyListProcessor()
        self._attach_deps(proc, mock_helper)
        proc.process()
        # Empty list → no work created
        mock_helper.api.work.initiate_work.assert_not_called()

    def test_process_generator_skips_empty_chunks(self, mock_helper: MagicMock):
        proc = EmptyChunkGeneratorProcessor()
        self._attach_deps(proc, mock_helper)
        proc.process()
        # Only 2 non-empty chunks sent
        assert mock_helper.send_stix2_bundle.call_count == 2

    def test_send_passes_work_name(self, mock_helper: MagicMock):
        proc = ListProcessor()
        self._attach_deps(proc, mock_helper)
        # Call send directly to verify work_name is passed
        with proc.work_manager:
            proc.send(["obj1", "obj2"])
        mock_helper.api.work.initiate_work.assert_called_once_with(
            "test-connector-id", "List Import"
        )

    def test_post_init_called(self, mock_helper: MagicMock):
        """post_init is called by _init_infrastructure after inject_dependencies."""

        class TrackedProcessor(BaseDataProcessor):
            work_name = "Tracked"
            post_init_called = False

            def post_init(self):
                self.post_init_called = True

            def collect(self):
                return []

            def transform(self, data):
                return []

        proc = TrackedProcessor()
        assert not proc.post_init_called
        self._attach_deps(proc, mock_helper)
        assert proc.post_init_called
