"""Tests for the generic connector."""

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from conftest import FakeIndicatorsAPI, build_extractor, load_fixture
from crowdstrike_indicators.bundle import MakeStixBundle
from crowdstrike_indicators.extractor import CrowdStrikeIndicatorExtractor
from crowdstrike_indicators.malware import CrowdStrikeAddMalware
from crowdstrike_indicators.transformer import CrowdStrikeIndicatorTransformer
from pydantic import BaseModel
from stix2.v21 import Bundle, DomainName

from shared.connector import Connector, CycleResult
from shared.extractor import AbstractExtractor
from shared.loader import AbstractLoader
from shared.record_to_file import RecordToFile
from shared.transformer import AbstractTransformer

T0 = datetime(2026, 11, 1, tzinfo=UTC)
FREQUENCY = timedelta(minutes=5)


def at(seconds: int) -> datetime:
    return T0 + timedelta(seconds=seconds)


# --- Test doubles ------------------------------------------------------------


class Item(BaseModel):
    name: str


class ScriptedExtractor(AbstractExtractor[Item]):
    """Returns the given batches in order, one per call, then empty lists."""

    def __init__(self, batches: list[Any]) -> None:
        self.batches = list(batches)
        self.calls: list[tuple[datetime, int]] = []

    def extract(
        self, from_date: datetime, max_element_count: int
    ) -> list[tuple[datetime, Item]]:
        self.calls.append((from_date, max_element_count))
        if not self.batches:
            return []
        batch = self.batches.pop(0)
        if isinstance(batch, Exception):
            raise batch
        return batch


def items(*seconds: int, prefix: str = "item") -> list[tuple[datetime, Item]]:
    return [(at(s), Item(name=f"{prefix}-{s}")) for s in seconds]


class ItemToDomain(AbstractTransformer[Item, DomainName]):
    def convert(self, item: Item) -> DomainName:
        if item.name.startswith("bad"):
            raise ValueError(f"{item.name}: cannot convert")
        return DomainName(value=f"{item.name}.example")


class DomainToBundle(AbstractTransformer[DomainName, Bundle]):
    def convert(self, item: DomainName) -> Bundle:
        bundle_uuid = uuid.uuid5(uuid.NAMESPACE_URL, item.value)
        return Bundle(id=f"bundle--{bundle_uuid}", objects=[item])


class RecordingLoader(AbstractLoader):
    def __init__(self, fail_on: int | None = None) -> None:
        self.loaded: list[Bundle] = []
        self.fail_on = fail_on

    def load(self, bundle: Bundle) -> None:
        if self.fail_on is not None and len(self.loaded) + 1 == self.fail_on:
            raise OSError("destination unavailable")
        self.loaded.append(bundle)


class StopLoop(Exception):
    """Raised by the fake sleep to end ``run``."""


class FakeSleep:
    """Records the waits; raises ``StopLoop`` on the ``stop_after``-th call."""

    def __init__(self, stop_after: int) -> None:
        self.waits: list[float] = []
        self.stop_after = stop_after

    def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)
        if len(self.waits) >= self.stop_after:
            raise StopLoop


def connector(
    extractor: AbstractExtractor[Any],
    loader: AbstractLoader | None = None,
    sleep: FakeSleep | None = None,
) -> Connector:
    return Connector(
        extractor,
        [ItemToDomain(), DomainToBundle()],
        loader or RecordingLoader(),
        sleep=sleep or FakeSleep(stop_after=1),
    )


def names(loader: RecordingLoader) -> list[str]:
    return [bundle.objects[0].value for bundle in loader.loaded]


# --- Construction ------------------------------------------------------------

CROWDSTRIKE_ROWS = load_fixture("indicators_sample.json")["resources"]


def crowdstrike_extractor() -> CrowdStrikeIndicatorExtractor:
    return build_extractor(FakeIndicatorsAPI(CROWDSTRIKE_ROWS))


def test_fitting_crowdstrike_chain_is_accepted(tmp_path):
    Connector(
        crowdstrike_extractor(),
        [CrowdStrikeIndicatorTransformer(), CrowdStrikeAddMalware(), MakeStixBundle()],
        RecordToFile(tmp_path),
    )


def test_mismatching_first_transformer_is_rejected(tmp_path):
    with pytest.raises(TypeError) as caught:
        Connector(
            crowdstrike_extractor(),
            [CrowdStrikeAddMalware(), MakeStixBundle()],
            RecordToFile(tmp_path),
        )

    message = str(caught.value)
    assert "CrowdStrikeIndicator " in message or message.endswith(
        "CrowdStrikeIndicator"
    )
    assert "CrowdStrikeStix2Indicator" in message
    assert "transformer 1 (CrowdStrikeAddMalware)" in message


def test_chain_not_ending_with_a_stix_bundle_is_rejected(tmp_path):
    with pytest.raises(
        TypeError, match="Bundle but .* produces CrowdStrikeIndicatorBundle"
    ):
        Connector(
            crowdstrike_extractor(),
            [CrowdStrikeIndicatorTransformer(), CrowdStrikeAddMalware()],
            RecordToFile(tmp_path),
        )


def test_empty_transformer_list_is_rejected():
    with pytest.raises(TypeError, match="produces Item"):
        Connector(ScriptedExtractor([]), [], RecordingLoader())


def test_component_without_declared_types_is_rejected():
    class Untyped(AbstractTransformer):  # type: ignore[type-arg]
        def convert(self, item: Any) -> Any:
            return item

    with pytest.raises(TypeError, match="Untyped does not declare"):
        Connector(
            ScriptedExtractor([]), [Untyped(), DomainToBundle()], RecordingLoader()
        )


# --- One cycle ---------------------------------------------------------------


def test_cycle_loads_every_item_in_order():
    loader = RecordingLoader()
    extractor = ScriptedExtractor([items(1, 2, 3)])

    result = connector(extractor, loader).run_once(T0, 10)

    assert names(loader) == ["item-1.example", "item-2.example", "item-3.example"]
    assert result == CycleResult(extracted=3, loaded=3, skipped=0, next_from_date=at(3))
    assert extractor.calls == [(T0, 10)]


def test_cycle_with_nothing_new():
    loader = RecordingLoader()

    result = connector(ScriptedExtractor([[]]), loader).run_once(at(7), 10)

    assert loader.loaded == []
    assert result == CycleResult(0, 0, 0, at(7))


def test_failing_item_is_skipped(caplog):
    loader = RecordingLoader()
    batch = items(1) + items(2, prefix="bad") + items(3)

    with caplog.at_level(logging.WARNING, logger="shared.connector"):
        result = connector(ScriptedExtractor([batch]), loader).run_once(T0, 10)

    assert names(loader) == ["item-1.example", "item-3.example"]
    assert result == CycleResult(3, 2, 1, at(3))
    assert "bad-2" in caplog.text
    assert "cannot convert" in caplog.text


def test_loader_failure_aborts_the_cycle():
    loader = RecordingLoader(fail_on=2)

    with pytest.raises(OSError, match="destination unavailable"):
        connector(ScriptedExtractor([items(1, 2, 3)]), loader).run_once(T0, 10)

    assert names(loader) == ["item-1.example"]


def test_extractor_failure_aborts_the_cycle():
    loader = RecordingLoader()
    extractor = ScriptedExtractor([RuntimeError("api down")])

    with pytest.raises(RuntimeError, match="api down"):
        connector(extractor, loader).run_once(T0, 10)

    assert loader.loaded == []


# --- The loop ----------------------------------------------------------------


def test_backlog_is_drained_before_waiting():
    sleep = FakeSleep(stop_after=1)
    extractor = ScriptedExtractor(
        [items(*range(1, 11)), items(*range(11, 21)), items(*range(21, 25))]
    )

    with pytest.raises(StopLoop):
        connector(extractor, sleep=sleep).run(T0, FREQUENCY, 10)

    assert [frm for frm, _ in extractor.calls] == [T0, at(10), at(20)]
    assert sleep.waits == [FREQUENCY.total_seconds()]


def test_cursor_is_carried_over_between_waits():
    sleep = FakeSleep(stop_after=3)
    extractor = ScriptedExtractor([items(1, 2), items(5), []])

    with pytest.raises(StopLoop):
        connector(extractor, sleep=sleep).run(T0, FREQUENCY, 10)

    assert [frm for frm, _ in extractor.calls] == [T0, at(2), at(5)]
    assert sleep.waits == [FREQUENCY.total_seconds()] * 3


@pytest.mark.parametrize("frequency", [timedelta(0), timedelta(seconds=-1)])
def test_invalid_frequency_is_rejected_before_extracting(frequency):
    extractor = ScriptedExtractor([items(1)])

    with pytest.raises(ValueError, match="run_frequency"):
        connector(extractor).run(T0, frequency, 10)

    assert extractor.calls == []


@pytest.mark.parametrize(
    ("from_date", "max_count", "message"),
    [(T0, 0, "max_element_count"), (datetime(2026, 11, 1), 10, "timezone-aware")],
)
def test_invalid_extraction_arguments_are_rejected_before_extracting(
    from_date, max_count, message
):
    extractor = ScriptedExtractor([items(1)])

    with pytest.raises(ValueError, match=message):
        connector(extractor).run(from_date, FREQUENCY, max_count)

    assert extractor.calls == []


def test_failed_cycle_is_retried_from_the_same_cursor(caplog):
    sleep = FakeSleep(stop_after=2)
    loader = RecordingLoader()
    extractor = ScriptedExtractor([RuntimeError("api down"), items(3)])

    with caplog.at_level(logging.ERROR, logger="shared.connector"):
        with pytest.raises(StopLoop):
            connector(extractor, loader, sleep).run(T0, FREQUENCY, 10)

    assert [frm for frm, _ in extractor.calls] == [T0, T0]
    assert sleep.waits == [FREQUENCY.total_seconds()] * 2
    assert names(loader) == ["item-3.example"]
    assert "api down" in caplog.text


def test_stalled_cursor_waits_instead_of_looping(caplog):
    sleep = FakeSleep(stop_after=1)
    full_batch_in_one_second = [(T0, Item(name=f"same-{n}")) for n in range(10)]
    extractor = ScriptedExtractor([full_batch_in_one_second])

    with caplog.at_level(logging.WARNING, logger="shared.connector"):
        with pytest.raises(StopLoop):
            connector(extractor, sleep=sleep).run(T0, FREQUENCY, 10)

    assert len(extractor.calls) == 1
    assert sleep.waits == [FREQUENCY.total_seconds()]
    assert "stalled" in caplog.text


# --- The real CrowdStrike chain ----------------------------------------------


def test_run_with_the_crowdstrike_chain_records_one_file_per_indicator(tmp_path):
    sleep = FakeSleep(stop_after=1)
    real = Connector(
        crowdstrike_extractor(),
        [CrowdStrikeIndicatorTransformer(), CrowdStrikeAddMalware(), MakeStixBundle()],
        RecordToFile(tmp_path),
        sleep=sleep,
    )

    result = real.run_once(datetime(2020, 1, 1, tzinfo=UTC), 100)
    with pytest.raises(StopLoop):
        real.run(datetime(2020, 1, 1, tzinfo=UTC), FREQUENCY, 100)

    latest = max(int(row["_marker"][:10]) for row in CROWDSTRIKE_ROWS)
    assert result.extracted == result.loaded == len(CROWDSTRIKE_ROWS)
    assert result.skipped == 0
    assert result.next_from_date == datetime.fromtimestamp(latest, tz=UTC)
    files = sorted(path.name for path in tmp_path.iterdir())
    assert len(files) == len(CROWDSTRIKE_ROWS)
    assert all(name.startswith("bundle--") and name.endswith(".json") for name in files)
