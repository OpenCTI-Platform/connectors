"""Former values of indicators a stream connector could not withdraw yet."""

import threading
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from connectors_sdk.connectors.stream.deployment import (
    PENDING_WITHDRAWALS_STATE_KEY,
    PendingWithdrawals,
)

INDICATOR = "indicator--5d4f2a3b-8c9d-4e1f-a2b3-c4d5e6f7a8b9"
OTHER = "indicator--0d8b4f0e-6a43-4f11-8f6c-1d2f5e6a7b8c"


class StateHelper:
    """The state methods of the pycti helper, over one state document."""

    def __init__(self, state: Any) -> None:
        self.state = state
        self.writes: list[Any] = []
        self.connector_logger = MagicMock()

    def get_state(self) -> Any:
        return self.state

    def set_state(self, state: Any) -> None:
        self.writes.append(state)
        self.state = state


def refuse(*refused: str):
    def withdraw(value: str) -> None:
        if value in refused:
            raise ConnectionError(f"{value} not withdrawn")

    return withdraw


def test_refused_values_are_kept_and_withdrawn_first_by_the_next_call():
    helper = StateHelper({"start_from": "1-0"})
    pending = PendingWithdrawals(helper)

    with pytest.raises(ConnectionError, match="a not withdrawn"):
        pending.withdraw(INDICATOR, refuse("a"), ["a", "b", "a"])

    assert pending.values(INDICATOR) == ["a", "b"]
    assert helper.state == {
        "start_from": "1-0",
        PENDING_WITHDRAWALS_STATE_KEY: {INDICATOR: ["a", "b"]},
    }

    withdrawn: list[str] = []
    pending.withdraw(INDICATOR, withdrawn.append, ["c", "b"])

    assert withdrawn == ["a", "b", "c"]
    assert pending.values(INDICATOR) == []
    assert helper.state == {"start_from": "1-0", PENDING_WITHDRAWALS_STATE_KEY: {}}


def test_only_the_values_not_withdrawn_yet_are_kept():
    helper = StateHelper(
        {PENDING_WITHDRAWALS_STATE_KEY: {INDICATOR: ["a", "b"], OTHER: ["z"]}}
    )
    pending = PendingWithdrawals(helper)

    with pytest.raises(ConnectionError):
        pending.withdraw(INDICATOR, refuse("b"), ["c"])

    assert pending.values(INDICATOR) == ["b", "c"]
    assert pending.values(OTHER) == ["z"]


def test_kept_values_are_added_once_and_withdrawn_by_the_next_call():
    helper = StateHelper({"start_from": "1-0"})
    pending = PendingWithdrawals(helper)

    pending.keep(INDICATOR, ["a", "b", "a"])
    pending.keep(INDICATOR, ["b", "c"])
    pending.keep(INDICATOR, ["c"])

    assert pending.values(INDICATOR) == ["a", "b", "c"]
    assert len(helper.writes) == 2
    withdrawn: list[str] = []
    pending.withdraw(INDICATOR, withdrawn.append)
    assert withdrawn == ["a", "b", "c"]
    assert pending.values(INDICATOR) == []


def test_a_retry_withdraws_the_kept_values_of_every_indicator():
    """A deleted indicator gets no later event: the retries withdraw its values."""
    helper = StateHelper(
        {PENDING_WITHDRAWALS_STATE_KEY: {INDICATOR: ["a", "b"], OTHER: ["z"]}}
    )
    pending = PendingWithdrawals(helper)
    calls: list[tuple[str, str]] = []

    def withdraw(indicator_id: str, value: str) -> None:
        calls.append((indicator_id, value))
        if value == "b":
            raise ConnectionError("b not withdrawn")

    pending.retry_all(withdraw)

    assert calls == [(INDICATOR, "a"), (INDICATOR, "b"), (OTHER, "z")]
    assert pending.values(INDICATOR) == ["b"]
    assert pending.values(OTHER) == []
    helper.connector_logger.warning.assert_called_once_with(
        "[DEPLOYMENT] Former values of an indicator still not withdrawn from the "
        "vendor, retried later.",
        meta={"indicator_id": INDICATOR, "error": "b not withdrawn"},
    )


def test_a_retry_that_cannot_read_the_state_is_logged():
    helper = StateHelper(None)
    helper.get_state = MagicMock(side_effect=RuntimeError("state unavailable"))
    withdraw = MagicMock()

    PendingWithdrawals(helper).retry_all(withdraw)

    withdraw.assert_not_called()
    meta = helper.connector_logger.warning.call_args.kwargs["meta"]
    assert meta == {"indicator_id": None, "error": "state unavailable"}


def test_retries_run_periodically_until_stopped():
    helper = StateHelper({PENDING_WITHDRAWALS_STATE_KEY: {INDICATOR: ["a"]}})
    pending = PendingWithdrawals(helper, retry_interval=0.01)
    withdrawn = threading.Event()

    def withdraw(indicator_id: str, value: str) -> None:
        withdrawn.set()

    assert pending.start_retries(withdraw) is True
    assert pending.start_retries(withdraw) is True
    assert withdrawn.wait(5)
    pending.stop_retries(timeout=5)

    assert not pending._thread.is_alive()
    assert pending.values(INDICATOR) == []


def test_no_retries_without_a_retry_interval():
    pending = PendingWithdrawals(StateHelper({}), retry_interval=0)

    assert pending.start_retries(MagicMock()) is False
    pending.stop_retries()
    assert pending._thread is None


def test_values_withdrawn_at_once_never_write_the_state():
    helper = StateHelper({"start_from": "1-0"})
    withdrawn: list[str] = []

    PendingWithdrawals(helper).withdraw(INDICATOR, withdrawn.append, ["a"])
    PendingWithdrawals(helper).withdraw(OTHER, withdrawn.append)

    assert withdrawn == ["a"]
    assert helper.writes == []


@pytest.mark.parametrize(
    "helper",
    [
        StateHelper(None),
        SimpleNamespace(),
        SimpleNamespace(get_state=lambda: {"start_from": "1-0"}),
    ],
    ids=["state reset", "no state", "state not writable"],
)
def test_nothing_is_kept_without_a_writable_state(helper):
    pending = PendingWithdrawals(helper)

    with pytest.raises(ConnectionError):
        pending.withdraw(INDICATOR, refuse("a"), ["a"])

    assert pending.values(INDICATOR) == []


@pytest.mark.parametrize(
    "kept, values",
    [
        ("not a mapping", []),
        ({INDICATOR: "not a list", 1: ["a"]}, []),
        ({INDICATOR: ["a", 2, None]}, ["a"]),
    ],
)
def test_unreadable_kept_values_are_ignored(kept, values):
    helper = StateHelper({PENDING_WITHDRAWALS_STATE_KEY: kept})

    assert PendingWithdrawals(helper).values(INDICATOR) == values
