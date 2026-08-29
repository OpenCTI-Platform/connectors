"""Tests for the run-scoped asset context."""

from wiz_cloud.run_context import WizRunContext, batched


def test_context_deduplicates_and_sorts_asset_ids():
    context = WizRunContext()
    context.add_asset("b")
    context.add_asset("a")
    context.add_asset("b")

    assert context.asset_ids == ["a", "b"]


def test_empty_context_is_falsy():
    assert not WizRunContext()


def test_context_with_an_asset_is_truthy():
    context = WizRunContext()
    context.add_asset("a")

    assert context


def test_batched_splits_on_the_size_boundary():
    assert list(batched(["a", "b", "c"], 2)) == [["a", "b"], ["c"]]


def test_batched_of_an_empty_list_yields_nothing():
    assert list(batched([], 2)) == []
