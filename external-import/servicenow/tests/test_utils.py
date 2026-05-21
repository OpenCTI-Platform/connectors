# isort: skipfile
"""Tests for ``connector.services.utils.Utils``."""

import pytest
from src.connector.services.utils import Utils


class TestTransformDescriptionToMarkdownNullComments:
    """``transform_description_to_markdown`` must handle ``comments=None``.

    ServiceNow's REST API returns the ``comments`` field as ``null``
    when no comments are present. Passing that ``None`` through to
    ``comments.strip()`` / the ``re.split`` call raised
    ``AttributeError: 'NoneType' object has no attribute 'strip'`` and
    crashed the enrichment. The helper now coerces ``None`` to an
    empty string before the regex split so the description still
    renders cleanly with only the original ``description`` block.
    """

    def test_none_comments_yields_description_only(self):
        result = Utils.transform_description_to_markdown(
            comment_to_exclude=[],
            description="Original description",
            comments=None,
        )
        assert result.startswith("Original description")
        # No "Date | Author | Comments" markdown table header is
        # emitted when there are no comments to render.
        assert "| Date |" not in result

    @pytest.mark.parametrize("blank_comments", ["", "   ", "\n\n"])
    def test_blank_comments_yield_description_only(self, blank_comments):
        # A pre-existing-empty / whitespace-only ``comments`` value
        # behaves the same way as ``None`` (the previous code path).
        result = Utils.transform_description_to_markdown(
            comment_to_exclude=[],
            description="Original description",
            comments=blank_comments,
        )
        assert result.startswith("Original description")
        assert "| Date |" not in result

    def test_none_comments_does_not_raise_attribute_error(self):
        # Regression guard: the previous code path crashed with
        # ``AttributeError`` on ``comments.strip()`` when ``comments``
        # was ``None``. Make sure the helper now succeeds.
        try:
            Utils.transform_description_to_markdown(
                comment_to_exclude=["private"],
                description="",
                comments=None,
            )
        except AttributeError as exc:  # pragma: no cover - regression guard
            pytest.fail(
                f"transform_description_to_markdown raised AttributeError "
                f"on comments=None: {exc}"
            )
