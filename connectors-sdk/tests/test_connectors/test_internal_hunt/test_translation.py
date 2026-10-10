# pragma: no cover
# type: ignore
"""Tests of the pySigma translation helpers."""

import sys

import pytest
from connectors_sdk.connectors.internal_hunt import (
    HuntTranslationError,
    build_pipeline,
    convert_sigma,
    detection_fields,
    parse_sigma_rule,
)
from sigma.backends.test import TextQueryTestBackend
from sigma.processing.pipeline import ProcessingPipeline

from .conftest import SIGMA_RULE, TEST_PIPELINES


def test_parse_sigma_rule_returns_the_rules():
    # Given/When a valid Sigma rule is parsed
    collection = parse_sigma_rule(SIGMA_RULE)

    # Then it holds one rule
    assert len(collection.rules) == 1


@pytest.mark.parametrize(
    "document",
    [
        pytest.param("{{{", id="invalid_yaml"),
        pytest.param("title: no logsource", id="invalid_rule"),
        pytest.param("", id="empty_document"),
    ],
)
def test_parse_sigma_rule_rejects_invalid_documents(document):
    # Given/When/Then an invalid document raises a translation error
    with pytest.raises(HuntTranslationError):
        parse_sigma_rule(document)


def test_parse_sigma_rule_reports_missing_pysigma(monkeypatch):
    # Given pySigma is not importable
    monkeypatch.setitem(sys.modules, "sigma.collection", None)

    # When/Then the error tells how to install it
    with pytest.raises(HuntTranslationError, match="pySigma is not installed"):
        parse_sigma_rule(SIGMA_RULE)


@pytest.mark.parametrize("name", [None, "", "  ", "none", "NONE"])
def test_build_pipeline_without_pipeline(name):
    # Given/When/Then no pipeline is built for an empty or "none" name
    assert build_pipeline(name, TEST_PIPELINES) is None


def test_build_pipeline_chains_pipelines():
    # Given/When pipelines are chained with "+" and ","
    single = build_pipeline("dummy", TEST_PIPELINES)
    chained = build_pipeline("dummy+another, ", TEST_PIPELINES)

    # Then the items of each pipeline are applied in order
    assert isinstance(single, ProcessingPipeline)
    assert len(chained.items) == len(single.items) + 1


def test_build_pipeline_rejects_unknown_names():
    # Given/When/Then an unknown pipeline name lists the supported ones
    with pytest.raises(HuntTranslationError, match="another, dummy, none"):
        build_pipeline("dummy+missing", TEST_PIPELINES)


@pytest.mark.parametrize("name", ["+", ",,", " + , "])
def test_build_pipeline_rejects_separators_only(name):
    # Given/When/Then a malformed value is refused, never read as no pipeline
    with pytest.raises(HuntTranslationError, match="Invalid pySigma pipeline"):
        build_pipeline(name, TEST_PIPELINES)


def test_convert_sigma_returns_queries_and_detection_fields():
    # Given a parsed rule and a backend
    collection = parse_sigma_rule(SIGMA_RULE)

    # When it is converted
    queries = convert_sigma(TextQueryTestBackend(), collection)

    # Then the query and the detection field names are returned
    assert queries == ['CommandLine contains " -enc " and DestinationIp="8.8.8.8"']
    assert detection_fields(collection) == ("CommandLine", "DestinationIp")


@pytest.mark.parametrize(
    "output_format, expected",
    [
        pytest.param(
            "str", 'CommandLine contains " -enc " and DestinationIp="8.8.8.8"', id="str"
        ),
        pytest.param(
            "list_of_dict",
            '{"query": "CommandLine contains \\" -enc \\" and DestinationIp=\\"8.8.8.8\\""}',
            id="dict",
        ),
    ],
)
def test_convert_sigma_normalizes_output_formats(output_format, expected):
    # Given/When a backend returns a string or structured queries
    queries = convert_sigma(
        TextQueryTestBackend(), parse_sigma_rule(SIGMA_RULE), output_format
    )

    # Then the queries are strings
    assert queries == [expected]


def test_convert_sigma_wraps_backend_errors():
    # Given/When/Then an unknown output format raises a translation error
    with pytest.raises(HuntTranslationError, match="Sigma conversion failed"):
        convert_sigma(TextQueryTestBackend(), parse_sigma_rule(SIGMA_RULE), "nope")


def test_detection_fields_walks_nested_detections_and_skips_keywords():
    # Given a rule with keywords and nested detection items
    collection = parse_sigma_rule("""
title: Nested
status: test
logsource:
  product: windows
detection:
  keywords:
    - mimikatz
  selection:
    - Image|endswith: '\\\\cmd.exe'
    - ParentImage|endswith: '\\\\explorer.exe'
  condition: keywords or selection
""")

    # When/Then the fields are listed once, keywords excluded
    assert detection_fields(collection) == ("Image", "ParentImage")
