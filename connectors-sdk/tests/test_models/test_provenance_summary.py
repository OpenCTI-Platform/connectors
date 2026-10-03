"""Offer tests for the read-only ProvenanceSummary model."""

import copy
import json
import pickle
import warnings
from datetime import datetime, timezone
from typing import Any

import pytest
import stix2
from connectors_sdk import models
from connectors_sdk.models import (
    STIX_EXT_OCTI_PROVENANCE,
    BaseObject,
    IPV4Address,
    Malware,
    OrganizationAuthor,
    ProvenanceSummary,
    ProvenanceSummaryError,
    Relationship,
    Sighting,
)
from connectors_sdk.models.enums import ProvenanceSourceKind
from pydantic import BaseModel, ValidationError

MALWARE_ID = "malware--2b2f3a4e-8a2c-4c6c-a8d4-0d6a7f5f9c11"
IDENTITY_ID = "identity--c9a3a6f2-2a3e-4d43-9f7e-6c1e2b0b8f31"
SIGHTING_ID = "sighting--5d1c9c3e-79a2-4b0f-8a51-9a4a2e2d6c07"
RELATIONSHIP_ID = "relationship--7f0f4c3a-1c2b-4e7a-9a8d-3b5c6d7e8f90"
OCTI_EXTENSION_ID = "extension-definition--ea279b3e-5c71-4632-ac08-831c66a786ba"


@pytest.fixture
def provenance_payload() -> dict[str, Any]:
    """Return a full provenance extension payload, as exported by OpenCTI."""
    return {
        "extension_type": "property-extension",
        "corroboration_count": 3,
        "assertions_count": 7,
        "first_asserted": "2026-01-05T08:00:00.000Z",
        "last_asserted": "2026-09-30T17:45:12.250Z",
        "single_sourced": False,
        "has_conflicts": True,
        "conflicting_fields": ["description", "x_opencti_score"],
        "freshness_stale": False,
        "sources_by_kind": {"connector": 2, "user": 1},
    }


@pytest.fixture
def minimal_payload() -> dict[str, Any]:
    """Return a payload stripped of its optional and empty values."""
    return {
        "extension_type": "property-extension",
        "corroboration_count": 1,
        "assertions_count": 1,
        "single_sourced": True,
        "has_conflicts": False,
        "freshness_stale": True,
    }


def _stix_dict(payload: Any, **extra_extensions: Any) -> dict[str, Any]:
    """Return a STIX object as a plain dict carrying the given provenance payload."""
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": MALWARE_ID,
        "name": "Emotet",
        "is_family": True,
        "extensions": {STIX_EXT_OCTI_PROVENANCE: payload, **extra_extensions},
    }


def test_provenance_summary_is_read_only_and_not_a_write_model() -> None:
    """Test that ProvenanceSummary cannot be converted to a STIX object."""
    # Given the ProvenanceSummary class
    # Then it is not a write model and has no STIX conversion
    assert not issubclass(ProvenanceSummary, BaseObject)
    assert not hasattr(ProvenanceSummary, "to_stix2_object")
    assert ProvenanceSummary.model_config["frozen"] is True


def test_extension_id_constant_matches_opencti_contract() -> None:
    """Test the id of the OpenCTI provenance extension definition."""
    assert (
        STIX_EXT_OCTI_PROVENANCE
        == "extension-definition--283daa2f-7739-5345-a110-19d73676f670"
    )


def test_from_stix_parses_a_full_payload(provenance_payload: dict[str, Any]) -> None:
    """Test that a full provenance extension is parsed with typed values."""
    # Given a STIX object carrying a full provenance extension
    stix_object = _stix_dict(provenance_payload)
    # When reading its provenance summary
    summary = ProvenanceSummary.from_stix(stix_object)
    # Then every field is typed and validated
    assert isinstance(summary, ProvenanceSummary)
    assert summary.extension_type == "property-extension"
    assert summary.corroboration_count == 3
    assert summary.assertions_count == 7
    assert summary.first_asserted == datetime(2026, 1, 5, 8, tzinfo=timezone.utc)
    assert summary.last_asserted == datetime(
        2026, 9, 30, 17, 45, 12, 250000, tzinfo=timezone.utc
    )
    assert summary.single_sourced is False
    assert summary.has_conflicts is True
    assert summary.conflicting_fields == ("description", "x_opencti_score")
    assert summary.freshness_stale is False
    assert dict(summary.sources_by_kind) == {
        ProvenanceSourceKind.CONNECTOR: 2,
        ProvenanceSourceKind.USER: 1,
    }
    assert all(
        isinstance(kind, ProvenanceSourceKind) for kind in summary.sources_by_kind
    )
    # Lookups work with the enum and with plain strings
    assert summary.sources_by_kind[ProvenanceSourceKind.CONNECTOR] == 2
    assert summary.sources_by_kind["user"] == 1
    assert summary.sources_by_kind.get(ProvenanceSourceKind.FEED, 0) == 0


def test_from_stix_applies_defaults_to_a_minimal_payload(
    minimal_payload: dict[str, Any],
) -> None:
    """Test that optional dates and empty collections can be omitted."""
    # Given a payload without dates, conflicting fields nor sources by kind
    # When reading the provenance summary
    summary = ProvenanceSummary.from_stix(_stix_dict(minimal_payload))
    # Then the defaults are applied
    assert summary is not None
    assert summary.first_asserted is None
    assert summary.last_asserted is None
    assert summary.conflicting_fields == ()
    assert dict(summary.sources_by_kind) == {}
    assert summary.single_sourced is True
    assert summary.freshness_stale is True


def test_from_stix_defaults_extension_type(minimal_payload: dict[str, Any]) -> None:
    """Test that a payload without extension_type is accepted."""
    del minimal_payload["extension_type"]
    summary = ProvenanceSummary.from_stix(_stix_dict(minimal_payload))
    assert summary is not None
    assert summary.extension_type == "property-extension"


@pytest.mark.parametrize(
    "stix_object",
    [
        pytest.param({"type": "malware", "id": MALWARE_ID}, id="no extensions"),
        pytest.param(
            {"type": "malware", "id": MALWARE_ID, "extensions": None},
            id="null extensions",
        ),
        pytest.param(
            {"type": "malware", "id": MALWARE_ID, "extensions": {}},
            id="empty extensions",
        ),
        pytest.param(
            {
                "type": "malware",
                "id": MALWARE_ID,
                "extensions": {
                    OCTI_EXTENSION_ID: {"extension_type": "property-extension"}
                },
            },
            id="other extensions only",
        ),
        pytest.param(_stix_dict(None), id="null provenance extension"),
    ],
)
def test_from_stix_returns_none_without_provenance(stix_object: dict[str, Any]) -> None:
    """Test that objects without provenance extension have no summary."""
    # Given a STIX object without provenance extension
    # When reading its provenance summary
    # Then None is returned
    assert ProvenanceSummary.from_stix(stix_object) is None


def test_from_stix_ignores_other_extensions(provenance_payload: dict[str, Any]) -> None:
    """Test that the provenance extension is read next to other extensions."""
    stix_object = _stix_dict(
        provenance_payload,
        **{OCTI_EXTENSION_ID: {"extension_type": "property-extension", "score": 50}},
    )
    summary = ProvenanceSummary.from_stix(stix_object)
    assert summary is not None
    assert summary.corroboration_count == 3


def test_from_stix_ignores_unknown_payload_fields(
    provenance_payload: dict[str, Any],
) -> None:
    """Test forward compatibility with fields added by later OpenCTI versions."""
    # Given a payload with a field unknown to this SDK version
    provenance_payload["future_field"] = {"anything": True}
    # When reading the provenance summary
    summary = ProvenanceSummary.from_stix(_stix_dict(provenance_payload))
    # Then the unknown field is ignored
    assert summary is not None
    assert "future_field" not in summary.model_dump()
    assert summary.model_extra is None


def test_from_stix_tolerates_unknown_source_kinds(
    provenance_payload: dict[str, Any],
) -> None:
    """Test forward compatibility with source kinds added by later OpenCTI versions."""
    # Given a payload with a source kind unknown to this SDK version
    provenance_payload["sources_by_kind"] = {"connector": 2, "sandbox": 4}
    # When reading the provenance summary
    with pytest.warns(UserWarning, match="'sandbox' is out of ProvenanceSourceKind"):
        summary = ProvenanceSummary.from_stix(_stix_dict(provenance_payload))
    # Then the unknown kind is kept with its count, and the summary stays printable
    assert summary is not None
    assert summary.sources_by_kind["sandbox"] == 4
    assert summary.sources_by_kind[ProvenanceSourceKind.CONNECTOR] == 2
    assert "sandbox" in repr(summary)
    assert summary.model_dump(mode="json")["sources_by_kind"] == {
        "connector": 2,
        "sandbox": 4,
    }


@pytest.mark.parametrize(
    "field, value, invalid_field",
    [
        pytest.param(
            "corroboration_count",
            -1,
            "corroboration_count",
            id="negative corroboration",
        ),
        pytest.param(
            "assertions_count", -5, "assertions_count", id="negative assertions"
        ),
        pytest.param(
            "sources_by_kind",
            {"connector": -1},
            "sources_by_kind.connector",
            id="negative source count",
        ),
    ],
)
def test_from_stix_rejects_negative_counts(
    provenance_payload: dict[str, Any], field: str, value: Any, invalid_field: str
) -> None:
    """Test that counts must be non-negative."""
    # Given a payload with a negative count
    provenance_payload[field] = value
    # When reading the provenance summary
    # Then a ProvenanceSummaryError naming the field is raised from the ValidationError
    with pytest.raises(ProvenanceSummaryError, match=invalid_field) as error:
        ProvenanceSummary.from_stix(_stix_dict(provenance_payload))
    assert isinstance(error.value.__cause__, ValidationError)
    assert MALWARE_ID in str(error.value)


def test_model_validate_rejects_negative_counts(
    provenance_payload: dict[str, Any],
) -> None:
    """Test that direct validation raises the pydantic ValidationError."""
    provenance_payload["corroboration_count"] = -1
    with pytest.raises(ValidationError) as error:
        ProvenanceSummary.model_validate(provenance_payload)
    assert error.value.errors()[0]["loc"] == ("corroboration_count",)


@pytest.mark.parametrize(
    "field, value",
    [
        pytest.param("corroboration_count", "3", id="count as string"),
        pytest.param("assertions_count", True, id="count as boolean"),
        pytest.param("assertions_count", 7.5, id="count as float"),
        pytest.param("single_sourced", "false", id="flag as string"),
        pytest.param("has_conflicts", 1, id="flag as integer"),
        pytest.param("freshness_stale", None, id="null flag"),
        pytest.param("first_asserted", "not-a-date", id="invalid date"),
        pytest.param(
            "last_asserted", "2026-09-30T17:45:12", id="date without timezone"
        ),
        pytest.param("conflicting_fields", "description", id="fields as string"),
        pytest.param("conflicting_fields", [""], id="empty field name"),
        pytest.param("conflicting_fields", [42], id="field name as integer"),
        pytest.param("sources_by_kind", ["connector"], id="sources as list"),
        pytest.param(
            "sources_by_kind", {"connector": "2"}, id="source count as string"
        ),
        pytest.param(
            "extension_type", "toplevel-property-extension", id="wrong extension type"
        ),
    ],
)
def test_from_stix_rejects_malformed_values(
    provenance_payload: dict[str, Any], field: str, value: Any
) -> None:
    """Test that values not following the extension contract are rejected."""
    provenance_payload[field] = value
    with pytest.raises(ProvenanceSummaryError, match=field) as error:
        ProvenanceSummary.from_stix(_stix_dict(provenance_payload))
    assert isinstance(error.value.__cause__, ValidationError)


@pytest.mark.parametrize(
    "missing_field",
    [
        "corroboration_count",
        "assertions_count",
        "single_sourced",
        "has_conflicts",
        "freshness_stale",
    ],
)
def test_from_stix_rejects_missing_required_fields(
    provenance_payload: dict[str, Any], missing_field: str
) -> None:
    """Test that the counts and flags of the contract are required."""
    del provenance_payload[missing_field]
    with pytest.raises(ProvenanceSummaryError, match=missing_field):
        ProvenanceSummary.from_stix(_stix_dict(provenance_payload))


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param([1, 2], id="list"),
        pytest.param("corroborated", id="string"),
        pytest.param(3, id="integer"),
    ],
)
def test_from_stix_rejects_a_payload_that_is_not_a_mapping(payload: Any) -> None:
    """Test that a provenance extension must be a mapping."""
    with pytest.raises(ProvenanceSummaryError, match="expected a mapping") as error:
        ProvenanceSummary.from_stix(_stix_dict(payload))
    assert MALWARE_ID in str(error.value)
    assert error.value.__cause__ is None


def test_from_stix_rejects_extensions_that_are_not_a_mapping() -> None:
    """Test that the extensions property must be a mapping."""
    stix_object = {"type": "malware", "id": MALWARE_ID, "extensions": ["provenance"]}
    with pytest.raises(ProvenanceSummaryError, match="'extensions' must be a mapping"):
        ProvenanceSummary.from_stix(stix_object)


def test_provenance_summary_error_is_a_value_error() -> None:
    """Test that generic ValueError handlers catch malformed payloads."""
    assert issubclass(ProvenanceSummaryError, ValueError)


@pytest.mark.parametrize(
    "stix_object",
    [
        pytest.param(json.dumps(_stix_dict({})), id="JSON string"),
        pytest.param(None, id="None"),
        pytest.param([("extensions", {})], id="list of pairs"),
    ],
)
def test_from_stix_requires_a_mapping(stix_object: Any) -> None:
    """Test that the STIX object itself must be a mapping."""
    with pytest.raises(TypeError, match="Expected a STIX object as a mapping"):
        ProvenanceSummary.from_stix(stix_object)


def _stix2_objects(payload: dict[str, Any]) -> list[Any]:
    """Return stix2 library objects of every exported kind carrying the payload."""
    extensions = {STIX_EXT_OCTI_PROVENANCE: payload}
    return [
        stix2.Malware(
            id=MALWARE_ID,
            name="Emotet",
            is_family=True,
            extensions=extensions,
        ),
        stix2.IPv4Address(value="198.51.100.7", extensions=extensions),
        stix2.Relationship(
            id=RELATIONSHIP_ID,
            relationship_type="related-to",
            source_ref=MALWARE_ID,
            target_ref=IDENTITY_ID,
            extensions=extensions,
        ),
        stix2.Sighting(
            id=SIGHTING_ID,
            sighting_of_ref=MALWARE_ID,
            where_sighted_refs=[IDENTITY_ID],
            extensions=extensions,
        ),
    ]


def test_from_stix_reads_stix2_library_objects(
    provenance_payload: dict[str, Any],
) -> None:
    """Test that SDO, SCO, relationship and sighting stix2 objects are supported."""
    # Given stix2 library objects carrying the provenance extension
    expected = ProvenanceSummary.model_validate(provenance_payload)
    for stix_object in _stix2_objects(provenance_payload):
        # When reading their provenance summary
        summary = ProvenanceSummary.from_stix(stix_object)
        # Then it matches the summary parsed from the plain payload
        assert summary == expected, stix_object["type"]


def test_from_stix_reads_parsed_stix2_bundles(
    provenance_payload: dict[str, Any],
) -> None:
    """Test objects parsed by stix2 from a JSON bundle, as connectors receive them."""
    bundle = stix2.parse(
        json.dumps(
            {
                "type": "bundle",
                "id": "bundle--0f7b1a8e-6c5d-4b3a-9e2f-1d0c9b8a7f6e",
                "objects": [_stix_dict(provenance_payload)],
            }
        ),
        allow_custom=True,
    )
    summary = ProvenanceSummary.from_stix(bundle.objects[0])
    assert summary == ProvenanceSummary.model_validate(provenance_payload)


def test_from_stix_returns_none_for_stix2_objects_without_provenance() -> None:
    """Test stix2 library objects without extension."""
    malware = stix2.Malware(id=MALWARE_ID, name="Emotet", is_family=True)
    assert ProvenanceSummary.from_stix(malware) is None


def test_provenance_summary_is_frozen(provenance_payload: dict[str, Any]) -> None:
    """Test that a summary cannot be modified."""
    # Given a provenance summary
    summary = ProvenanceSummary.model_validate(provenance_payload)
    # When trying to modify it, Then it is rejected
    with pytest.raises(ValidationError, match="frozen"):
        summary.corroboration_count = 10
    with pytest.raises(ValidationError, match="frozen"):
        del summary.has_conflicts
    with pytest.raises(TypeError):
        summary.sources_by_kind[ProvenanceSourceKind.FEED] = 1
    with pytest.raises(AttributeError):
        summary.conflicting_fields.append("name")
    assert summary.corroboration_count == 3
    assert ProvenanceSourceKind.FEED not in summary.sources_by_kind


def test_provenance_summary_does_not_share_the_input_mapping(
    provenance_payload: dict[str, Any],
) -> None:
    """Test that mutating the parsed payload does not alter the summary."""
    summary = ProvenanceSummary.model_validate(provenance_payload)
    provenance_payload["sources_by_kind"]["connector"] = 100
    provenance_payload["conflicting_fields"].append("name")
    assert summary.sources_by_kind[ProvenanceSourceKind.CONNECTOR] == 2
    assert summary.conflicting_fields == ("description", "x_opencti_score")


def test_provenance_summary_serialization(provenance_payload: dict[str, Any]) -> None:
    """Test that summaries serialize without warnings and round trip."""
    summary = ProvenanceSummary.model_validate(provenance_payload)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        python_dump = summary.model_dump()
        json_dump = summary.model_dump(mode="json")
        json_string = summary.model_dump_json()
    assert python_dump["sources_by_kind"] == {
        ProvenanceSourceKind.CONNECTOR: 2,
        ProvenanceSourceKind.USER: 1,
    }
    assert type(python_dump["sources_by_kind"]) is dict
    assert json_dump["sources_by_kind"] == {"connector": 2, "user": 1}
    assert json_dump["conflicting_fields"] == ["description", "x_opencti_score"]
    assert json_dump["first_asserted"] == "2026-01-05T08:00:00Z"
    assert json.loads(json_string) == json_dump
    assert ProvenanceSummary.model_validate(python_dump) == summary
    assert ProvenanceSummary.model_validate(json_dump) == summary
    assert ProvenanceSummary.model_validate_json(json_string) == summary


def test_provenance_summary_equality_and_hash(
    provenance_payload: dict[str, Any], minimal_payload: dict[str, Any]
) -> None:
    """Test that summaries are comparable values usable in sets."""
    summary = ProvenanceSummary.model_validate(provenance_payload)
    same_summary = ProvenanceSummary.model_validate(provenance_payload)
    other_summary = ProvenanceSummary.model_validate(minimal_payload)
    assert summary == same_summary
    assert hash(summary) == hash(same_summary)
    assert summary != other_summary
    assert len({summary, same_summary, other_summary}) == 2


@pytest.mark.parametrize(
    "copier",
    [
        pytest.param(copy.copy, id="copy"),
        pytest.param(copy.deepcopy, id="deepcopy"),
        pytest.param(lambda summary: summary.model_copy(), id="model_copy"),
        pytest.param(
            lambda summary: summary.model_copy(deep=True), id="deep model_copy"
        ),
        pytest.param(lambda summary: pickle.loads(pickle.dumps(summary)), id="pickle"),
    ],
)
def test_provenance_summary_copies(
    provenance_payload: dict[str, Any], copier: Any
) -> None:
    """Test that summaries can be copied and pickled."""
    summary = ProvenanceSummary.model_validate(provenance_payload)
    copied = copier(summary)
    assert copied == summary
    assert copied is not summary
    assert copied.model_fields_set == summary.model_fields_set


def test_deep_model_copy_with_update_leaves_the_original_untouched(
    provenance_payload: dict[str, Any],
) -> None:
    """Test that a deep model_copy with update never alters the original summary."""
    summary = ProvenanceSummary.model_validate(provenance_payload)
    updated = summary.model_copy(update={"corroboration_count": 9}, deep=True)
    assert updated.corroboration_count == 9
    assert summary.corroboration_count == 3


def test_write_models_never_carry_provenance() -> None:
    """Test that no write model exposes a provenance or extensions field."""
    # Given every model of the public API
    for name in models.__all__:
        model = getattr(models, name)
        if not (isinstance(model, type) and issubclass(model, BaseModel)):
            continue
        if model is ProvenanceSummary:
            continue
        # Then none of them accepts a provenance summary nor raw STIX extensions
        assert "extensions" not in model.model_fields, name
        for field_name, field in model.model_fields.items():
            assert "ProvenanceSummary" not in str(field.annotation), (name, field_name)


WRITE_MODEL_KINDS = ["sdo", "sco", "relationship", "sighting"]


def _build_write_model(
    kind: str, author: OrganizationAuthor, **extra: Any
) -> BaseObject:
    """Build a write model of a kind that OpenCTI exports with provenance."""
    malware = Malware(name="Emotet", is_family=True, author=author)
    ip = IPV4Address(value="198.51.100.7", author=author)
    builders = {
        "sdo": lambda: Malware(name="Emotet", is_family=True, author=author, **extra),
        "sco": lambda: IPV4Address(value="198.51.100.7", author=author, **extra),
        "relationship": lambda: Relationship(
            type="related-to", source=ip, target=malware, author=author, **extra
        ),
        "sighting": lambda: Sighting(
            sighting_of=malware, where_sighted=[author], author=author, **extra
        ),
    }
    return builders[kind]()


@pytest.mark.parametrize("kind", WRITE_MODEL_KINDS)
@pytest.mark.parametrize("forbidden_input", ["extensions", "provenance"])
def test_write_models_reject_provenance_input(
    fake_valid_organization_author: OrganizationAuthor,
    provenance_payload: dict[str, Any],
    kind: str,
    forbidden_input: str,
) -> None:
    """Test that write models refuse provenance passed as input."""
    # Given provenance passed as raw STIX extensions or as a summary
    values = {
        "extensions": {STIX_EXT_OCTI_PROVENANCE: provenance_payload},
        "provenance": ProvenanceSummary.model_validate(provenance_payload),
    }
    # When building a write model with it
    # Then the write model rejects it
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _build_write_model(
            kind,
            fake_valid_organization_author,
            **{forbidden_input: values[forbidden_input]},
        )


@pytest.mark.parametrize("kind", WRITE_MODEL_KINDS)
def test_write_models_stix_output_has_no_provenance(
    fake_valid_organization_author: OrganizationAuthor, kind: str
) -> None:
    """Test that to_stix2_object never emits the provenance extension."""
    stix_object = _build_write_model(
        kind, fake_valid_organization_author
    ).to_stix2_object()
    assert STIX_EXT_OCTI_PROVENANCE not in stix_object.get("extensions", {})
    assert STIX_EXT_OCTI_PROVENANCE not in stix_object.serialize()
