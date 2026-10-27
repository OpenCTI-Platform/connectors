import base64
import hashlib

import pytest
from connectors_sdk.models import Artifact, OrganizationAuthor, TLPMarking
from connectors_sdk.models.base_observable_entity import BaseObservableEntity
from connectors_sdk.models.enums import HashAlgorithm
from pydantic import ValidationError
from stix2.v21 import Artifact as Stix2Artifact

PDF = b"%PDF-1.7 test content"
SHA256 = hashlib.sha256(PDF).hexdigest()


def test_artifact_is_a_base_observable_entity() -> None:
    """Test that Artifact is a BaseObservableEntity."""
    assert issubclass(Artifact, BaseObservableEntity)


def test_artifact_from_content() -> None:
    """Test that content is serialised as base64 payload_bin with its MIME type."""
    # Given an artifact built from PDF bytes
    artifact = Artifact(content=PDF, mime_type="application/pdf")
    # When converting it to STIX
    stix = artifact.to_stix2_object()
    # Then the content is base64-encoded and the MIME type kept
    assert isinstance(stix, Stix2Artifact)
    assert base64.b64decode(stix["payload_bin"]) == PDF
    assert stix["mime_type"] == "application/pdf"
    assert "url" not in stix


def test_artifact_content_is_hashed() -> None:
    """Test that the SHA-256 is computed from the content when no hash is given."""
    artifact = Artifact(content=PDF)

    assert artifact.hashes == {HashAlgorithm.SHA256: SHA256}
    assert artifact.to_stix2_object()["hashes"] == {"SHA-256": SHA256}


def test_artifact_given_hashes_are_kept() -> None:
    """Test that hashes given with the content are not replaced."""
    md5 = hashlib.md5(PDF).hexdigest()  # noqa: S324 # Test value, not security
    artifact = Artifact(content=PDF, hashes={HashAlgorithm.MD5: md5})

    assert artifact.hashes == {HashAlgorithm.MD5: md5}


def test_artifact_from_string_content_is_hashed_as_utf8() -> None:
    """Test that string content is hashed like its UTF-8 bytes."""
    artifact = Artifact.model_validate({"content": "text"})

    assert artifact.hashes == {
        HashAlgorithm.SHA256: hashlib.sha256(b"text").hexdigest()
    }


def test_artifact_from_url() -> None:
    """Test an artifact built from a URL and a hash."""
    artifact = Artifact(
        url="https://example.com/report.pdf", hashes={HashAlgorithm.SHA256: SHA256}
    )

    stix = artifact.to_stix2_object()

    assert stix["url"] == "https://example.com/report.pdf"
    assert stix["hashes"] == {"SHA-256": SHA256}
    assert "payload_bin" not in stix


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (
            {"content": PDF, "url": "https://example.com/report.pdf"},
            "mutually exclusive",
        ),
        ({"url": "https://example.com/report.pdf"}, "'hashes' must be provided"),
        ({"mime_type": "application/pdf"}, "Either 'content' or 'url'"),
    ],
)
def test_artifact_invalid_combinations(data: dict[str, object], message: str) -> None:
    """Test that invalid content/URL combinations are rejected."""
    with pytest.raises(ValidationError, match=message):
        Artifact.model_validate(data)


def test_artifact_rejects_unknown_fields() -> None:
    """Test that Artifact does not accept unknown fields."""
    with pytest.raises(ValidationError):
        Artifact.model_validate({"content": PDF, "invalid_key": "invalid_value"})


def test_artifact_id_only_depends_on_content() -> None:
    """Test that file names, MIME type, author and markings do not change the id."""
    first = Artifact(content=PDF, additional_names=["first.pdf"])
    second = Artifact(
        content=PDF,
        mime_type="application/pdf",
        additional_names=["second.pdf"],
        author=OrganizationAuthor(name="Example"),
        markings=[TLPMarking(level="amber")],
    )

    assert first.id == second.id


def test_artifact_id_differs_for_different_content() -> None:
    """Test that different content gives different ids."""
    assert Artifact(content=PDF).id != Artifact(content=b"other").id


def test_artifact_file_name_is_exposed_to_opencti() -> None:
    """Test that file names are serialised as x_opencti_additional_names."""
    stix = Artifact(content=PDF, additional_names=["report.pdf"]).to_stix2_object()

    assert stix["x_opencti_additional_names"] == ["report.pdf"]


def test_artifact_author_and_markings(
    fake_valid_organization_author: OrganizationAuthor,
    fake_valid_tlp_markings: list[TLPMarking],
) -> None:
    """Test that the artifact references its author and markings."""
    stix = Artifact(
        content=PDF,
        author=fake_valid_organization_author,
        markings=fake_valid_tlp_markings,
    ).to_stix2_object()

    assert stix["x_opencti_created_by_ref"] == fake_valid_organization_author.id
    assert stix["object_marking_refs"] == [
        marking.id for marking in fake_valid_tlp_markings
    ]
