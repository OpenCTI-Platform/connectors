import pytest
from connector.labels import extract_label_values, parse_actor_labels


@pytest.mark.parametrize(
    "labels, expected",
    [
        pytest.param(["apt:APT44"], ["APT44"], id="single_actor"),
        pytest.param(
            [
                "IOC",
                "apt:APT38",
                "domain",
                "attack-infrastructure",
                "source:lazarus.day",
            ],
            ["APT38"],
            id="ignores_other_namespaces_and_flat_labels",
        ),
        pytest.param([], [], id="no_labels"),
        pytest.param(
            ["IOPA", "domain", "attack-infrastructure", "source:malanta"],
            [],
            id="untagged_indicator_from_the_backlog",
        ),
        pytest.param(
            ["apt:APT28", "apt:APT29", "apt:Fox Kitten"],
            ["APT28", "APT29", "Fox Kitten"],
            id="multiple_actors",
        ),
        pytest.param(
            ["apt:Earth Lusca", "apt:Ajax Security Team"],
            ["Earth Lusca", "Ajax Security Team"],
            id="actor_names_containing_spaces_are_not_split",
        ),
        pytest.param(
            ["redistributed-by:malanta", "source:abuse.ch"],
            [],
            id="other_namespaces_only",
        ),
    ],
)
def test_parse_actor_labels_extracts_expected_actors(labels, expected):
    """Only `apt:` labels yield actors, and their values survive intact."""
    assert parse_actor_labels(labels) == expected


def test_parse_actor_labels_splits_comma_joined_token():
    """A comma-joined token is split into separate actors.

    Upstream data bug: 36 indicators carry `apt:APT17,APT5` as one token. Left
    unsplit it would create an Intrusion Set literally named "APT17,APT5".
    """
    assert parse_actor_labels(["apt:APT17,APT5"]) == ["APT17", "APT5"]


def test_parse_actor_labels_deduplicates_after_splitting():
    """Splitting must not duplicate actors already present as their own tokens.

    On the live feed, `apt:APT17` and `apt:APT5` appear alongside the malformed
    `apt:APT17,APT5` on the same object.
    """
    labels = ["apt:APT17", "apt:APT17,APT5", "apt:APT5"]
    assert parse_actor_labels(labels) == ["APT17", "APT5"]


def test_parse_actor_labels_is_case_insensitive_but_keeps_first_spelling():
    """`turla` and `Turla` are one actor; the first spelling seen is kept."""
    assert parse_actor_labels(["apt:turla", "apt:Turla", "apt:TURLA"]) == ["turla"]
    assert parse_actor_labels(["apt:Turla", "apt:turla"]) == ["Turla"]


def test_parse_actor_labels_matches_prefix_case_insensitively():
    """The namespace itself may be capitalised inconsistently."""
    assert parse_actor_labels(["APT:APT44", "Apt:APT28"]) == ["APT44", "APT28"]


@pytest.mark.parametrize(
    "labels",
    [
        pytest.param(["apt:"], id="empty_value"),
        pytest.param(["apt:   "], id="whitespace_only_value"),
        pytest.param(["apt:,"], id="separator_only"),
        pytest.param(["apt:APT1,,APT2"], id="empty_segment_between_separators"),
    ],
)
def test_parse_actor_labels_drops_empty_segments(labels):
    """Empty or whitespace-only segments never become an Intrusion Set."""
    assert "" not in parse_actor_labels(labels)
    assert all(actor.strip() for actor in parse_actor_labels(labels))


def test_parse_actor_labels_trims_surrounding_whitespace():
    assert parse_actor_labels(["apt: APT44 , APT28 "]) == ["APT44", "APT28"]


def test_parse_actor_labels_ignores_non_string_entries():
    """Defensive: a malformed payload must not crash the stream."""
    assert parse_actor_labels(["apt:APT44", None, 42, {"value": "apt:APT28"}]) == [
        "APT44"
    ]


def test_parse_actor_labels_rejects_empty_prefix():
    """An empty prefix would match every label and is a configuration error."""
    with pytest.raises(ValueError):
        parse_actor_labels(["apt:APT44"], prefix="")


def test_parse_actor_labels_honours_custom_prefix_and_separators():
    labels = ["actor:APT44;APT28", "apt:APT1"]
    assert parse_actor_labels(labels, prefix="actor:", separators=(";",)) == [
        "APT44",
        "APT28",
    ]


@pytest.mark.parametrize(
    "entity, expected",
    [
        pytest.param(
            {"labels": ["apt:APT44", "IOC"]}, ["apt:APT44", "IOC"], id="stix_strings"
        ),
        pytest.param(
            {"labels": [{"value": "apt:APT44"}, {"value": "IOC"}]},
            ["apt:APT44", "IOC"],
            id="opencti_dicts",
        ),
        pytest.param(
            {"labels": ["apt:APT44", {"value": "IOC"}]},
            ["apt:APT44", "IOC"],
            id="mixed_shapes",
        ),
        pytest.param({}, [], id="no_labels_key"),
        pytest.param({"labels": None}, [], id="null_labels"),
        pytest.param({"labels": [{"no_value_key": "x"}]}, [], id="malformed_dict"),
    ],
)
def test_extract_label_values_handles_both_payload_shapes(entity, expected):
    """The stream is not consistent about label shape; both must work."""
    assert extract_label_values(entity) == expected
