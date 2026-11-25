from pathlib import Path
from typing import Any

import pytest
from connector.summary_note import NOTE_TITLE, _escape_markdown, render_summary
from otx_client import OtxGeneral

RESOURCES = Path(__file__).parent.parent / "resources"

IPV4_SUMMARY = """## General

- **Type**: IPv4
- **OTX reputation**: 0

## Geolocation

- **Country**: Netherlands

## Tags

- bruteforce
- SSH
- web app attack
- webscanner

## Malware families

- ExampleBot

## MITRE ATT&CK IDs

- T1027

## Targeted industries

- Financial
- Healthcare
- Legal"""


def load_general(name: str) -> OtxGeneral:
    return OtxGeneral.model_validate_json((RESOURCES / name).read_text())


def make_general(*pulses: dict[str, Any], **fields: Any) -> OtxGeneral:
    """An OTX answer holding the given pulses, with the given top-level fields."""
    return OtxGeneral.model_validate(
        {"pulse_info": {"count": len(pulses), "pulses": list(pulses)}, **fields}
    )


def test_note_title():
    assert NOTE_TITLE == "AlienVault OTX Enrichment Results"


def test_ipv4_fixture_renders_every_section():
    assert render_summary("IPv4", load_general("general_ipv4_known.json")) == (
        IPV4_SUMMARY
    )


def test_domain_fixture_renders_its_lists_without_ipv4_only_sections():
    assert render_summary("domain", load_general("general_domain_known.json")) == (
        "## General\n\n- **Type**: domain\n\n"
        "## Tags\n\n- phishing\n\n"
        "## MITRE ATT&CK IDs\n\n- T1566\n\n"
        "## Targeted industries\n\n- Finance"
    )


def test_ipv4_gate_applies_to_the_section_not_to_the_data():
    # The same answer, read as an IPv4 answer then as a domain answer
    general = load_general("general_ipv4_known.json")

    assert "OTX reputation" in render_summary("IPv4", general)
    assert render_summary("domain", general).startswith(
        "## General\n\n- **Type**: domain\n\n## Tags\n\n"
    )


def test_output_has_no_trailing_newline_and_does_not_repeat_the_title():
    summary = render_summary("IPv4", load_general("general_ipv4_known.json"))

    assert not summary.endswith("\n")
    assert NOTE_TITLE not in summary
    assert summary.startswith("## General\n\n- **Type**: IPv4")


@pytest.mark.parametrize(
    "section, fixture",
    [
        ("domain", "general_domain_known.json"),
        ("hostname", "general_hostname_known.json"),
        ("url", "general_url_known.json"),
    ],
)
def test_other_sections_have_no_reputation_and_no_geolocation(section, fixture):
    summary = render_summary(section, load_general(fixture))

    assert summary.startswith(f"## General\n\n- **Type**: {section}")
    assert "OTX reputation" not in summary
    assert "Geolocation" not in summary


def test_reputation_and_geolocation_are_ignored_outside_the_ipv4_section():
    general = load_general("general_ipv4_known.json")
    assert general.reputation == 0
    assert general.country_name == "Netherlands"

    summary = render_summary("domain", general)

    assert "OTX reputation" not in summary
    assert "Geolocation" not in summary
    assert "Netherlands" not in summary


def test_general_section_is_the_only_one_for_a_known_indicator_without_details():
    general = make_general({"id": "1"}, reputation=None)

    assert render_summary("url", general) == "## General\n\n- **Type**: url"


def test_case_variants_collapse_to_the_smallest_spelling():
    general = make_general({"tags": ["ssh", "SSH", "Ssh"]}, {"tags": ["sSh"]})

    assert render_summary("url", general).endswith("## Tags\n\n- SSH")


def test_case_variants_collapse_across_pulses_whatever_their_order():
    first = {"malware_families": ["emotet"], "industries": ["Finance"]}
    second = {"malware_families": ["Emotet"], "industries": ["FINANCE"]}

    summary = render_summary("url", make_general(first, second))

    assert "- Emotet" in summary
    assert "- emotet" not in summary
    assert "- FINANCE" in summary
    assert "- Finance" not in summary
    assert summary == render_summary("url", make_general(second, first))


def test_lists_are_sorted_case_insensitively():
    general = make_general(
        {"tags": ["banana", "Cherry", "apple", "Banana2", "BANANA1"]}
    )

    assert render_summary("url", general).split("## Tags\n\n")[1].splitlines() == [
        "- apple",
        "- banana",
        "- BANANA1",
        "- Banana2",
        "- Cherry",
    ]


def test_lists_are_the_union_over_the_pulses():
    general = make_general(
        {"tags": ["b"], "attack_ids": ["T1059"]},
        {"tags": ["a", "b"], "attack_ids": ["T1027", "T1059"]},
    )

    summary = render_summary("url", general)

    assert "## Tags\n\n- a\n- b" in summary
    assert "## MITRE ATT&CK IDs\n\n- T1027\n- T1059" in summary


def test_reordering_the_pulses_gives_the_same_output():
    pulses = [
        {
            "tags": ["zeta", "Alpha"],
            "malware_families": ["Beta"],
            "attack_ids": ["T2"],
            "industries": ["Legal"],
        },
        {
            "tags": ["alpha", "gamma"],
            "malware_families": ["alpha", "BETA"],
            "attack_ids": ["T1"],
            "industries": ["Energy"],
        },
        {"tags": ["Zeta"], "industries": ["energy"]},
    ]

    forward = render_summary("IPv4", make_general(*pulses, reputation=3))
    backward = render_summary("IPv4", make_general(*reversed(pulses), reputation=3))

    assert forward == backward


def test_empty_lists_omit_their_sections():
    general = make_general({"tags": ["a"]}, {"malware_families": ["Bot"]})

    summary = render_summary("url", general)

    assert summary == (
        "## General\n\n- **Type**: url\n\n## Tags\n\n- a\n\n"
        "## Malware families\n\n- Bot"
    )
    assert "MITRE ATT&CK IDs" not in summary
    assert "Targeted industries" not in summary


def test_no_pulse_gives_only_the_general_section():
    assert render_summary("url", make_general()) == "## General\n\n- **Type**: url"


def test_partial_geolocation_shows_only_the_present_fields():
    general = make_general({"id": "1"}, city="Amsterdam", country_name="Netherlands")

    assert render_summary("IPv4", general) == (
        "## General\n\n- **Type**: IPv4\n\n"
        "## Geolocation\n\n- **City**: Amsterdam\n- **Country**: Netherlands"
    )


def test_geolocation_lists_city_region_country_in_that_order():
    general = make_general(city="Amsterdam", region="North Holland", country_name="NL")

    assert render_summary("IPv4", general).endswith(
        "## Geolocation\n\n"
        "- **City**: Amsterdam\n- **Region**: North Holland\n- **Country**: NL"
    )


def test_ipv4_without_geolocation_fields_has_no_geolocation_section():
    general = make_general({"tags": ["a"]}, reputation=5)

    summary = render_summary("IPv4", general)

    assert "Geolocation" not in summary
    assert "- **OTX reputation**: 5" in summary


@pytest.mark.parametrize(
    "reputation, expected",
    [(None, None), (0, "0"), (7, "7"), (-2, "-2")],
)
def test_reputation_is_shown_when_it_is_not_none_even_if_zero(reputation, expected):
    summary = render_summary("IPv4", make_general(reputation=reputation))

    if expected is None:
        assert "OTX reputation" not in summary
    else:
        assert f"- **OTX reputation**: {expected}" in summary


def test_special_characters_are_escaped_in_every_rendered_value():
    general = make_general(
        {
            "tags": ["a_b*c", "[x](y)", "<b>", "p|q", "#1", "back\\slash", "`code`"],
            "malware_families": ["Bot_Net"],
            "attack_ids": ["T1_0"],
            "industries": ["R&D*"],
        },
        city="Saint_Louis",
        region="[R]",
        country_name="C*",
    )

    summary = render_summary("IPv4", general)

    for escaped in (
        "- a\\_b\\*c",
        "- \\[x\\](y)",
        "- \\<b\\>",
        "- p\\|q",
        "- \\#1",
        "- back\\\\slash",
        "- \\`code\\`",
        "- Bot\\_Net",
        "- T1\\_0",
        "- R&D\\*",
        "- **City**: Saint\\_Louis",
        "- **Region**: \\[R\\]",
        "- **Country**: C\\*",
    ):
        assert escaped in summary.splitlines()


def test_whitespace_inside_values_is_collapsed_to_one_space():
    general = make_general(
        {
            "tags": ["multi\nline\n\ntag", "tab\tseparated", "a b", "a  \n b"],
            "malware_families": ["Bot\r\nNet"],
            "attack_ids": ["T1\t027"],
            "industries": ["Oil \n\n and Gas"],
        },
        city="New\nYork",
        region="North\t\tHolland",
        country_name="Nether\n\nlands",
    )

    summary = render_summary("IPv4", general)

    assert summary.splitlines() == [
        "## General",
        "",
        "- **Type**: IPv4",
        "",
        "## Geolocation",
        "",
        "- **City**: New York",
        "- **Region**: North Holland",
        "- **Country**: Nether lands",
        "",
        "## Tags",
        "",
        "- a b",
        "- multi line tag",
        "- tab separated",
        "",
        "## Malware families",
        "",
        "- Bot Net",
        "",
        "## MITRE ATT&CK IDs",
        "",
        "- T1 027",
        "",
        "## Targeted industries",
        "",
        "- Oil and Gas",
    ]


def test_values_that_differ_only_by_whitespace_or_case_are_one_item():
    general = make_general({"tags": ["Foo\nBar"]}, {"tags": ["foo   bar", "FOO BAR"]})

    assert render_summary("url", general).endswith("## Tags\n\n- FOO BAR")


def test_a_value_that_is_only_whitespace_is_skipped():
    general = make_general({"id": "1"}, city="x")
    # The models drop blank values: build the pulse around them to stay safe
    pulse = general.pulse_info.pulses[0].model_copy(update={"tags": [" \n\t ", "a"]})
    general = general.model_copy(
        update={
            "city": " \n ",
            "pulse_info": general.pulse_info.model_copy(update={"pulses": [pulse]}),
        }
    )

    assert render_summary("IPv4", general) == (
        "## General\n\n- **Type**: IPv4\n\n## Tags\n\n- a"
    )


def test_escape_markdown_escapes_each_special_character_once():
    assert _escape_markdown("\\`*_[]<>|#") == "\\\\\\`\\*\\_\\[\\]\\<\\>\\|\\#"
    assert _escape_markdown("plain text & (parentheses)") == (
        "plain text & (parentheses)"
    )


def test_markdown_headings_and_labels_are_not_escaped():
    summary = render_summary("IPv4", load_general("general_ipv4_known.json"))

    assert "\\#" not in summary
    assert "## MITRE ATT&CK IDs" in summary
    assert "- **Type**: IPv4" in summary


def test_country_names_with_a_comma_are_never_rendered_or_split():
    general = load_general("general_ipv4_known.json")
    assert (
        "Tanzania, United Republic of"
        in general.pulse_info.pulses[0].targeted_countries
    )

    summary = render_summary("IPv4", general)

    assert "Tanzania" not in summary
    assert "United Republic" not in summary
    assert "Targeted countries" not in summary


@pytest.mark.parametrize(
    "section, fixture, indicator",
    [
        ("IPv4", "general_ipv4_known.json", "192.0.2.10"),
        ("domain", "general_domain_known.json", "malicious.example"),
        ("hostname", "general_hostname_known.json", "www.malicious.example"),
        ("url", "general_url_known.json", "http://malicious.example/payload.bin"),
    ],
)
def test_the_indicator_value_is_not_in_the_content(section, fixture, indicator):
    general = load_general(fixture)
    assert general.indicator is not None

    summary = render_summary(section, general)

    assert general.indicator not in summary
    assert indicator not in summary
