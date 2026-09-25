"""Smoke tests for the developer CLI helpers in ``scripts/``.

The command bodies are deliberately untested (they need a live API key), but
these tests keep the modules importable and their argument parsing honest, so a
future move or rename cannot silently break them.
"""

import pytest
from scripts import dry_run, hunter_client_cli


def test_dry_run_parses_minimal_arguments():
    args = dry_run.build_parser().parse_args(
        ["--entity-type", "Campaign", "--entity-name", "Shai-Hulud 2.0"]
    )

    assert args.entity_type == "Campaign"
    assert args.entity_name == "Shai-Hulud 2.0"
    assert args.out == "-"


def test_dry_run_rejects_unmapped_entity_type():
    with pytest.raises(SystemExit):
        dry_run.build_parser().parse_args(
            ["--entity-type", "City", "--entity-name", "Paris"]
        )


def test_dry_run_synthesises_stable_stix_id():
    first = dry_run._synthesise_stix_id("Threat-Actor-Group", "TeamPCP")
    second = dry_run._synthesise_stix_id("Threat-Actor-Group", "TeamPCP")

    assert first == second
    assert first.startswith("threat-actor--")


def test_hunter_client_cli_parses_filters():
    args = hunter_client_cli.build_parser().parse_args(
        ["--actors", "TeamPCP", "--mitre-technique-ids", "T1059.007", "T1027"]
    )

    assert args.actors == ["TeamPCP"]
    assert args.mitre_technique_ids == ["T1059.007", "T1027"]
    assert args.base_url.startswith("https://")
