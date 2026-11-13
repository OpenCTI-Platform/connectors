"""Command-line entry point: extract CrowdStrike indicators, or transform one.

Usage, from the proof of concept folder::

    PYTHONPATH=src python -m crowdstrike_indicators extract --from 2026-11-01T00:00:00Z --max 50
    PYTHONPATH=src python -m crowdstrike_indicators transform indicator.json

Exit codes: 0 on success, 1 when the extraction or the transformation fails
(API, validation or conversion error, unreadable input), 2 on a usage or
configuration error.
"""

import argparse
import json
import logging
import os
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from crowdstrike_indicators.dotenv import read_dotenv
from crowdstrike_indicators.errors import (
    CrowdStrikeAPIError,
    IndicatorConversionError,
    IndicatorValidationError,
)
from crowdstrike_indicators.extractor import (
    CrowdStrikeIndicatorExtractor,
    IndicatorsClient,
    validate_indicator,
)
from crowdstrike_indicators.malware import CrowdStrikeAddMalware
from crowdstrike_indicators.stix import CrowdStrikeIndicatorBundle
from crowdstrike_indicators.transformer import CrowdStrikeIndicatorTransformer

from shared.transformer import AbstractTransformer

LOGGER = logging.getLogger("crowdstrike_indicators")

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE_ERROR = 2

CLIENT_ID = "CROWDSTRIKE_CLIENT_ID"
CLIENT_SECRET = "CROWDSTRIKE_CLIENT_SECRET"
BASE_URL = "CROWDSTRIKE_BASE_URL"
DEFAULT_BASE_URL = "https://api.crowdstrike.com"
DEFAULT_ENV_FILE = Path(".env")

# The steps ``transform`` runs, in order: each takes the previous one's output.
TRANSFORM_STEPS: tuple[AbstractTransformer[Any, Any], ...] = (
    CrowdStrikeIndicatorTransformer(),
    CrowdStrikeAddMalware(),
)


def build_client(client_id: str, client_secret: str, base_url: str) -> IndicatorsClient:
    """Build the FalconPy ``Intel`` service class."""
    from falconpy import Intel

    return Intel(client_id=client_id, client_secret=client_secret, base_url=base_url)


def _parse_from_date(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"not an ISO 8601 datetime: {value!r}"
        ) from error
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _parse_max(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"not an integer: {value!r}") from error
    if parsed < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or more, got {parsed}")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="log level on standard error (default: INFO)",
    )

    parser = argparse.ArgumentParser(
        prog="python -m crowdstrike_indicators",
        description="CrowdStrike Falcon Intelligence indicators proof of concept.",
    )
    commands = parser.add_subparsers(
        dest="command", required=True, metavar="{extract,transform}"
    )

    extract = commands.add_parser(
        "extract",
        parents=[common],
        help="extract indicators from the API and print them as JSON",
        description=(
            "Extract CrowdStrike Falcon Intelligence indicators and print them "
            "as JSON on standard output."
        ),
    )
    extract.add_argument(
        "--from",
        dest="from_date",
        required=True,
        type=_parse_from_date,
        metavar="DATETIME",
        help=(
            "ISO 8601 datetime; indicators at or after it are returned. "
            "Without a timezone, it is read as UTC."
        ),
    )
    extract.add_argument(
        "--max",
        dest="max_element_count",
        required=True,
        type=_parse_max,
        metavar="N",
        help="maximum number of indicators to return (1 or more)",
    )
    extract.add_argument(
        "--env-file",
        type=Path,
        metavar="PATH",
        help=f"file holding the credentials (default: ./{DEFAULT_ENV_FILE})",
    )
    extract.add_argument(
        "--dump-raw",
        type=Path,
        metavar="PATH",
        help="also write every raw API page received, as a JSON array",
    )

    transform = commands.add_parser(
        "transform",
        parents=[common],
        help="convert one indicator given as JSON into STIX JSON",
        description=(
            "Read one CrowdStrike indicator as a JSON object, in the API shape, "
            "and print its STIX 2.1 indicator as JSON on standard output. "
            "No credentials and no network are needed."
        ),
    )
    transform.add_argument(
        "file",
        nargs="?",
        type=Path,
        metavar="FILE",
        help="JSON file holding one indicator (default: standard input)",
    )
    return parser


def _load_config(env_file: Path) -> dict[str, str | None]:
    """Read the configuration; the process environment wins over the file."""
    file_values = read_dotenv(env_file)

    def value(key: str) -> str | None:
        if key in os.environ:
            return os.environ[key]
        return file_values.get(key)

    return {
        CLIENT_ID: value(CLIENT_ID),
        CLIENT_SECRET: value(CLIENT_SECRET),
        BASE_URL: value(BASE_URL) or DEFAULT_BASE_URL,
    }


def _write_dump(path: Path, pages: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(pages, indent=2) + "\n", encoding="utf-8")
    LOGGER.info("Wrote %d raw page(s) to %s", len(pages), path)


def _report_validation_error(error: IndicatorValidationError) -> None:
    print(f"error: {error}", file=sys.stderr)
    print("validation errors:", file=sys.stderr)
    print(json.dumps(error.errors, indent=2, default=str), file=sys.stderr)
    print("raw indicator:", file=sys.stderr)
    print(json.dumps(error.raw, indent=2, default=str), file=sys.stderr)


def _json_type_name(value: Any) -> str:
    return {list: "array", str: "string", bool: "boolean", type(None): "null"}.get(
        type(value), "number"
    )


def _run_extract(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.env_file is not None and not args.env_file.is_file():
        parser.error(f"--env-file: no such file: {args.env_file}")
    config = _load_config(args.env_file or DEFAULT_ENV_FILE)

    missing = [key for key in (CLIENT_ID, CLIENT_SECRET) if not config[key]]
    if missing:
        print(
            f"error: missing configuration: {', '.join(missing)} "
            f"(expected in the environment or in {args.env_file or DEFAULT_ENV_FILE})",
            file=sys.stderr,
        )
        return EXIT_USAGE_ERROR

    pages: list[dict[str, Any]] = []
    client = build_client(config[CLIENT_ID], config[CLIENT_SECRET], config[BASE_URL])
    extractor = CrowdStrikeIndicatorExtractor(
        client, on_raw_page=pages.append if args.dump_raw else None
    )

    try:
        result = extractor.extract(args.from_date, args.max_element_count)
    except CrowdStrikeAPIError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_FAILURE
    except IndicatorValidationError as error:
        _report_validation_error(error)
        return EXIT_FAILURE
    finally:
        if args.dump_raw:
            _write_dump(args.dump_raw, pages)

    output = [
        {
            "datetime": dt.isoformat(),
            "indicator": indicator.model_dump(
                mode="json", by_alias=True, exclude_unset=True
            ),
        }
        for dt, indicator in result
    ]
    print(json.dumps(output, indent=2))
    LOGGER.info("Extracted %d indicator(s)", len(result))
    return EXIT_OK


def _to_json(value: Any) -> Any:
    """Return the JSON form of a step's output."""
    if isinstance(value, CrowdStrikeIndicatorBundle):
        return {
            "indicator": _to_json(value.indicator),
            "malware": [_to_json(obj) for obj in value.malware],
            "attack_patterns": [_to_json(obj) for obj in value.attack_patterns],
            "relationships": [_to_json(obj) for obj in value.relationships],
        }
    # stix2 objects: their STIX JSON, in stix2's property order.
    return json.loads(value.serialize(pretty=True))


def _run_transform(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    if args.file is not None and not args.file.is_file():
        parser.error(f"no such file: {args.file}")
    text = args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read()

    try:
        raw = json.loads(text)
    except json.JSONDecodeError as error:
        print(f"error: input is not valid JSON: {error}", file=sys.stderr)
        return EXIT_FAILURE
    if not isinstance(raw, dict):
        print(
            f"error: expected one JSON object, got {_json_type_name(raw)}",
            file=sys.stderr,
        )
        return EXIT_FAILURE

    steps: list[dict[str, Any]] = []
    try:
        value: Any = validate_indicator(raw)
        for number, step in enumerate(TRANSFORM_STEPS, start=1):
            value = step.convert(value)
            steps.append(
                {
                    "step": number,
                    "transformer": type(step).__name__,
                    "output": _to_json(value),
                }
            )
    except IndicatorValidationError as error:
        _report_validation_error(error)
        return EXIT_FAILURE
    except IndicatorConversionError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_FAILURE

    print(json.dumps(steps, indent=2))
    LOGGER.info("Transformed indicator %s in %d step(s)", raw.get("id"), len(steps))
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        stream=sys.stderr,
        level=args.log_level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )

    if args.command == "transform":
        return _run_transform(parser, args)
    return _run_extract(parser, args)
