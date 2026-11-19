"""Command-line entry point: extract CrowdStrike indicators, or transform one.

Installed as the ``crowdstrike-indicators-cli`` console command, for example
with ``uv run`` from the proof of concept folder::

    uv run crowdstrike-indicators-cli extract --from 2026-11-01T00:00:00Z --max 50
    uv run crowdstrike-indicators-cli transform indicator.json

Exit codes: 0 on success, 1 when the extraction or the transformation fails
(API, validation or conversion error, unreadable input), 2 on a usage or
configuration error.
"""

import argparse
import json
import logging
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from crowdstrike_indicators.entities.errors import (
    CrowdStrikeAPIError,
    IndicatorConversionError,
    IndicatorValidationError,
)
from crowdstrike_indicators.entities.models import EnrichedCrowdStrikeIndicator
from crowdstrike_indicators.entities.stix import CrowdStrikeIndicatorBundle
from crowdstrike_indicators.extract.extractor import validate_indicator
from crowdstrike_indicators.factory import CrowdStrikeConnectorFactory

from shared.factory import ConnectorConfigurationError

LOGGER = logging.getLogger("crowdstrike_indicators")

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE_ERROR = 2

DEFAULT_ENV_FILE = Path(".env")


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
    common.add_argument(
        "--env-file",
        type=Path,
        metavar="PATH",
        help=f"file holding the configuration (default: ./{DEFAULT_ENV_FILE})",
    )

    parser = argparse.ArgumentParser(
        prog="crowdstrike-indicators-cli",
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
        "--output",
        type=Path,
        metavar="FILE",
        help=(
            "write the result to FILE instead of standard output, "
            "only when the extraction succeeds"
        ),
    )

    transform = commands.add_parser(
        "transform",
        parents=[common],
        help="convert one indicator given as JSON into STIX JSON",
        description=(
            "Read one CrowdStrike indicator as a JSON object, in the API shape, "
            "run it through the chain of transformers and print every step's "
            "result as JSON on standard output. "
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
    transform.add_argument(
        "--attack-data",
        type=Path,
        metavar="PATH",
        help=(
            "local MITRE ATT&CK Enterprise STIX bundle (enterprise-attack.json), "
            "instead of CROWDSTRIKE_ATTACK_DATA; with a dataset, a third step "
            "adds the AttackPatterns the labels name"
        ),
    )
    return parser


def _build_factory(
    parser: argparse.ArgumentParser, args: argparse.Namespace, **overrides: Any
) -> CrowdStrikeConnectorFactory | None:
    """Build the factory from the configuration, or report why it cannot be.

    The process environment wins over the ``.env`` file, and ``overrides``
    over both. Returns ``None`` after reporting a configuration error.
    """
    if args.env_file is not None and not args.env_file.is_file():
        parser.error(f"--env-file: no such file: {args.env_file}")
    env_file = args.env_file or DEFAULT_ENV_FILE
    try:
        return CrowdStrikeConnectorFactory(env_file=env_file, **overrides)
    except ConnectorConfigurationError as error:
        print(f"error: {error}", file=sys.stderr)
        print(f"(read from the environment, then from {env_file})", file=sys.stderr)
        return None


def _write_output(path: Path, text: str, count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n", encoding="utf-8")
    LOGGER.info("Wrote %d indicator(s) to %s", count, path)


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
    factory = _build_factory(parser, args)
    if factory is None:
        return EXIT_USAGE_ERROR
    extractor = factory.create_extractor()

    try:
        result = extractor.extract(args.from_date, args.max_element_count)
    except CrowdStrikeAPIError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_FAILURE
    except IndicatorValidationError as error:
        _report_validation_error(error)
        return EXIT_FAILURE

    output = [
        {
            "datetime": dt.isoformat(),
            "indicator": indicator.model_dump(
                mode="json", by_alias=True, exclude_unset=True
            ),
        }
        for dt, indicator in result
    ]
    text = json.dumps(output, indent=2)
    if args.output is not None:
        _write_output(args.output, text, len(result))
    else:
        print(text)
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
    overrides: dict[str, Any] = {}
    if args.attack_data is not None:
        if not args.attack_data.is_file():
            parser.error(f"--attack-data: no such file: {args.attack_data}")
        overrides["attack_data"] = args.attack_data
    factory = _build_factory(parser, args, **overrides)
    if factory is None:
        return EXIT_USAGE_ERROR
    catalog = factory.attack_pattern_catalog
    if catalog is not None:
        LOGGER.info(
            "Loaded %d ATT&CK technique(s) from %s",
            len(catalog),
            factory.settings.attack_data,
        )
    transformers = factory.create_transformers()
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
        value: Any = validate_indicator(raw, EnrichedCrowdStrikeIndicator)
        for number, step in enumerate(transformers, start=1):
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
