"""Source-independent debug command line: run any connector factory's components.

Installed as the ``connector-cli`` console command. The source is the
connector factory named by ``--factory MODULE:CLASS``; its configuration comes
from the process environment, then from ``./.env`` or ``--env-file``, never
from arguments::

    connector-cli --factory crowdstrike_indicators.factory:CrowdStrikeConnectorFactory \\
        extract --from 2026-11-01T00:00:00Z --max 50
    connector-cli --factory crowdstrike_indicators.factory:CrowdStrikeConnectorFactory \\
        transform indicator.json

``extract`` prints what the extractor returns, as one JSON array of
``{"datetime": ..., "item": ...}`` objects. ``transform`` validates one JSON
value as the first transformer's input, then prints each step's output as
soon as it finishes, after a ``Step N - TYPE`` line.

Exit codes: 0 on success, 1 when a component fails or the input cannot be read
(``error: <message>`` on standard error, the traceback at ``--log-level
DEBUG``), 2 on a usage or configuration error.
"""

import argparse
import importlib
import inspect
import json
import logging
import sys
from collections.abc import Sequence
from dataclasses import fields, is_dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, PydanticSchemaGenerationError, TypeAdapter
from stix2.base import _STIXBase

from shared.factory import (
    DEFAULT_ENV_FILE,
    AbstractConnectorFactory,
    ConnectorConfigurationError,
)
from shared.transformer import AbstractTransformer
from shared.type_arguments import declared_types

LOGGER = logging.getLogger("connector_cli")

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE_ERROR = 2


def to_json(value: Any) -> Any:
    """Return the JSON form of a value that :func:`json.dumps` cannot write.

    Meant as ``json.dumps(..., default=to_json)``: ``json.dumps`` writes the
    returned value in turn, so values nested in it are converted the same way.

    * a STIX object (every stix2 object, custom ones included): its STIX JSON,
      with STIX timestamps and property order;
    * a pydantic model: every field, under its alias;
    * a dataclass instance: its fields, in declaration order;
    * a date or a datetime: ISO 8601.

    :raises TypeError: for any other value.
    """
    if isinstance(value, _STIXBase):
        return json.loads(value.serialize(pretty=True))
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", by_alias=True)
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: getattr(value, field.name) for field in fields(value)}
    if isinstance(value, date):
        return value.isoformat()
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _dumps(value: Any) -> str:
    return json.dumps(value, default=to_json, indent=2)


# Arguments


def _factory_class(value: str) -> type[AbstractConnectorFactory[Any]]:
    """Resolve ``MODULE:CLASS`` to a concrete connector factory class."""
    module_name, separator, class_name = value.rpartition(":")
    if not separator or not module_name or not class_name:
        raise argparse.ArgumentTypeError(f"expected MODULE:CLASS, got {value!r}")
    try:
        module = importlib.import_module(module_name)
    except Exception as error:
        raise argparse.ArgumentTypeError(
            f"cannot import {module_name}: {error}"
        ) from error
    try:
        factory = getattr(module, class_name)
    except AttributeError as error:
        raise argparse.ArgumentTypeError(
            f"{module_name} has no attribute {class_name}"
        ) from error
    if not (
        isinstance(factory, type) and issubclass(factory, AbstractConnectorFactory)
    ):
        raise argparse.ArgumentTypeError(f"{value} is not a connector factory")
    if inspect.isabstract(factory):
        raise argparse.ArgumentTypeError(f"{value} is an abstract connector factory")
    return factory


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
    parser = argparse.ArgumentParser(
        prog="connector-cli",
        description=(
            "Run the extractor or the chain of transformers of a connector "
            "factory, and print what they return as JSON."
        ),
    )
    parser.add_argument(
        "--factory",
        required=True,
        type=_factory_class,
        metavar="MODULE:CLASS",
        help=(
            "the connector factory, for example "
            "crowdstrike_indicators.factory:CrowdStrikeConnectorFactory"
        ),
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        metavar="PATH",
        help=(
            "file holding the configuration, read after the environment "
            f"(default: ./{DEFAULT_ENV_FILE})"
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="log level on standard error (default: INFO)",
    )
    commands = parser.add_subparsers(
        dest="command", required=True, metavar="{extract,transform}"
    )

    extract = commands.add_parser(
        "extract",
        help="run the extractor and print what it returns as JSON",
        description=(
            "Run the factory's extractor and print the pairs it returns as one "
            'JSON array of {"datetime": ..., "item": ...} objects.'
        ),
    )
    extract.add_argument(
        "--from",
        dest="from_date",
        required=True,
        type=_parse_from_date,
        metavar="DATETIME",
        help="ISO 8601 datetime passed to the extractor; without a timezone, UTC",
    )
    extract.add_argument(
        "--max",
        dest="max_element_count",
        required=True,
        type=_parse_max,
        metavar="N",
        help="maximum number of items to return (1 or more)",
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
    extract.set_defaults(run=_run_extract)

    transform = commands.add_parser(
        "transform",
        help="run one item through the chain of transformers",
        description=(
            "Read one JSON value, validate it as the first transformer's input, "
            "run it through the factory's chain of transformers and print each "
            "step's output as soon as it finishes."
        ),
    )
    transform.add_argument(
        "file",
        nargs="?",
        type=Path,
        metavar="FILE",
        help="JSON file holding the item (default: standard input)",
    )
    transform.set_defaults(run=_run_transform)
    return parser


# Subcommands


def _run_extract(
    factory: AbstractConnectorFactory[Any], args: argparse.Namespace
) -> int:
    extractor = factory.create_extractor()
    pairs = extractor.extract(args.from_date, args.max_element_count)
    text = _dumps([{"datetime": dt, "item": item} for dt, item in pairs])
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
        LOGGER.info("Wrote %d item(s) to %s", len(pairs), args.output)
    else:
        print(text)
    LOGGER.info("Extracted %d item(s)", len(pairs))
    return EXIT_OK


def _read_input(
    transformers: Sequence[AbstractTransformer[Any, Any]], text: str
) -> Any:
    """Validate ``text`` as the input of the first transformer."""
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as error:
        raise ValueError(f"the input is not valid JSON: {error}") from error
    input_type = declared_types(transformers[0], AbstractTransformer)[0]
    try:
        adapter = TypeAdapter(input_type)
    except PydanticSchemaGenerationError as error:
        raise TypeError(
            f"cannot read an input of type {getattr(input_type, '__name__', input_type)}"
            f" for {type(transformers[0]).__name__}"
        ) from error
    return adapter.validate_python(raw)


def _run_transform(
    factory: AbstractConnectorFactory[Any], args: argparse.Namespace
) -> int:
    transformers = list(factory.create_transformers())
    if not transformers:
        raise ValueError(f"{type(factory).__name__} returned no transformer")
    text = args.file.read_text(encoding="utf-8") if args.file else sys.stdin.read()
    value = _read_input(transformers, text)
    for step, transformer in enumerate(transformers, start=1):
        value = transformer.convert(value)
        output = _dumps(value)
        print(f"Step {step} - {type(transformer).__name__}")
        print(output)
        print(flush=True)
    LOGGER.info("Ran %d step(s)", len(transformers))
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
    if args.env_file is not None and not args.env_file.is_file():
        parser.error(f"--env-file: no such file: {args.env_file}")
    if getattr(args, "file", None) is not None and not args.file.is_file():
        parser.error(f"no such file: {args.file}")
    env_file = args.env_file or DEFAULT_ENV_FILE

    try:
        factory = args.factory(env_file=env_file)
        return args.run(factory, args)
    except ConnectorConfigurationError as error:
        print(f"error: {error}", file=sys.stderr)
        print(f"(read from the environment, then from {env_file})", file=sys.stderr)
        return EXIT_USAGE_ERROR
    except Exception as error:
        print(f"error: {str(error) or type(error).__name__}", file=sys.stderr)
        LOGGER.debug("%s failed", args.command, exc_info=True)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
