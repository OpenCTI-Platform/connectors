"""Runner: loads checks, executes them against a connector, collects results."""

import importlib
import pkgutil
from pathlib import Path

from connector_linter import checks as checks_package
from connector_linter.models import CheckResult, ConnectorContext, Severity
from connector_linter.noqa import filter_noqa
from connector_linter.registry import CheckRegistry

_CHECKS_DISCOVERED = False


def _import_checks_modules() -> None:
    """Auto-import all check modules from the checks/ package (recursively).

    Uses a module-level sentinel so the filesystem walk runs only once per
    process, regardless of how many times run_checks() is called.
    """
    global _CHECKS_DISCOVERED
    if _CHECKS_DISCOVERED:
        return

    package_path = Path(checks_package.__file__).parent

    for _finder, module_name, _is_pkg in pkgutil.walk_packages(
        [str(package_path)],
        prefix="connector_linter.checks.",
    ):
        if module_name.rsplit(".", 1)[-1].startswith("_"):
            continue  # skip private helpers like _helpers.py
        importlib.import_module(module_name)

    _CHECKS_DISCOVERED = True


def _resolve_file_path(file_path: Path | None, root: Path) -> Path | None:
    if file_path is None:
        return None
    return file_path if file_path.is_absolute() else root / file_path


def run_checks(
    connector_path: Path,
    select: list[str] | None = None,
    ignore: list[str] | None = None,
    disable_noqa: bool = False,
) -> list[CheckResult]:
    """Run all registered checks against a connector.

    Args:
        connector_path: Path to the connector directory.
        select: If provided, only run checks matching these codes/prefixes.
        ignore: If provided, skip checks matching these codes/prefixes.
        disable_noqa: If True, ignore all ``# noqa`` inline suppressions.

    Returns:
        List of CheckResult objects.
    """
    _import_checks_modules()

    ctx = ConnectorContext.load(connector_path)
    all_checks = CheckRegistry.get_all()

    checks_to_run = all_checks
    if select:
        filtered = {}
        for pattern in select:
            if pattern in all_checks:
                filtered[pattern] = all_checks[pattern]
            else:
                filtered.update(CheckRegistry.get_by_prefix(pattern))
        checks_to_run = filtered

    if ignore:
        ignore_codes = set()
        for pattern in ignore:
            if pattern in checks_to_run:
                ignore_codes.add(pattern)
            else:
                ignore_codes.update(CheckRegistry.get_by_prefix(pattern).keys())
        checks_to_run = {
            code: desc
            for code, desc in checks_to_run.items()
            if code not in ignore_codes
        }

    results: list[CheckResult] = []
    for code in sorted(checks_to_run.keys()):
        descriptor = checks_to_run[code]

        if (
            descriptor.applicable_types is not None
            and ctx.connector_type is not None
            and ctx.connector_type not in descriptor.applicable_types
        ):
            continue

        try:
            findings = descriptor.func(ctx)
            results.extend(
                CheckResult(
                    code=descriptor.code,
                    name=descriptor.name,
                    message=finding.message,
                    severity=finding.severity,
                    file_path=_resolve_file_path(finding.file_path, ctx.path),
                    line=finding.line,
                    suggestion=finding.suggestion,
                )
                for finding in findings
            )
        except Exception as e:
            results.append(
                CheckResult(
                    code=code,
                    name=descriptor.name,
                    message=f"Check raised {type(e).__name__}: {e}",
                    severity=Severity.ERROR,
                ),
            )

    if not disable_noqa:
        results = filter_noqa(results, connector_path)

    return results
