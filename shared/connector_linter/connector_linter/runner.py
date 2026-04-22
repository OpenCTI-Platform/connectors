"""Runner: loads checks, executes them against a connector, collects results."""

import importlib
import pkgutil
from pathlib import Path

from connector_linter import checks as checks_package
from connector_linter.models import CheckResult, ConnectorContext
from connector_linter.noqa import filter_noqa
from connector_linter.registry import CheckRegistry


def _discover_checks() -> None:
    """Auto-import all check modules from the checks/ package (recursively)."""
    package_path = Path(checks_package.__file__).parent

    for _finder, module_name, _is_pkg in pkgutil.walk_packages(
        [str(package_path)],
        prefix="connector_linter.checks.",
    ):
        if module_name.rsplit(".", 1)[-1].startswith("_"):
            continue  # skip private helpers like _helpers.py
        importlib.import_module(module_name)


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
    _discover_checks()

    ctx = ConnectorContext.load(connector_path)
    all_checks = CheckRegistry.get_all()

    # Filter checks based on select/ignore
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

    # Execute checks (sorted by code for deterministic output)
    results: list[CheckResult] = []
    for code in sorted(checks_to_run.keys()):
        descriptor = checks_to_run[code]
        try:
            findings = descriptor.func(ctx)
            results.extend(
                CheckResult(
                    code=descriptor.code,
                    name=descriptor.name,
                    message=finding.message,
                    severity=finding.severity or descriptor.severity,
                    passed=finding.passed,
                    file_path=finding.file_path,
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
                    message=f"Check raised an exception: {e}",
                    severity=descriptor.severity,
                    passed=False,
                ),
            )

    # Apply noqa suppression unless disabled
    if not disable_noqa:
        results = filter_noqa(results)

    return results
