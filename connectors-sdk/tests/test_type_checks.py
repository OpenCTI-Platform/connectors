# pragma: no cover # Do not compute coverage on test files
"""Offer tests for the static typing of the public API.

`tests/type_checks/` holds modules that are only type-checked, never imported. Each
negative case carries a `# E: <code>` marker on the line `mypy` reports the error on.
"""

import re
import subprocess
import sys
from pathlib import Path

SDK_ROOT = Path(__file__).resolve().parent.parent
TYPE_CHECKS_DIR = Path(__file__).resolve().parent / "type_checks"

# `path:line: error: message  [code]`, `note:` lines do not match
_MYPY_ERROR = re.compile(
    r"^(?P<path>.+?):(?P<line>\d+): error: .*?(?: {2}\[(?P<code>[\w-]+)\])?$"
)
_EXPECTED_ERROR = re.compile(r"#\s*E:\s*(?P<code>[\w-]+)\s*$")


def _expected_errors(source: Path) -> set[tuple[int, str]]:
    """Return the `(line, code)` pairs announced by the `# E: <code>` markers."""
    expected = set()
    for line_number, line in enumerate(source.read_text().splitlines(), start=1):
        marker = _EXPECTED_ERROR.search(line)
        if marker:
            expected.add((line_number, marker.group("code")))
    return expected


def _mypy_errors(source: Path) -> tuple[set[tuple[int, str]], str]:
    """Run strict `mypy` on `source`, return its `(line, code)` errors and its output.

    `mypy` runs from the SDK root so that `pyproject.toml` (strict mode, pydantic
    plugin) applies. The `exclude` option does not apply to a file passed on the
    command line. An error without a code gets the code `<none>`.
    """
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "mypy", str(source)],
        cwd=SDK_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    # Errors are always expected: 1 means "type errors found", 2 is a crash
    assert (
        result.returncode == 1
    ), f"mypy exited with {result.returncode}, expected 1\nmypy output:\n{output}"
    errors = set()
    for output_line in output.splitlines():
        error = _MYPY_ERROR.match(output_line)
        if error:
            # Errors in other files (imports) are out of scope: the checked file
            # is the only one this test has markers for.
            if (SDK_ROOT / error.group("path")).resolve() == source.resolve():
                errors.add((int(error.group("line")), error.group("code") or "<none>"))
    return errors, output


def test_external_import_generics_type_checks():
    """Test that `mypy` reports exactly the errors marked with `# E:`."""
    # Given a module with positive cases (no error) and marked negative cases
    source = TYPE_CHECKS_DIR / "check_external_import_generics.py"
    expected = _expected_errors(source)
    assert expected  # the module must contain negative cases

    # When strict mypy checks it
    actual, output = _mypy_errors(source)

    # Then every marked rejection is reported and nothing else is
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected)
    assert not missing and not unexpected, (
        f"Missing mypy errors (line, code): {missing}\n"
        f"Unexpected mypy errors (line, code): {unexpected}\n"
        f"mypy output:\n{output}"
    )
