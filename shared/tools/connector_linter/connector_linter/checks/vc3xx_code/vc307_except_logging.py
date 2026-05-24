"""VC307 — Except blocks should use error/warning logging, not debug/info."""

from connector_linter.checks.vc3xx_code._helpers import (
    find_calls_in_stmts,
    find_except_blocks,
)
from connector_linter.models import (
    CheckFinding,
    ConnectorContext,
    Severity,
    no_python_sources_finding,
)
from connector_linter.registry import CheckRegistry

# ---------------------------------------------------------------------------
# Logging level separation:
#
#   LOW_LEVEL_METHODS  — debug/info: informational, not appropriate as the
#                        ONLY log in an except block (errors should be loud)
#   HIGH_LEVEL_METHODS — error/warning/critical/exception: appropriate for
#                        except blocks (signal something went wrong)
#
# Having debug/info as supplementary logs alongside error/warning is OK —
# only flag when debug/info is the ONLY logging in the except block.
# ---------------------------------------------------------------------------
_LOW_LEVEL_METHODS = {"debug", "info"}
_HIGH_LEVEL_METHODS = {"error", "warning", "warn", "critical", "exception"}

# ---------------------------------------------------------------------------
# Exception types exempt from the rule:
#
# KeyboardInterrupt and SystemExit are used for graceful shutdown (CTRL+C,
# sys.exit). Logging them at debug/info is appropriate since they're expected
# control flow, not errors.
# ---------------------------------------------------------------------------
_EXEMPT_EXCEPTIONS = {"KeyboardInterrupt", "SystemExit"}


@CheckRegistry.register(
    code="VC307",
    name="except-logging-level",
    description="Except blocks should use error/warning logging, not debug/info",
    severity=Severity.WARNING,
)
def check_except_logging_level(ctx: ConnectorContext) -> list[CheckFinding]:
    """Check that except blocks use error/warning level logging."""
    sources = ctx.python_sources

    if not sources:
        return [no_python_sources_finding()]

    trees = ctx.python_trees
    except_blocks = find_except_blocks(trees)

    issues: list[CheckFinding] = []

    for block in except_blocks:
        # Skip exempt exceptions (KeyboardInterrupt, SystemExit)
        if block.exception_types and set(block.exception_types).issubset(
            _EXEMPT_EXCEPTIONS,
        ):
            continue

        # Find all logging calls in the except body (scoped to this block only)
        all_log_methods = _LOW_LEVEL_METHODS | _HIGH_LEVEL_METHODS
        log_calls = find_calls_in_stmts(
            block.body,
            func_names=all_log_methods,
            file_path=block.file_path,
        )

        if not log_calls:
            # No logging at all in this except block — separate concern,
            # not flagged by this check (could be a different rule)
            continue

        has_high = any(c.func_name in _HIGH_LEVEL_METHODS for c in log_calls)
        low_calls = [c for c in log_calls if c.func_name in _LOW_LEVEL_METHODS]

        # Only flag when debug/info is the ONLY log level used in the block.
        # If error/warning is also present, the debug/info is supplementary and OK.
        if low_calls and not has_high:
            call = low_calls[0]
            issues.append(
                CheckFinding(
                    message=(
                        f"Except block at {block.file_path}:{block.line} uses "
                        f"only {call.func_name}() logging (line {call.line})"
                    ),
                    severity=Severity.WARNING,
                    file_path=block.file_path,
                    line=block.line,
                    suggestion=(
                        "Use logger.error() or logger.warning() in except blocks. "
                        "debug/info can be used as supplementary logs alongside "
                        "error/warning, but should not be the only log level"
                    ),
                ),
            )

    if not issues:
        return [
            CheckFinding(
                message="All except blocks use appropriate logging levels",
                severity=Severity.INFO,
            ),
        ]

    return issues
