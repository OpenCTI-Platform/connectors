"""Translation of Sigma rules into SentinelOne PowerQuery.

The community pySigma SentinelOne PowerQuery backend provides the field mapping
of the SentinelOne EDR telemetry and the query syntax. Its output is adjusted to
what the PowerQuery reference of SentinelOne requires to keep the Sigma
semantics on the Singularity Data Lake:

- a negation is written ``!(...)``, always parenthesised: in
  ``not f contains "x"`` the negation applies to the field and the query
  matches nothing;
- prefixes and suffixes use ``starts_with`` / ``ends_with`` instead of
  ``contains``, so the ``startswith`` / ``endswith`` modifiers and the CIDR
  ranges (expanded to address prefixes) match exactly;
- plain values compare without case (``in:anycase``), as Sigma does: ``=`` and
  ``in`` compare strings with case in PowerQuery;
- a value with inner wildcards is matched with an anchored regular expression;
- the field mapping is the ``sentinelone_pq`` pipeline chosen by the connector
  setting, and the ``fields`` of a rule add no ``columns`` command: the
  connector names the columns it reads.
"""

import re
from typing import Any, ClassVar

from sigma.backends.sentinelone_pq import SentinelOnePQBackend
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionNOT
from sigma.conversion.deferred import DeferredQueryExpression
from sigma.conversion.state import ConversionState
from sigma.pipelines.sentinelone_pq import sentinelonepq_pipeline
from sigma.processing.pipeline import ProcessingPipeline
from sigma.rule import SigmaRule
from sigma.types import SigmaString, SpecialChars

PIPELINES = {"sentinelone_pq": sentinelonepq_pipeline}
"""pySigma pipelines of the connector, by name."""


def quote_string(value: str) -> str:
    """Return a PowerQuery string literal (double quotes, backslash escapes)."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def wildcard_regex(value: SigmaString) -> str:
    """Return the anchored regular expression of a Sigma value with wildcards."""
    parts = []
    for part in value.s:
        if part == SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part == SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        elif isinstance(part, str):
            parts.append(re.escape(part))
    return "^" + "".join(parts) + "$"


class PowerQueryBackend(SentinelOnePQBackend):  # type: ignore[misc]
    """SentinelOne PowerQuery backend keeping the Sigma semantics."""

    backend_processing_pipeline: ClassVar[ProcessingPipeline] = ProcessingPipeline()
    startswith_expression: ClassVar[str] = "{field} starts_with {value}"
    endswith_expression: ClassVar[str] = "{field} ends_with {value}"
    case_sensitive_startswith_expression: ClassVar[str] = (
        "{field} starts_with:matchcase({value})"
    )
    case_sensitive_endswith_expression: ClassVar[str] = (
        "{field} ends_with:matchcase({value})"
    )
    or_in_operator: ClassVar[str] = "in:anycase"
    field_null_expression: ClassVar[str] = "!({field} = *)"
    field_not_exists_expression: ClassVar[str] = "!({field} = *)"

    def convert_condition_not(self, cond: ConditionNOT, state: ConversionState) -> Any:
        """Negate a condition, always within parentheses."""
        expr = self.convert_condition(cond.args[0], state)
        if isinstance(expr, DeferredQueryExpression):
            return expr.negate()
        return f"!({expr})"

    def convert_condition_field_eq_val_str(
        self, cond: ConditionFieldEqualsValueExpression, state: ConversionState
    ) -> Any:
        """Compare a field to a string value without case, as Sigma does."""
        value = cond.value
        field = self.escape_and_quote_field(cond.field)
        if not value.contains_special():
            return f"{field} in:anycase ({self.convert_value_str(value, state)})"
        inner = value
        if inner.startswith(SpecialChars.WILDCARD_MULTI):
            inner = inner[1:]
        if inner.endswith(SpecialChars.WILDCARD_MULTI):
            inner = inner[:-1]
        if not inner.contains_special():
            return super().convert_condition_field_eq_val_str(cond, state)
        return f"{field} matches {quote_string(wildcard_regex(value))}"

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        """Return the query without the ``columns`` of the rule ``fields``."""
        return query
