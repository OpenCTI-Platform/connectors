"""Base internal hunt connector module.

This module provides the ``InternalHuntConnector`` class, the foundation of the
connectors of type ``INTERNAL_HUNT``. OpenCTI dispatches one message per hunt
run; the base class turns it into a query, executes it within the run limits,
maps the results to STIX and reports the run outcome.

Architecture::

    InternalHuntConnector
    ├── OpenCTIConnectorHelper → pycti bridge (register_hunt_platform, listen_hunt, report_hunt_run)
    ├── resolve_query()        → native query override, or translate() of the Sigma rule
    │   └── sigma_backend()    → pySigma backend of the platform (abstract)
    ├── ioc_query()            → indicator hunts: the lookup of a batch of values (optional)
    ├── execute()              → query execution on the platform (abstract), time-boxed
    ├── to_stix()              → observables + observed-data (telemetry), overridable
    └── report                 → hits, hit keys, distinct entities, evidence per field and per hit,
                                 result ids, and one result per value for indicator hunts

OpenCTI keeps the sightings of a hunt (one per technique or indicator and
Security Platform, updated in place) and tells new hits from the ones it already
knows with the hit keys of each run (``analysis.hit_key``).
"""

from __future__ import annotations

import inspect
import json
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar

from connectors_sdk.connectors.external_import.logger import ConnectorLogger
from connectors_sdk.connectors.internal_hunt.analysis import (
    DEFAULT_ENTITY_FIELDS,
    DEFAULT_HIT_FIELDS,
    HOST_FIELDS,
    HitFields,
    build_evidence,
    build_hit_evidence,
    build_hit_keys,
    count_distinct_entities,
    event_time_bounds,
    evidence_fields,
    present_fields,
    suppress_benign,
)
from connectors_sdk.connectors.internal_hunt.errors import (
    HuntError,
    HuntExecutionError,
    HuntRequestError,
    HuntTimeoutError,
    HuntTranslationError,
    HuntUnsupportedPyctiError,
    is_retryable,
)
from connectors_sdk.connectors.internal_hunt.indicators import (
    IocBatch,
    IocObservation,
    aggregated_observations,
    batch_iocs,
    build_indicator_objects,
    build_ioc_evidence,
    build_ioc_results,
    match_events,
    value_hit_keys,
    value_hits,
)
from connectors_sdk.connectors.internal_hunt.models import (
    HuntConnectionCheck,
    HuntEvent,
    HuntLimits,
    HuntRequest,
    HuntResult,
    HuntRunMode,
    HuntRunReport,
    HuntRunStatus,
    HuntTimeWindow,
    NativeQuery,
)
from connectors_sdk.connectors.internal_hunt.observables import extract_observables
from connectors_sdk.connectors.internal_hunt.stix_mapping import (
    build_telemetry_objects,
)
from connectors_sdk.connectors.internal_hunt.timing import RunDeadline
from connectors_sdk.connectors.internal_hunt.translation import (
    convert_sigma,
    detection_fields,
    parse_sigma_rule,
)
from connectors_sdk.settings.base_settings import (
    HUNT_INTERNET_PLATFORM,
    BaseConnectorSettings,
    BaseInternalHuntConnectorConfig,
)
from pycti import OpenCTIConnectorHelper
from pydantic import ValidationError

if TYPE_CHECKING:
    from sigma.conversion.base import Backend

REQUIRED_HELPER_METHODS: tuple[str, ...] = (
    "listen_hunt",
    "register_hunt_platform",
    "report_hunt_run",
)
"""pycti helper methods hunt connectors rely on."""

ERROR_MESSAGE_MAX_LENGTH = 2000
"""Maximum length of the error reported for a failed run."""

INDICATOR_HUNT = "indicators"
"""Hunt type of indicator hunts, whose values are looked up instead of a query."""

CONNECTION_CHECK_MODE = "check"
"""Mode of the message of a connection test, which carries no hunt run."""

CONNECTION_CHECK_TIMEOUT_SECONDS = 60
"""Time budget of a connection test."""

CONNECTION_CHECK_WINDOW = timedelta(minutes=15)
"""Time window of the search a default connection test runs."""


def _accepts_keyword(function: Any, keyword: str) -> bool:
    """Whether a callable accepts a keyword argument (a newer pycti helper parameter)."""
    try:
        parameters = inspect.signature(function).parameters
    except (TypeError, ValueError):
        return False
    return keyword in parameters or any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    )


def ensure_pycti_hunt_support() -> None:
    """Fail fast when the installed pycti does not provide the hunt connector API.

    Raises:
        HuntUnsupportedPyctiError: If ``ConnectorType.INTERNAL_HUNT`` or one of
            the hunt helper methods is missing.
    """
    from pycti import __version__ as pycti_version
    from pycti.connector.opencti_connector import ConnectorType

    missing = []
    if "INTERNAL_HUNT" not in ConnectorType.__members__:
        missing.append("ConnectorType.INTERNAL_HUNT")
    missing.extend(
        f"OpenCTIConnectorHelper.{name}"
        for name in REQUIRED_HELPER_METHODS
        if not callable(getattr(OpenCTIConnectorHelper, name, None))
    )
    if missing:
        raise HuntUnsupportedPyctiError(
            f"The installed pycti {pycti_version} does not support hunt connectors "
            f"(missing: {', '.join(missing)}). Install the pycti release matching an "
            "OpenCTI platform that provides hunts (INTERNAL_HUNT connector type)."
        )


def _error_message(error: BaseException) -> str:
    """Format an exception for the run report."""
    text = str(error).strip()
    message = f"{type(error).__name__}: {text}" if text else type(error).__name__
    return message[:ERROR_MESSAGE_MAX_LENGTH]


def _check_message(error: BaseException) -> str:
    """Format an exception for a connection check: the plain-words message first."""
    text = str(error).strip()
    if not text or not isinstance(error, HuntError):
        text = f"{type(error).__name__}: {text}" if text else type(error).__name__
    return text[:2048]


def _mark_reported(error: BaseException) -> None:
    """Flag an error whose run outcome is already reported.

    The ``listen_hunt`` wrapper of pycti, which receives the error raised again
    to mark the work in error, then does not report the run a second time.
    """
    try:
        error.hunt_run_reported = True  # type: ignore[attr-defined]
    except AttributeError:
        # An exception type without instance attributes: the wrapper reports it again and OpenCTI refuses the duplicate
        pass


class InternalHuntConnector(ABC):
    """Base class for internal hunt connectors.

    Subclasses implement the platform specifics:

    - ``languages``: query languages the connector executes (the first one is
      the language produced by ``translate``);
    - ``sigma_backend()``: the pySigma backend (and pipeline) of the platform;
    - ``execute()``: the query execution on the platform API;
    - ``ioc_query()`` (optional): the lookup of a batch of values of one
      observable type, which makes the connector run indicator hunts.

    Everything else is handled here: pycti compatibility check, platform
    registration, message parsing, native query override, preview mode,
    timeout and ``max_results`` enforcement, benign suppression, STIX mapping,
    bundle sending, evidence redaction and run reporting. For indicator hunts:
    the batching of the values by type, the matching of the values in the
    results (or the reading of aggregated rows, see ``ioc_aggregated``), one
    result per value with the keys of its hits, and the observables of the
    seen values (OpenCTI keeps their sightings).

    The ``OpenCTIConnectorHelper`` is created lazily by ``start()`` so that the
    connector can be instantiated and tested without an OpenCTI platform.

    Attributes:
        languages: Query languages the connector can execute.
        sigma_output_format: pySigma backend output format (backend default when None).
        query_join: Operator joining several translated queries (e.g. ``" OR "``),
            or None to reject Sigma documents translating into several queries.
        evidence_excluded_fields: Result fields never sampled as evidence nor
            reported in the evidence of a hit, with their sub-fields.
        entity_fields: Result fields identifying hosts, users and network peers,
            sampled as evidence right after the fields of the detection.
        hit_fields: Result fields naming the event id, host, user and process
            in the evidence of each hit.
        observable_fields: Result field to observable type mapping that takes
            precedence over the field name heuristics.
        ioc_aggregated: True when ``ioc_query`` returns one aggregated row per
            value (``ioc``, ``hits``, ``first_seen``, ``last_seen``, ``hosts``),
            False when it returns raw events the base searches for the values.
        ioc_host_fields: Result fields naming the host of an event.
        required_permissions: Permissions the account of the connector needs on
            its platform, as ``(name, purpose)``: OpenCTI shows them on the
            connector, next to its connection test.
        documentation_url: Setup documentation of the connector (https).
        settings: Connector settings.
        config: Connector-level settings (``BaseInternalHuntConnectorConfig``).

    Example:
        >>> class SplunkHuntConnector(InternalHuntConnector):
        ...     languages = ("spl",)
        ...     def sigma_backend(self, pipeline):
        ...         return SplunkBackend(build_pipeline(pipeline or "splunk_windows", PIPELINES))
        ...     def execute(self, native_query, time_window, limits, deadline=None):
        ...         deadline = deadline or RunDeadline(limits.timeout_seconds)
        ...         return self.client.search(native_query.query, time_window, deadline)
        >>> SplunkHuntConnector(settings=ConnectorSettings()).start()
    """

    languages: ClassVar[tuple[str, ...]] = ()
    sigma_output_format: ClassVar[str | None] = None
    query_join: ClassVar[str | None] = None
    evidence_excluded_fields: ClassVar[frozenset[str]] = frozenset()
    entity_fields: ClassVar[tuple[str, ...]] = DEFAULT_ENTITY_FIELDS
    hit_fields: ClassVar[HitFields] = DEFAULT_HIT_FIELDS
    observable_fields: ClassVar[Mapping[str, str]] = MappingProxyType({})
    ioc_aggregated: ClassVar[bool] = False
    ioc_host_fields: ClassVar[tuple[str, ...]] = HOST_FIELDS
    required_permissions: ClassVar[tuple[tuple[str, str], ...]] = ()
    documentation_url: ClassVar[str | None] = None

    def __init__(self, settings: BaseConnectorSettings) -> None:
        """Initialize the hunt connector.

        Args:
            settings: Connector settings whose ``connector`` namespace is a
                ``BaseInternalHuntConnectorConfig``.

        Raises:
            TypeError: If the connector settings are not hunt connector settings.
            ValueError: If the connector declares no query language.
        """
        if not isinstance(settings.connector, BaseInternalHuntConnectorConfig):
            raise TypeError(
                "settings.connector must be a BaseInternalHuntConnectorConfig."
            )
        if not self.languages:
            raise ValueError("A hunt connector must declare at least one language.")
        self.settings = settings
        self.config: BaseInternalHuntConnectorConfig = settings.connector
        self._helper: Any = None
        self._logger: ConnectorLogger | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @property
    def platform(self) -> str:
        """Return the hunt platform slug of the connector."""
        return self.config.platform

    @property
    def helper(self) -> Any:
        """Return the pycti connector helper.

        Raises:
            RuntimeError: If the connector has not been started.
        """
        if self._helper is None:
            raise RuntimeError("The connector helper is created by start().")
        return self._helper

    @property
    def logger(self) -> ConnectorLogger:
        """Return the connector logger.

        Raises:
            RuntimeError: If the connector has not been started.
        """
        if self._logger is None:
            raise RuntimeError("The connector logger is created by start().")
        return self._logger

    def _init_dependencies(self) -> None:
        """Check pycti, create the helper and the logger, then call ``post_init``."""
        ensure_pycti_hunt_support()
        self._helper = OpenCTIConnectorHelper(config=self.settings.to_helper_config())
        self._logger = ConnectorLogger(self._helper)
        self.post_init()

    def post_init(self) -> None:  # noqa: B027 # optional hook
        """Hook called once the helper and the logger exist.

        Override it to create the platform API client. By default, does nothing.
        """

    def register_platform(self) -> dict[str, Any]:
        """Register the hunt platform of the connector in OpenCTI.

        Returns:
            The hunt connector registration returned by OpenCTI.
        """
        is_internet = self.platform == HUNT_INTERNET_PLATFORM
        capabilities: dict[str, Any] = {}
        # A pycti without indicator hunts registers the connector without them
        if _accepts_keyword(self.helper.register_hunt_platform, "supports_indicators"):
            capabilities["supports_indicators"] = self.supports_indicators
        if self.required_permissions and _accepts_keyword(
            self.helper.register_hunt_platform, "required_permissions"
        ):
            capabilities["required_permissions"] = [
                {"name": name, "purpose": purpose}
                for name, purpose in self.required_permissions
            ]
        if self.documentation_url and _accepts_keyword(
            self.helper.register_hunt_platform, "documentation_url"
        ):
            capabilities["documentation_url"] = self.documentation_url
        registration = self.helper.register_hunt_platform(
            platform=self.platform,
            languages=list(self.languages),
            security_platform_name=(
                None if is_internet else self.config.security_platform_name
            ),
            security_platform_type=self.config.security_platform_type,
            supports_preview=True,
            max_concurrent_runs=self.config.max_concurrent_runs,
            **capabilities,
        )
        self.logger.info(
            "[HUNT] Hunt platform registered",
            {
                "platform": self.platform,
                "languages": list(self.languages),
                "security_platform": self.config.security_platform_name,
                "supports_indicators": capabilities.get("supports_indicators", False),
            },
        )
        return dict(registration or {})

    def start(self) -> None:
        """Start the connector: register the hunt platform and listen to hunt runs."""
        self._init_dependencies()
        self.register_platform()
        self.helper.listen_hunt(message_callback=self.process_message)

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    @abstractmethod
    def sigma_backend(self, pipeline: str | None) -> Backend:
        """Create the pySigma backend translating Sigma rules for the platform.

        Args:
            pipeline: Name of the processing pipeline requested by the hunt, or
                ``None`` for the connector default.

        Returns:
            A pySigma backend instance configured with its processing pipeline.
        """

    @abstractmethod
    def execute(
        self,
        native_query: NativeQuery,
        time_window: HuntTimeWindow,
        limits: HuntLimits,
        deadline: RunDeadline | None = None,
    ) -> HuntResult:
        """Execute a query on the platform.

        Implementations must bound their API calls, polling and retries with
        ``deadline`` and fetch at most ``limits.max_results`` events. The base
        class also enforces both limits.

        Args:
            native_query: Query to execute.
            time_window: Time window to restrict the query to.
            limits: Run limits.
            deadline: Deadline of the run, the one the base class waits for, so
                that no call outlives the run. ``None`` only for direct calls,
                which start one from ``limits.timeout_seconds``.

        Returns:
            The query results.
        """

    def ioc_query(self, batch: IocBatch) -> NativeQuery | None:
        """Build the platform lookup of a batch of values of one observable type.

        Override it to run indicator hunts: the connector then registers as
        supporting indicator lookups, and ``execute`` runs the returned query
        within the run window. Return raw events (the base finds the values in
        them) or, with ``ioc_aggregated``, one row per value key.

        Args:
            batch: Values of one observable type (and hash algorithm), at most
                ``limits.ioc_batch_size``.

        Returns:
            The lookup, or ``None`` when the platform cannot look this type up
            (its values are reported not searched).
        """
        return None

    @property
    def supports_indicators(self) -> bool:
        """Return whether the connector looks up the values of indicator hunts."""
        return type(self).ioc_query is not InternalHuntConnector.ioc_query

    # ------------------------------------------------------------------
    # Connection test
    # ------------------------------------------------------------------

    def connection_test_query(self) -> NativeQuery | None:
        """Build the cheapest search proving the account can query the platform.

        The default connection test runs it over the last 15 minutes, with at
        most one result.

        Returns:
            The search, or ``None`` when the connector has none: the test then
            reports that it cannot check the search.
        """
        return None

    def connection_checks(self, deadline: RunDeadline) -> list[HuntConnectionCheck]:
        """Test the connection of the connector and the permissions it needs.

        Override it to check the permissions one by one (for instance by
        reading the capabilities of the account), each through ``run_check``.
        By default, runs ``connection_test_query``.

        Args:
            deadline: Deadline of the connection test, bounding every call.

        Returns:
            One check per permission or step, in the order they are tested.
        """
        query = self.connection_test_query()
        if query is None:
            return [
                HuntConnectionCheck(
                    name="Search",
                    ok=False,
                    message="This connector cannot test its search: run a hunt with Run now to check it.",
                )
            ]
        end = datetime.now(UTC)
        window = HuntTimeWindow(start=end - CONNECTION_CHECK_WINDOW, end=end)
        limits = HuntLimits(
            max_results=1, timeout_seconds=CONNECTION_CHECK_TIMEOUT_SECONDS
        )
        outcome: dict[str, HuntResult] = {}

        def _search() -> None:
            outcome["result"] = self.execute(query, window, limits, deadline)

        check = self.run_check(
            "Search", _search, "The account can run searches on the platform."
        )
        result = outcome.get("result")
        if check.ok and isinstance(result, HuntResult) and not result.events:
            # Allowed, yet blind: the account may not read the hunted data
            check = HuntConnectionCheck(
                name="Search",
                ok=True,
                message="The account can run searches, which found no event in the last 15 minutes: check that it can read the hunted data.",
            )
        return [check]

    def run_check(
        self, name: str, call: Callable[[], Any], success: str
    ) -> HuntConnectionCheck:
        """Run one check of the connection test.

        Args:
            name: What is checked (``"Authentication"``, a permission name...).
            call: The platform call proving it; it raises when refused.
            success: What a passing check means, in plain words.

        Returns:
            The check: passed, or failed with the plain-words reason (a refused
            call names what the account lacks, see ``HuntAccessDeniedError``).
        """
        try:
            call()
        except HuntTimeoutError:
            return HuntConnectionCheck(
                name=name,
                ok=False,
                message="The platform did not answer in time: check its URL and the network path from the connector.",
            )
        except Exception as err:
            return HuntConnectionCheck(name=name, ok=False, message=_check_message(err))
        return HuntConnectionCheck(name=name, ok=True, message=success)

    def _complete_connection_check(self, event: Mapping[str, Any]) -> str:
        """Run the connection test OpenCTI asked for and report its checks."""
        check_id = str((event.get("connection_check") or {}).get("id") or "").strip()
        if not check_id:
            raise HuntRequestError(
                "The connection test message has no connection_check.id."
            )
        report = getattr(self.helper, "report_hunt_connection_check", None)
        if not callable(report):
            raise HuntUnsupportedPyctiError(
                "The installed pycti cannot report connection tests: install the "
                "pycti release matching the OpenCTI platform."
            )
        checks = self.connection_checks(RunDeadline(CONNECTION_CHECK_TIMEOUT_SECONDS))
        if not checks:
            checks = [
                HuntConnectionCheck(
                    name="Connection", ok=False, message="The connector ran no check."
                )
            ]
        report(check_id, [check.model_dump() for check in checks])
        failed = [check for check in checks if not check.ok]
        self.logger.info(
            "[HUNT] Connection tested",
            {"platform": self.platform, "failed": [check.name for check in failed]},
        )
        if failed:
            return f"Connection test failed: {failed[0].message}"
        return "Connection test passed"

    def on_timeout(self, native_query: NativeQuery) -> None:  # noqa: B027
        """Hook called when ``execute`` exceeds the run timeout.

        Override it to cancel the job running on the platform. By default, does nothing.
        It runs in a background thread while the timeout is reported, so a platform
        slow to cancel never delays the report; an error it raises is logged.

        Args:
            native_query: Query that timed out.
        """

    def combine_queries(self, queries: Sequence[str]) -> str:
        """Combine the queries a Sigma document translates into.

        Args:
            queries: Queries produced by the pySigma backend.

        Returns:
            A single query.

        Raises:
            HuntTranslationError: If there is no query, or several queries and
                no ``query_join`` operator.
        """
        if not queries:
            raise HuntTranslationError("The Sigma rule translated into no query.")
        if len(queries) == 1:
            return queries[0]
        if self.query_join is None:
            raise HuntTranslationError(
                f"The Sigma rule translated into {len(queries)} queries; "
                f"the '{self.platform}' platform executes a single query per hunt."
            )
        return self.query_join.join(f"({query})" for query in queries)

    def translate(self, sigma_rule: str, pipeline: str | None) -> NativeQuery:
        """Translate the Sigma rule of a hunt into a native query.

        Args:
            sigma_rule: Sigma rule (YAML).
            pipeline: pySigma pipeline requested by the hunt, or ``None``.

        Returns:
            The translated query, with the platform field names of the detection.
        """
        collection = parse_sigma_rule(sigma_rule)
        backend = self.sigma_backend(pipeline)
        queries = convert_sigma(backend, collection, self.sigma_output_format)
        return NativeQuery(
            language=self.languages[0],
            query=self.combine_queries(queries),
            pipeline=pipeline,
            translated=True,
            fields=detection_fields(collection),
        )

    def to_stix(self, request: HuntRequest, result: HuntResult) -> list[Any]:
        """Map the results of a run to STIX objects.

        The default mapping produces the observables and the observed-data of a
        telemetry hunt; OpenCTI keeps the sightings of the hunt itself. Override
        it for other kinds of hunts.

        Args:
            request: The hunt run request.
            result: The results, after benign suppression.

        Returns:
            connectors-sdk models, stix2 objects or STIX dictionaries.
        """
        first_seen, last_seen = event_time_bounds(result.events, request.time_window)
        allowed_types = [
            observable_type
            for observable_type in request.hunt.expected_observables
            if observable_type in self.config.observable_types
        ]
        observables = extract_observables(
            result.events,
            allowed_types,
            self.observable_fields,
            self.config.max_observables,
        )
        return list(
            build_telemetry_objects(
                request, result.hits_count, first_seen, last_seen, observables
            )
        )

    # ------------------------------------------------------------------
    # Run processing
    # ------------------------------------------------------------------

    def parse_request(self, event: Mapping[str, Any]) -> HuntRequest:
        """Validate the hunt run message sent by OpenCTI.

        Args:
            event: The ``event`` part of the queue message.

        Returns:
            The parsed hunt run request.

        Raises:
            HuntRequestError: If the message is not a valid hunt run.
        """
        try:
            return HuntRequest.model_validate(event)
        except ValidationError as err:
            raise HuntRequestError(f"Invalid hunt run message: {err}") from err

    def resolve_query(self, request: HuntRequest) -> NativeQuery:
        """Return the query to execute for a hunt run.

        The native query override of the platform is executed verbatim. An
        override with an empty query only selects the pySigma pipeline used to
        translate the Sigma rule.

        Args:
            request: The hunt run request.

        Returns:
            The query to execute.

        Raises:
            HuntTranslationError: If the override language is not supported or
                the hunt has no logic for the platform.
        """
        native = request.hunt.native_query
        pipeline = None
        if native is not None and native.platform == self.platform:
            if native.query.strip():
                if native.language not in self.languages:
                    raise HuntTranslationError(
                        f"The '{native.language}' language is not supported by this "
                        f"connector (supported: {', '.join(self.languages)})."
                    )
                return NativeQuery(
                    language=native.language,
                    query=native.query.strip(),
                    pipeline=native.pipeline,
                )
            pipeline = native.pipeline
        if request.hunt.sigma_rule and request.hunt.sigma_rule.strip():
            return self.translate(request.hunt.sigma_rule, pipeline)
        raise HuntTranslationError(
            f"The hunt has no Sigma rule and no native query for the '{self.platform}' platform."
        )

    def process_message(self, event: dict[str, Any]) -> str:
        """Process a hunt run dispatched by OpenCTI.

        The run is reported as completed (with hits, distinct entities, evidence
        and result ids) or as failed (with the error), then the error is raised
        again so that OpenCTI marks the work in error.

        Args:
            event: The ``event`` part of the queue message.

        Returns:
            The work completion message.
        """
        if event.get("mode") == CONNECTION_CHECK_MODE:
            return self._complete_connection_check(event)
        started = time.monotonic()
        try:
            request = self.parse_request(event)
        except HuntRequestError as err:
            run_id = self._raw_run_id(event)
            self.logger.error(
                "[HUNT] Invalid hunt run message", {"hunt_run_id": run_id}
            )
            if run_id:
                self._report_failure(run_id, None, started, err)
            raise

        run_id = request.hunt_run.id
        self.logger.info(
            "[HUNT] Hunt run received",
            {
                "hunt_run_id": run_id,
                "hunt_id": request.hunt.id,
                "mode": request.mode.value,
                "attempt": request.hunt_run.attempt,
            },
        )
        native_query: NativeQuery | None = None
        try:
            if request.hunt.hunt_type == INDICATOR_HUNT:
                return self._complete_indicator_run(request, started)
            native_query = self.resolve_query(request)
            if request.mode is HuntRunMode.PREVIEW:
                return self._complete_preview(request, native_query, started)
            return self._complete_execution(request, native_query, started)
        except Exception as err:
            if getattr(err, "hunt_run_reported", False) is True:
                raise
            self.logger.error(
                "[HUNT] Hunt run failed",
                {"hunt_run_id": run_id, "error": _error_message(err)},
            )
            self._report_failure(run_id, native_query, started, err)
            raise

    def _complete_preview(
        self, request: HuntRequest, native_query: NativeQuery, started: float
    ) -> str:
        """Report the translated query of a preview run (nothing is executed)."""
        self.report(
            request.hunt_run.id,
            HuntRunReport(
                status=HuntRunStatus.COMPLETED,
                translated_query=native_query.query,
                query_language=native_query.language,
                cost_ms=self._elapsed_ms(started),
            ),
        )
        return f"Hunt run {request.hunt_run.id} preview completed ({native_query.language})."

    def _complete_execution(
        self, request: HuntRequest, native_query: NativeQuery, started: float
    ) -> str:
        """Execute the query, send its knowledge, then report the completed run.

        The bundle is sent before the run is reported completed: a bundle that
        cannot be sent fails the run, which OpenCTI retries, and a run reported
        completed always has its knowledge sent. The identifiers of the
        knowledge derive from the hunt run, so a retry upserts the same objects.
        """
        deadline = RunDeadline(request.limits.timeout_seconds)
        raw_result = self._execute_within_limits(request, native_query, deadline)
        result = suppress_benign(raw_result, request.hunt.benign_patterns, deadline)
        objects = self._bundle_objects(self.to_stix(request, result))
        result_ids = list(objects)
        hits_count = result.hits_count
        hits = [
            (
                event,
                evidence_fields(
                    present_fields(event, native_query.fields),
                    self.evidence_excluded_fields,
                ),
            )
            for event in result.events
        ]
        self._send_objects(objects)
        self.report(
            request.hunt_run.id,
            HuntRunReport(
                status=HuntRunStatus.COMPLETED,
                translated_query=native_query.query,
                query_language=native_query.language,
                hits_count=hits_count,
                truncated=result.truncated,
                distinct_entities=count_distinct_entities(
                    result.events, self.entity_fields
                ),
                evidence_sample=build_evidence(
                    result.events,
                    request.limits,
                    (*native_query.fields, *self.entity_fields),
                    self.evidence_excluded_fields,
                ),
                hits_sample=build_hit_evidence(hits, request.limits, self.hit_fields),
                hit_keys=build_hit_keys(hits, request.limits, self.hit_fields),
                result_ids=result_ids,
                cost_ms=self._elapsed_ms(started),
            ),
        )
        self.logger.info(
            "[HUNT] Hunt run completed",
            {
                "hunt_run_id": request.hunt_run.id,
                "hits_count": hits_count,
                "suppressed": len(raw_result.events) - len(result.events),
                "objects_sent": len(result_ids),
            },
        )
        return (
            f"Hunt run {request.hunt_run.id} completed: {hits_count} hit(s), "
            f"{len(result_ids)} object(s) sent."
        )

    def plan_ioc_lookups(
        self, request: HuntRequest
    ) -> list[tuple[IocBatch, NativeQuery | None]]:
        """Return the lookups of an indicator hunt run: its values batched by type, each with its query.

        Args:
            request: The hunt run request.

        Returns:
            Each batch with its lookup, ``None`` for a type the platform cannot look up.
        """
        return [
            (batch, self.ioc_query(batch))
            for batch in batch_iocs(request.hunt.iocs, request.limits.ioc_batch_size)
        ]

    def _complete_indicator_run(self, request: HuntRequest, started: float) -> str:
        """Look up the values of an indicator hunt, send the observables seen, then report one result per value.

        A preview reports the lookups without running them. A type the platform
        cannot look up is reported not searched, so that OpenCTI never concludes
        benign about it. The lookups share the ``max_results`` of the run: each
        one fetches at most what the previous ones left, and the values of a
        lookup the run can no longer afford are reported not searched. As for
        telemetry runs, the knowledge is sent before the completed report.
        """
        if not self.supports_indicators:
            raise HuntTranslationError(
                f"The '{self.platform}' hunt connector does not look up indicator values."
            )
        lookups = self.plan_ioc_lookups(request)
        queries = [query for _, query in lookups if query is not None]
        language = queries[0].language if queries else self.languages[0]
        translated = "\n\n".join(query.query for query in queries) or None
        if request.mode is HuntRunMode.PREVIEW:
            self.report(
                request.hunt_run.id,
                HuntRunReport(
                    status=HuntRunStatus.COMPLETED,
                    translated_query=translated,
                    query_language=language,
                    cost_ms=self._elapsed_ms(started),
                ),
            )
            return f"Hunt run {request.hunt_run.id} preview completed ({len(queries)} lookup(s))."
        self._require_ioc_results_report()
        deadline = RunDeadline(request.limits.timeout_seconds)
        observations: dict[str, IocObservation] = {}
        unsearched: dict[str, str] = {}
        hits: list[tuple[HuntEvent, list[str]]] = []
        # Aggregated lookups return one count per value, never the events: their hits cannot be told apart
        value_keys: dict[str, dict[str, None]] | None = (
            None if self.ioc_aggregated else {}
        )
        truncated = False
        remaining = request.limits.max_results
        for batch, query in lookups:
            if query is None:
                reason = f"The {self.platform} hunt connector does not look up {batch.observable_type} values."
                unsearched.update({ioc.key: reason for ioc in batch.iocs})
                continue
            if remaining <= 0:
                reason = (
                    f"The {self.platform} lookups of this run read the maximum number of results "
                    "before this value: run the hunt again with fewer values or a higher maximum."
                )
                unsearched.update({ioc.key: reason for ioc in batch.iocs})
                truncated = True
                continue
            raw_result = self._execute_within_limits(
                request, query, deadline, max_results=remaining
            )
            remaining -= len(raw_result.events)
            result = suppress_benign(raw_result, request.hunt.benign_patterns, deadline)
            truncated = truncated or result.truncated
            if value_keys is None:
                found = aggregated_observations(batch, result.events)
            else:
                found = match_events(batch, result.events, self.ioc_host_fields)
                batch_hits = [
                    (event, evidence_fields(fields, self.evidence_excluded_fields))
                    for event, fields in value_hits(batch, result.events)
                ]
                hits.extend(batch_hits)
                batch_keys = value_hit_keys(
                    batch, batch_hits, request.limits, self.hit_fields
                )
                for key, keys in batch_keys.items():
                    value_keys.setdefault(key, {}).update(dict.fromkeys(keys))
            for key, observation in found.items():
                observations.setdefault(key, IocObservation()).merge(observation)
            if result.truncated:
                # The rows or events left unread may hold any value of the batch
                # that is absent from the part read: none of them is a verified negative
                reason = (
                    f"The {self.platform} lookup of the {batch.observable_type} values "
                    "returned partial results and this value was not in the part read: "
                    "run the hunt again with fewer values or a shorter time window."
                )
                unsearched.update(
                    {ioc.key: reason for ioc in batch.iocs if ioc.key not in found}
                )
        ioc_results = build_ioc_results(
            request.hunt.iocs,
            observations,
            unsearched,
            (
                None
                if value_keys is None
                else {key: list(keys) for key, keys in value_keys.items()}
            ),
        )
        objects = self._bundle_objects(build_indicator_objects(request, ioc_results))
        hits_count = sum(result.hits_count for result in ioc_results)
        self._send_objects(objects)
        self.report(
            request.hunt_run.id,
            HuntRunReport(
                status=HuntRunStatus.COMPLETED,
                translated_query=translated,
                query_language=language,
                hits_count=hits_count,
                truncated=truncated,
                distinct_entities=len(
                    {host for result in ioc_results for host in result.hosts}
                ),
                evidence_sample=build_ioc_evidence(
                    request.hunt.iocs, ioc_results, request.limits
                ),
                hits_sample=build_hit_evidence(hits, request.limits, self.hit_fields),
                hit_keys=(
                    None
                    if value_keys is None
                    else build_hit_keys(hits, request.limits, self.hit_fields)
                ),
                result_ids=list(objects),
                cost_ms=self._elapsed_ms(started),
                ioc_results=ioc_results,
            ),
        )
        seen = sum(1 for result in ioc_results if result.seen)
        self.logger.info(
            "[HUNT] Indicator hunt run completed",
            {
                "hunt_run_id": request.hunt_run.id,
                "values": len(ioc_results),
                "seen": seen,
                "not_searched": len(unsearched),
                "objects_sent": len(objects),
            },
        )
        return (
            f"Hunt run {request.hunt_run.id} completed: {seen} of {len(ioc_results)} "
            f"value(s) seen, {len(objects)} object(s) sent."
        )

    def _execute_within_limits(
        self,
        request: HuntRequest,
        native_query: NativeQuery,
        deadline: RunDeadline,
        max_results: int | None = None,
    ) -> HuntResult:
        """Run ``execute`` within the run deadline and cap the results to ``max_results``.

        Args:
            request: The hunt run request.
            native_query: The query to run.
            deadline: The deadline of the run.
            max_results: The events this query may fetch, ``limits.max_results``
                when omitted (an indicator run passes what its lookups left).

        Raises:
            HuntTimeoutError: If the execution exceeds ``limits.timeout_seconds``.
            HuntExecutionError: If ``execute`` does not return a ``HuntResult``.
        """
        outcome: dict[str, Any] = {}
        limit = request.limits.max_results if max_results is None else max_results
        limits = (
            request.limits
            if limit == request.limits.max_results
            else request.limits.model_copy(update={"max_results": limit})
        )

        def _run() -> None:
            try:
                outcome["result"] = self.execute(
                    native_query, request.time_window, limits, deadline
                )
            except BaseException as err:
                outcome["error"] = err
            # Judged when the query finished, not when the caller looks: a query
            # ending between the end of the wait and the check is still late
            outcome["late"] = deadline.expired()

        worker = threading.Thread(
            target=_run, name=f"hunt-run-{request.hunt_run.id}", daemon=True
        )
        worker.start()
        worker.join(deadline.remaining())
        alive = worker.is_alive()
        if alive or outcome.get("late"):
            if alive:
                self._cancel_in_background(request, native_query)
            raise HuntTimeoutError(
                f"The hunt query did not complete within {request.limits.timeout_seconds} seconds."
            )
        if "error" in outcome:
            raise outcome["error"]
        result = outcome.get("result")
        if not isinstance(result, HuntResult):
            raise HuntExecutionError("execute() must return a HuntResult.")
        if len(result.events) > limit:
            return HuntResult(
                events=result.events[:limit],
                total_hits=result.hits_count,
                truncated=True,
            )
        return result

    def _cancel_in_background(
        self, request: HuntRequest, native_query: NativeQuery
    ) -> None:
        """Ask the platform to cancel a timed out query without holding the run report.

        The run deadline has passed: a platform slow to answer the cancellation
        must not delay the timeout report beyond ``limits.timeout_seconds``.
        """

        def _cancel() -> None:
            try:
                self.on_timeout(native_query)
            except Exception as err:
                self.logger.warning(
                    "[HUNT] Unable to cancel the timed out query",
                    {"error": _error_message(err)},
                )

        threading.Thread(
            target=_cancel, name=f"hunt-cancel-{request.hunt_run.id}", daemon=True
        ).start()

    def send_bundle(self, stix_objects: Sequence[Any]) -> list[str]:
        """Send the knowledge of a run to OpenCTI within the run work.

        Args:
            stix_objects: connectors-sdk models, stix2 objects or STIX dictionaries.

        Returns:
            The STIX ids of the objects sent.
        """
        objects = self._bundle_objects(stix_objects)
        self._send_objects(objects)
        return list(objects)

    def _bundle_objects(self, stix_objects: Sequence[Any]) -> dict[str, dict[str, Any]]:
        """The STIX dictionaries of a run's knowledge, by id (duplicates merged)."""
        objects: dict[str, dict[str, Any]] = {}
        for stix_object in stix_objects:
            stix_dict = self._to_stix_dict(stix_object)
            objects[stix_dict["id"]] = stix_dict
        return objects

    def _send_objects(self, objects: dict[str, dict[str, Any]]) -> None:
        """Send STIX dictionaries to OpenCTI within the run work."""
        if not objects:
            return
        bundle = self.helper.stix2_create_bundle(list(objects.values()))
        # The bundle references entities that already exist in OpenCTI (markings,
        # author, the threats an outside-in hunt relates its infrastructure to):
        # cleaning up "inconsistent" references would strip them from the objects sent.
        self.helper.send_stix2_bundle(
            bundle,
            work_id=self.helper.work_id,
            cleanup_inconsistent_bundle=False,
        )

    def report(self, run_id: str, report: HuntRunReport) -> None:
        """Report the outcome of a hunt run to OpenCTI.

        Args:
            run_id: OpenCTI id of the hunt run.
            report: Outcome of the run.
        """
        extra: dict[str, Any] = {}
        # A pycti that knows hit keys reports to an OpenCTI that keeps the known hits of a hunt;
        # an older one keeps the previous report, every hit then counting as new
        hit_keys_supported = _accepts_keyword(self.helper.report_hunt_run, "hit_keys")
        if report.hit_keys is not None and hit_keys_supported:
            extra["hit_keys"] = report.hit_keys
        if report.ioc_results is not None:
            self._require_ioc_results_report()
            extra["ioc_results"] = [
                result.model_dump(
                    mode="json", exclude=None if hit_keys_supported else {"hit_keys"}
                )
                for result in report.ioc_results
            ]
        # A pycti that cannot tell a terminal failure keeps the class prefix of the error
        if report.retryable is not None and _accepts_keyword(
            self.helper.report_hunt_run, "retryable"
        ):
            extra["retryable"] = report.retryable
        # A pycti without single hits keeps the evidence aggregated per field
        if report.hits_sample is not None and _accepts_keyword(
            self.helper.report_hunt_run, "hits_sample"
        ):
            extra["hits_sample"] = [
                hit.model_dump(mode="json") for hit in report.hits_sample
            ]
        self.helper.report_hunt_run(
            run_id,
            report.status.value,
            hits_count=report.hits_count,
            distinct_entities=report.distinct_entities,
            evidence_sample=(
                [evidence.model_dump() for evidence in report.evidence_sample]
                if report.evidence_sample is not None
                else None
            ),
            translated_query=report.translated_query,
            query_language=report.query_language,
            cost_ms=report.cost_ms,
            result_ids=report.result_ids,
            error=report.error,
            truncated=report.truncated,
            **extra,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _require_ioc_results_report(self) -> None:
        """Fail when pycti cannot report the result of each value of an indicator hunt.

        Raises:
            HuntUnsupportedPyctiError: If ``report_hunt_run`` takes no ``ioc_results``.
        """
        if not _accepts_keyword(self.helper.report_hunt_run, "ioc_results"):
            raise HuntUnsupportedPyctiError(
                "The installed pycti cannot report the results of indicator hunts: "
                "install the pycti release matching the OpenCTI platform."
            )

    def _report_failure(
        self,
        run_id: str,
        native_query: NativeQuery | None,
        started: float,
        error: BaseException,
    ) -> None:
        """Report a failed or timed out run without masking the original error.

        Once reported, the error carries ``hunt_run_reported = True`` so that
        the ``listen_hunt`` wrapper of pycti, which receives it re-raised to
        mark the work in error, does not report the run a second time.
        """
        status = (
            HuntRunStatus.TIMEOUT
            if isinstance(error, HuntTimeoutError)
            else HuntRunStatus.FAILED
        )
        try:
            self.report(
                run_id,
                HuntRunReport(
                    status=status,
                    translated_query=native_query.query if native_query else None,
                    query_language=native_query.language if native_query else None,
                    cost_ms=self._elapsed_ms(started),
                    error=_error_message(error),
                    retryable=is_retryable(error),
                ),
            )
        except Exception as report_error:
            self.logger.error(
                "[HUNT] Unable to report the failed hunt run",
                {"hunt_run_id": run_id, "error": _error_message(report_error)},
            )
            return
        _mark_reported(error)

    @staticmethod
    def _raw_run_id(event: Mapping[str, Any]) -> str | None:
        """Extract the hunt run id of an invalid message, if present."""
        hunt_run = event.get("hunt_run") if isinstance(event, Mapping) else None
        run_id = hunt_run.get("id") if isinstance(hunt_run, Mapping) else None
        return run_id if isinstance(run_id, str) and run_id else None

    @staticmethod
    def _elapsed_ms(started: float) -> int:
        """Return the milliseconds elapsed since ``started`` (monotonic clock)."""
        return int((time.monotonic() - started) * 1000)

    @staticmethod
    def _to_stix_dict(stix_object: Any) -> dict[str, Any]:
        """Convert a connectors-sdk model or a stix2 object to a STIX dictionary."""
        if hasattr(stix_object, "to_stix2_object"):
            stix_object = stix_object.to_stix2_object()
        if hasattr(stix_object, "serialize"):
            stix_dict: dict[str, Any] = json.loads(stix_object.serialize())
            return stix_dict
        if isinstance(stix_object, Mapping) and "id" in stix_object:
            return dict(stix_object)
        raise TypeError(f"Unsupported STIX object: {type(stix_object).__name__}")
