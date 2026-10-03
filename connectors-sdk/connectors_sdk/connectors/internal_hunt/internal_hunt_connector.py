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
    ├── execute()              → query execution on the platform (abstract), time-boxed
    ├── to_stix()              → sightings + observed-data (telemetry), overridable
    └── report                 → hits, distinct entities, hashed evidence, result ids
"""

from __future__ import annotations

import json
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, ClassVar

from connectors_sdk.connectors.external_import.logger import ConnectorLogger
from connectors_sdk.connectors.internal_hunt.analysis import (
    DEFAULT_ENTITY_FIELDS,
    build_evidence,
    count_distinct_entities,
    event_time_bounds,
    suppress_benign,
)
from connectors_sdk.connectors.internal_hunt.errors import (
    HuntExecutionError,
    HuntRequestError,
    HuntTimeoutError,
    HuntTranslationError,
    HuntUnsupportedPyctiError,
)
from connectors_sdk.connectors.internal_hunt.models import (
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


class InternalHuntConnector(ABC):
    """Base class for internal hunt connectors.

    Subclasses implement the platform specifics:

    - ``languages``: query languages the connector executes (the first one is
      the language produced by ``translate``);
    - ``sigma_backend()``: the pySigma backend (and pipeline) of the platform;
    - ``execute()``: the query execution on the platform API.

    Everything else is handled here: pycti compatibility check, platform
    registration, message parsing, native query override, preview mode,
    timeout and ``max_results`` enforcement, benign suppression, STIX mapping,
    bundle sending, evidence redaction and run reporting.

    The ``OpenCTIConnectorHelper`` is created lazily by ``start()`` so that the
    connector can be instantiated and tested without an OpenCTI platform.

    Attributes:
        languages: Query languages the connector can execute.
        sigma_output_format: pySigma backend output format (backend default when None).
        query_join: Operator joining several translated queries (e.g. ``" OR "``),
            or None to reject Sigma documents translating into several queries.
        evidence_excluded_fields: Result fields never sampled as evidence.
        entity_fields: Result fields identifying hosts, users and network peers.
        observable_fields: Result field to observable type mapping that takes
            precedence over the field name heuristics.
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
    observable_fields: ClassVar[Mapping[str, str]] = MappingProxyType({})

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
        registration = self.helper.register_hunt_platform(
            platform=self.platform,
            languages=list(self.languages),
            security_platform_name=(
                None if is_internet else self.config.security_platform_name
            ),
            security_platform_type=self.config.security_platform_type,
            supports_preview=True,
            max_concurrent_runs=self.config.max_concurrent_runs,
        )
        self.logger.info(
            "[HUNT] Hunt platform registered",
            {
                "platform": self.platform,
                "languages": list(self.languages),
                "security_platform": self.config.security_platform_name,
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

    def on_timeout(self, native_query: NativeQuery) -> None:  # noqa: B027
        """Hook called when ``execute`` exceeds the run timeout.

        Override it to cancel the job running on the platform. By default, does nothing.

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

        The default mapping produces the sightings and the observed-data of a
        telemetry hunt. Override it for other kinds of hunts.

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
        if request.security_platform is None and result.hits_count > 0:
            self.logger.warning(
                "[HUNT] No Security Platform in the hunt run, sightings are skipped",
                {"hunt_run_id": request.hunt_run.id},
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
            native_query = self.resolve_query(request)
            if request.mode is HuntRunMode.PREVIEW:
                return self._complete_preview(request, native_query, started)
            return self._complete_execution(request, native_query, started)
        except Exception as err:
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
        """Execute the query, send the knowledge and report the completed run."""
        deadline = RunDeadline(request.limits.timeout_seconds)
        raw_result = self._execute_within_limits(request, native_query, deadline)
        result = suppress_benign(raw_result, request.hunt.benign_patterns, deadline)
        result_ids = self.send_bundle(self.to_stix(request, result))
        hits_count = result.hits_count
        self.report(
            request.hunt_run.id,
            HuntRunReport(
                status=HuntRunStatus.COMPLETED,
                translated_query=native_query.query,
                query_language=native_query.language,
                hits_count=hits_count,
                distinct_entities=count_distinct_entities(
                    result.events, self.entity_fields
                ),
                evidence_sample=build_evidence(
                    result.events,
                    request.limits,
                    native_query.fields,
                    self.evidence_excluded_fields,
                ),
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

    def _execute_within_limits(
        self, request: HuntRequest, native_query: NativeQuery, deadline: RunDeadline
    ) -> HuntResult:
        """Run ``execute`` within the run deadline and cap the results to ``max_results``.

        Raises:
            HuntTimeoutError: If the execution exceeds ``limits.timeout_seconds``.
            HuntExecutionError: If ``execute`` does not return a ``HuntResult``.
        """
        outcome: dict[str, Any] = {}

        def _run() -> None:
            try:
                outcome["result"] = self.execute(
                    native_query, request.time_window, request.limits, deadline
                )
            except BaseException as err:
                outcome["error"] = err

        worker = threading.Thread(
            target=_run, name=f"hunt-run-{request.hunt_run.id}", daemon=True
        )
        worker.start()
        worker.join(deadline.remaining())
        if worker.is_alive():
            try:
                self.on_timeout(native_query)
            except Exception as err:
                self.logger.warning(
                    "[HUNT] Unable to cancel the timed out query",
                    {"error": _error_message(err)},
                )
            raise HuntTimeoutError(
                f"The hunt query did not complete within {request.limits.timeout_seconds} seconds."
            )
        if "error" in outcome:
            raise outcome["error"]
        result = outcome.get("result")
        if not isinstance(result, HuntResult):
            raise HuntExecutionError("execute() must return a HuntResult.")
        max_results = request.limits.max_results
        if len(result.events) > max_results:
            return HuntResult(
                events=result.events[:max_results],
                total_hits=result.hits_count,
                truncated=True,
            )
        return result

    def send_bundle(self, stix_objects: Sequence[Any]) -> list[str]:
        """Send the knowledge of a run to OpenCTI within the run work.

        Args:
            stix_objects: connectors-sdk models, stix2 objects or STIX dictionaries.

        Returns:
            The STIX ids of the objects sent.
        """
        objects: dict[str, dict[str, Any]] = {}
        for stix_object in stix_objects:
            stix_dict = self._to_stix_dict(stix_object)
            objects[stix_dict["id"]] = stix_dict
        if not objects:
            return []
        bundle = self.helper.stix2_create_bundle(list(objects.values()))
        # The bundle references entities that already exist in OpenCTI (techniques,
        # indicators, Security Platform, markings, author): cleaning up "inconsistent"
        # references would strip them from the sightings.
        self.helper.send_stix2_bundle(
            bundle,
            work_id=self.helper.work_id,
            cleanup_inconsistent_bundle=False,
        )
        return list(objects)

    def report(self, run_id: str, report: HuntRunReport) -> None:
        """Report the outcome of a hunt run to OpenCTI.

        Args:
            run_id: OpenCTI id of the hunt run.
            report: Outcome of the run.
        """
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
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _report_failure(
        self,
        run_id: str,
        native_query: NativeQuery | None,
        started: float,
        error: BaseException,
    ) -> None:
        """Report a failed or timed out run without masking the original error."""
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
                ),
            )
        except Exception as report_error:
            self.logger.error(
                "[HUNT] Unable to report the failed hunt run",
                {"hunt_run_id": run_id, "error": _error_message(report_error)},
            )

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
