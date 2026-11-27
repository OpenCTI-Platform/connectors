"""Privara Unmask internal enrichment connector.

Flow for one file observable (Artifact or StixFile with an attached file):
    1. check the TLP and the entity type;
    2. download the attached file from OpenCTI and check, locally, that it is an
       Android package (APK, XAPK, APKM or .apks) under the size limit (the API's
       `limits.max_file_mb`, or a lower connector setting): nothing else is ever
       sent to Privara;
    3. look the SHA-256 up (GET /jobs?sha256=, free) and reuse a charged result
       (live / dead, last 30 days) or wait for a running job; otherwise POST
       /samples (Idempotency-Key `opencti-<sha256>`, plus a suffix derived from
       the earlier job after a none / void / failed result, so a retried upload
       never charges twice and a re-run really runs again); then poll
       GET /jobs/{id}, following the server's Retry-After, up to `max_wait`;
    4. send a STIX 2.1 bundle: an Indicator per C2 (url / ipv4 / ipv6 / domain
       pattern on the raw value), the Malware family when known, relationships
       and a Note with the outcome, the charge and the report link.

Each analysis can be charged on the customer's Privara wallet, so the
connector never retries an upload that the API refused (402, 403, refused
file) and pauses itself for a few minutes after 402 / 403. Job ids are
opaque: they are read from the API's JSON and never parsed or validated.
"""

from __future__ import annotations

import hashlib
import io
import time
import zipfile
from typing import Any

from connector.converter_to_stix import ConverterToStix, format_cents
from connector.settings import ConnectorSettings
from privara_unmask_client import (
    REFUSED_REASONS,
    UnmaskClient,
    UnmaskError,
    UnmaskTimeout,
    dashboard_url,
    idempotency_key,
)
from pycti import OpenCTIConnectorHelper

ANDROID_EXTENSIONS = (".apk", ".xapk", ".apkm", ".apks")
# After 402 / 403 from the API, skip new uploads for this long (no retry storm in auto mode).
PAUSE_SECONDS = 600


def android_package_kind(content: bytes) -> str | None:
    """Return ``apk`` / ``bundle`` when ``content`` looks like an Android package, else None.

    An APK is a ZIP with ``AndroidManifest.xml``; XAPK / APKM / .apks are ZIPs
    holding one or more ``.apk`` files.
    """
    if not content.startswith(b"PK\x03\x04"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, ValueError):
        return None
    if "AndroidManifest.xml" in names:
        return "apk"
    if any(name.lower().endswith(".apk") for name in names):
        return "bundle"
    return None


class PrivaraUnmaskConnector:
    """Enriches Android packages with the C2 servers Privara Unmask extracts."""

    def __init__(
        self,
        config: ConnectorSettings,
        helper: OpenCTIConnectorHelper,
        client: UnmaskClient | None = None,
    ):
        self.config = config
        self.helper = helper
        settings = config.privara_unmask
        self.base_url = str(settings.api_base_url).rstrip("/")
        self.client = client or UnmaskClient(
            api_key=settings.api_key.get_secret_value(),
            base_url=self.base_url,
            integration="opencti",
        )
        self.converter = ConverterToStix(create_observables=settings.create_observables)
        self.max_wait = settings.max_wait
        self.poll_interval = settings.poll_interval
        self.max_file_mb = settings.max_file_size_mb
        self.notify_email = settings.notify_email
        self.max_tlp = f"TLP:{config.connector.max_tlp.upper()}"
        self.octi_api_url = str(config.opencti.url).rstrip("/")
        self.scope = {s.lower() for s in config.connector.scope}
        self._paused_until = 0.0
        self._paused_note: tuple[str, str] | None = None

    # ---------------------------------------------------------------- bundle

    def _send_bundle(self, objects: list) -> int:
        bundle = self.helper.stix2_create_bundle(objects)
        return len(
            self.helper.send_stix2_bundle(bundle, cleanup_inconsistent_bundle=True)
        )

    def _finish(
        self, data: dict, stix_objects: list, new_objects: list, message: str
    ) -> str:
        """Send the result. In a playbook, always send one bundle (the original if nothing new).

        A message without ``event_type`` comes from a playbook: the original
        bundle must go back even when the entity is skipped (out of scope, TLP).
        """
        in_playbook = getattr(
            self.helper, "playbook", None
        ) is not None or not data.get("event_type")
        if new_objects:
            self._send_bundle(stix_objects + new_objects)
        elif in_playbook:
            self._send_bundle(stix_objects)
        self.helper.connector_logger.info(message)
        return message

    # ------------------------------------------------------------- messages

    def process_message(self, data: dict) -> str:
        opencti_entity = data["enrichment_entity"]
        stix_entity = data["stix_entity"]
        stix_objects = data["stix_objects"]
        try:
            tlp = "TLP:CLEAR"
            for marking in opencti_entity.get("objectMarking") or []:
                if marking.get("definition_type") == "TLP":
                    tlp = marking["definition"]
            if not OpenCTIConnectorHelper.check_max_tlp(tlp, self.max_tlp):
                return self._finish(
                    data,
                    stix_objects,
                    [],
                    f"Skipped: the file is {tlp}, above the connector's max TLP ({self.max_tlp}); nothing sent to Privara.",
                )
            if opencti_entity["entity_type"].lower() not in self.scope:
                return self._finish(
                    data,
                    stix_objects,
                    [],
                    f"Skipped: {opencti_entity['entity_type']} is not in the connector scope.",
                )
            new_objects, message = self._enrich(opencti_entity, stix_entity)
            return self._finish(data, stix_objects, new_objects, message)
        except Exception as err:
            self.helper.connector_logger.error(
                "Privara Unmask enrichment failed", {"error": str(err)}
            )
            if getattr(self.helper, "playbook", None) is not None or not data.get(
                "event_type"
            ):
                self._send_bundle(stix_objects)
            raise

    def _pick_file(self, opencti_entity: dict) -> dict | None:
        files = opencti_entity.get("importFiles") or []
        for item in files:
            if str(item.get("name", "")).lower().endswith(ANDROID_EXTENSIONS):
                return item
        return files[0] if files else None

    def _enrich(self, opencti_entity: dict, stix_entity: dict) -> tuple[list, str]:
        sample_ref = stix_entity["id"]
        markings = list(stix_entity.get("object_marking_refs") or [])

        def note(abstract: str, content: str) -> list:
            return self.converter.message_note(sample_ref, markings, abstract, content)

        if time.monotonic() < self._paused_until and self._paused_note:
            abstract, content = self._paused_note
            return note(abstract, content), f"Not sent to Privara: {abstract}"

        attached = self._pick_file(opencti_entity)
        if attached is None:
            return (
                [],
                "No file attached to this observable: Privara Unmask needs the sample itself.",
            )
        max_bytes = self._max_file_bytes()
        too_large = (
            [],
            f"Not sent: the file is larger than the size limit ({max_bytes // 1048576} MB).",
        )
        size = attached.get("size")
        if isinstance(size, int) and size > max_bytes:
            return too_large

        content = self.helper.api.fetch_opencti_file(
            f"{self.octi_api_url}/storage/get/{attached['id']}", binary=True
        )
        if not content:
            return [], "The attached file is empty."
        if len(content) > max_bytes:
            return too_large
        if android_package_kind(content) is None:
            return (
                [],
                "Not sent: the file is not an Android package (APK, XAPK, APKM or .apks).",
            )

        sha256 = hashlib.sha256(content).hexdigest()
        job, earlier = self._existing_job(sha256)
        reused = job is not None
        submitted = job is None
        if job is None:
            name = (attached.get("name") or "sample").rsplit("/", 1)[-1]
            self.helper.connector_logger.info(
                "Submitting the sample to Privara Unmask",
                {"sha256": sha256, "file_name": name},
            )
            try:
                answer = self.client.submit_sample(
                    name,
                    content,
                    idempotency_key=idempotency_key(
                        "opencti", sha256, earlier.get("job_id") if earlier else None
                    ),
                    label=f"OpenCTI {name}",
                    notify_email=self.notify_email,
                )
            except UnmaskError as err:
                return self._submit_error(err, note)
            jobs = answer.get("jobs") or []
            if not jobs:
                raise ValueError(
                    "The Unmask API accepted the upload but returned no job"
                )
            job = jobs[0]
            if job.get("status") == "refused":
                refused = job.get("refused") or {}
                code = refused.get("code") or "refused"
                reason = REFUSED_REASONS.get(code, "it was refused")
                detail = refused.get("message") or ""
                return (
                    note(
                        "file refused (not charged)",
                        f"Privara did not analyse this file because {reason} "
                        f"(code `{code}`). {detail} Refused files cost nothing.",
                    ),
                    f"Privara refused the file ({code}): {reason}",
                )

        job_id = job["job_id"]
        # The server matched an earlier charged result of this sample: no new charge.
        duplicate = bool(job.get("duplicate_of"))
        result = job
        # A submit answer is only a summary (even when it says `done`, for a
        # duplicate): always read the full job. wait_for_job reads it at once.
        if submitted or job.get("status") != "done":
            self.helper.connector_logger.info(
                "Waiting for the Unmask job",
                {"job_id": job_id, "max_wait": self.max_wait, "reused": reused},
            )
            try:
                result = self.client.wait_for_job(
                    job_id, max_wait=self.max_wait, initial_interval=self.poll_interval
                )
            except UnmaskTimeout as err:
                return (
                    note(
                        "analysis still running",
                        f"Job `{job_id}` was still `{err.job.get('status')}` after {int(err.waited)} s. "
                        "It keeps running on Privara. Enrich this file again later to collect "
                        "the result: the same job is found again and nothing is charged twice.",
                    ),
                    f"Job {job_id} still running after {int(err.waited)} s; enrich again later to collect it.",
                )
            except UnmaskError as err:
                raise self._config_error(err) from None
            reused = duplicate or (reused and job.get("status") == "done")

        objects = self.converter.build_result(
            result, sample_ref, markings, reused=reused
        )
        indicators = sum(1 for obj in objects if obj["type"] == "indicator")
        charge = (
            "existing result, no new charge"
            if reused
            else f"charged {format_cents(result.get('charge_cents'))}"
        )
        return objects, (
            f"Privara Unmask job {job_id}: status {result.get('status')}, outcome "
            f"{result.get('outcome')}, {indicators} C2 indicator(s), {charge}."
        )

    def _max_file_bytes(self) -> int:
        """The API's size limit (GET /balance), lowered by `max_file_size_mb` when set."""
        try:
            limit = self.client.max_file_bytes()
        except UnmaskError as err:
            raise self._config_error(err) from None
        if self.max_file_mb:
            limit = min(limit, self.max_file_mb * 1024 * 1024)
        return limit

    def _existing_job(self, sha256: str) -> tuple[dict | None, dict | None]:
        """(job to reuse or wait for, earlier job not reused) for this sample."""
        try:
            job, earlier = self.client.lookup(sha256)
        except UnmaskError as err:
            if not err.transient:
                raise self._config_error(err) from None
            self.helper.connector_logger.warning(
                "Could not look the sample up, submitting it", {"error": err.code}
            )
            return None, None
        if job is not None:
            self.helper.connector_logger.info(
                "Reusing an existing Unmask job",
                {"job_id": job.get("job_id"), "status": job.get("status")},
            )
        elif earlier is not None:
            self.helper.connector_logger.info(
                "Analysing the sample again (the earlier result is not reused)",
                {
                    "job_id": earlier.get("job_id"),
                    "outcome": earlier.get("outcome"),
                    "status": earlier.get("status"),
                },
            )
        return job, earlier

    @staticmethod
    def _config_error(err: UnmaskError, submitting: bool = False) -> Exception:
        """A clear error for problems the user must fix; other errors unchanged."""
        if err.code == "invalid_key" or err.status == 401:
            return ValueError(
                "The Unmask API key is invalid or revoked: check PRIVARA_UNMASK_API_KEY"
            )
        if err.code == "missing_scope":
            return ValueError(
                "The Unmask API key lacks a scope: it needs `submit` and `read`"
            )
        if err.code == "not_found" and submitting:
            return ValueError(
                "The Unmask API is not enabled for this Privara account (or the API URL "
                "is wrong): check PRIVARA_UNMASK_API_BASE_URL and the account's Unmask API plan"
            )
        if err.code == "not_found":
            return ValueError(
                "The Unmask job was not found for this key (was the key replaced by "
                "one of another account?)"
            )
        return err

    def _submit_error(self, err: UnmaskError, note: Any) -> tuple[list, str]:
        """Turn an API refusal into a Note; raise for configuration problems."""
        wallet = dashboard_url(self.base_url)
        if err.status == 402:
            abstract = "wallet balance too low (nothing queued, not charged)"
            content = (
                f"Privara answered `{err.code}`: {err.message}\n\n"
                f"Top up the Unmask wallet at {wallet}, then enrich this file again."
            )
        elif err.status == 403 and err.code == "fair_use_reached":
            abstract = "monthly fair-use limit reached (not charged)"
            content = (
                f"Privara answered `{err.code}`: {err.message}\n\n"
                "New analyses wait until next month or until Privara support raises the limit."
            )
        elif err.status == 413:
            return (
                note(
                    "file too large for Privara (not charged)",
                    f"Privara answered `{err.code}`: {err.message}",
                ),
                f"Privara refused the file as too large: {err.message}",
            )
        elif err.status == 429:
            # Still rate limited after the client's own retries: no pause, no charge.
            return (
                note(
                    "rate limited, nothing sent (not charged)",
                    f"Privara answered `{err.code}`: {err.message}\n\n"
                    "Too many requests for this API key right now. Enrich this file again "
                    "in a few minutes.",
                ),
                f"Not sent to Privara: rate limited ({err.message})",
            )
        else:
            raise self._config_error(err, submitting=True) from None
        self._paused_until = time.monotonic() + PAUSE_SECONDS
        self._paused_note = (abstract, content)
        return note(abstract, content), f"Not sent to Privara: {abstract}"

    def run(self) -> None:
        self.helper.listen(message_callback=self.process_message)
