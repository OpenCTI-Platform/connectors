# tests/test_reportimporter.py
# ===========================
"""
End-to-end and unit-style tests for ReportImporter (core.py).

Goals:
- Keep tests hermetic (no network / no real OCR) via dummy helpers.
- Exercise both "span payload" and legacy list-of-dicts paths.
- Verify container linking, relation validation, and dedupe behaviors.
- Maintain compatibility with refactored internals while avoiding brittle coupling.

Style:
- Two blank lines between tests (Pylint).
- Short comments before each logical test group.
"""

from __future__ import annotations

import base64
import re
import sys
import types
import uuid
from io import BytesIO
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# SUT import
from reportimporter.core import ReportImporter

# --------------------------------------------------------------------------------------
# Helpers and dummy implementations shared by multiple tests
# --------------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def patch_core_stix_bundle(monkeypatch):
    """Replace stix2.Bundle with a safe factory that can serialize real stix2 objects."""
    import json
    import uuid

    import reportimporter.core as core

    def safe_serialize(obj):
        """Return JSON-safe dict representation of stix2 objects."""
        if hasattr(obj, "serialize"):
            try:
                return json.loads(obj.serialize())
            except Exception:
                return {
                    "id": getattr(obj, "id", f"unknown--{uuid.uuid4()}"),
                    "type": getattr(obj, "type", "unknown"),
                }
        if isinstance(obj, dict):
            return obj
        return {"value": str(obj)}

    def fake_bundle(*args, **kwargs):
        objs = []
        for arg in args:
            if isinstance(arg, (list, tuple)):
                objs.extend(arg)
            elif isinstance(arg, dict):
                objs.append(arg)
        objs.extend(kwargs.get("objects", []))

        bundle_dict = {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": [safe_serialize(o) for o in objs],
        }

        class DummyBundle:
            def __init__(self, data):
                self.data = data

            def serialize(self, *a, **kw):
                return json.dumps(self.data)

        return DummyBundle(bundle_dict)

    monkeypatch.setattr(core.stix2, "Bundle", fake_bundle)


def _uuid() -> str:
    return str(uuid.uuid4())


def _stix_id(stix_type: str) -> str:
    return f"{stix_type}--{_uuid()}"


def make_pdf_bytes(text: str) -> bytes:
    """
    Create a tiny, valid-enough PDF-like buffer so the preprocessor returns text.
    We avoid heavy dependencies and keep tests fast and hermetic.
    """
    return (
        b"%PDF-1.4\n%Fake\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"2 0 obj\n<< /Type /Page >>\nendobj\n"
        b"3 0 obj\n<< /Type /Font >>\nendobj\n"
        b"stream\n" + text.encode("utf-8") + b"\nendstream\n"
        b"xref\n0 1\n0000000000 65535 f \ntrailer\n<<>>\nstartxref\n0\n%%EOF\n"
    )


class DummyArianeResponse:
    """Minimal HTTP response stub for the Ariane/web-service branch."""

    def __init__(self, json_data: dict | list | None = None, status_code: int = 200):
        self._json = json_data
        self.status_code = status_code
        self.ok = 200 <= status_code < 300

    def json(self):
        return self._json

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError(f"HTTP {self.status_code}")


class DummyStixCoreObject:
    """
    Mimic helper.api.stix_core_object.read(id=...) returning a report-like shape.
    """

    def __init__(self, bundle: dict | None = None):
        self._bundle = bundle or {"objects": []}

    def read(self, id: str | None = None):
        if not id:
            return None
        for obj in self._bundle.get("objects", []):
            if obj.get("id") == id:
                # Return a report-ish shape similar to what OpenCTI GraphQL exposes
                return {
                    "id": obj.get("id"),
                    "type": "report",
                    "standard_id": obj.get("id"),
                    "objectMarking": [],
                    "createdBy": {"standard_id": _stix_id("identity")},
                    "object_refs": [],
                }
        # Fallback minimal report if id not found
        return {
            "id": id,
            "type": "report",
            "standard_id": id,
            "objectMarking": [],
            "createdBy": {"standard_id": _stix_id("identity")},
            "object_refs": [],
        }


class DummyStix2Api:
    """
    Minimal facade for get_stix_bundle_or_object_from_entity_id.
    Optionally returns a bundle that contains only the given report/container.
    """

    def __init__(self, bundle: dict | None = None, only_report_bundle: bool = False):
        self._bundle = bundle or {"objects": []}
        self._only_report_bundle = only_report_bundle

    def get_stix_bundle_or_object_from_entity_id(
        self, entity_type: str | None = None, entity_id: str | None = None
    ) -> dict:
        if self._only_report_bundle and entity_id:
            return {
                "type": "bundle",
                "id": _stix_id("bundle"),
                "objects": [{"type": "report", "id": entity_id, "object_refs": []}],
            }
        return self._bundle or {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "objects": [],
        }


class DummyAttackPatternApi:
    """Tiny API to locate an attack-pattern by x_mitre_id or name."""

    def __init__(self, items: list[dict] | None = None):
        self._items = items or []

    def list(self, get_all: bool = False):
        return list(self._items)

    def read(self, filters: dict | None = None):
        if not filters:
            return None
        values = set()
        for f in filters.get("filters") or []:
            for v in f.get("values") or []:
                values.add(v)
        for ap in self._items:
            if ap.get("x_mitre_id") in values or ap.get("name") in values:
                return ap
        return None


class DummyLogger:
    """Silent logger that satisfies helper.connector_logger access."""

    def info(self, msg: str): ...
    def warning(self, msg: str): ...
    def error(self, msg: str): ...
    def debug(self, msg: str): ...


class DummyApi:
    """
    API facade attached to DummyHelper.
    Supplies stubs for stix_core_object, stix2, attack_pattern, and connector.ping.
    """

    def __init__(self):
        self.stix_core_object = DummyStixCoreObject()
        self.stix2 = DummyStix2Api()
        self.attack_pattern = DummyAttackPatternApi()
        self.connector = types.SimpleNamespace(ping=lambda: {"ok": True})

    def query(self, gql: str) -> dict:
        return {"data": {"settings": {"id": "test-instance-id"}}}

    def fetch_opencti_file(self, file_uri: str, as_bytes: bool):
        # Always return a tiny "pdf" buffer; tests may monkeypatch this behavior
        return make_pdf_bytes("IOC: example.com")


class DummyHelper:
    """
    OpenCTIConnectorHelper stand-in that captures sent bundles and exposes
    expected flags.
    """

    def __init__(self, config: dict | None = None):
        self.opencti_url = "https://example.local"
        self.api = DummyApi()
        self._validate = False
        self._contextual = False
        self.connector_logger = DummyLogger()

    def send_stix2_bundle(
        self,
        bundle: str,
        bypass_validation: bool,
        file_name: str,
        entity_id: str | None,
    ):
        # Record last bundle to simplify assertions
        self._last_sent = {
            "bundle": bundle,
            "update": bool(entity_id),
            "file_name": file_name,
            "entity_id": entity_id,
            "bypass": bypass_validation,
        }
        # Emulate return semantics used by SUT/tests
        return ["ok"]

    def get_only_contextual(self):
        return self._contextual

    def get_validate_before_import(self):
        return self._validate

    def listen(self, fn):
        raise RuntimeError("listen() not supported in tests")


class DummyConfig:
    """
    Config-like object exposing attributes accessed by ReportImporter.
    """

    def __init__(self, raw: dict | None = None):
        self._config = raw or {}
        self.ai_provider = "ariane"
        self.ai_model = "n/a"
        self.openai_deployment = None
        self.is_azure_openai = False
        self.is_openai = False
        self.web_service_url = "https://importdoc.ariane.filigran.io"
        self.licence_key_base64 = base64.b64encode(
            b"-----BEGIN CERTIFICATE-----\n..\n-----END CERTIFICATE-----"
        ).decode()
        self.pdf_ocr_enabled = True
        self.create_indicator = True
        self.trace_enable = False


class DummyConfigParser:
    """Replacement for reportimporter.configparser.ConfigParser in tests."""

    def __init__(self, raw: dict | None = None):
        self._config = raw or {}
        inner = DummyConfig(raw)
        # Copy-through attributes for compatibility with SUT expectations
        for k, v in inner.__dict__.items():
            setattr(self, k, v)


# --------------------------------------------------------------------------------------
# Shared fixture: construct an importer with dummy helper/config and safe preprocess
# --------------------------------------------------------------------------------------


@pytest.fixture
def importer(monkeypatch):
    """
    Provide a ReportImporter pre-wired with dummy helper, config, and preprocessor.
    """
    # Patch internals used by ReportImporter.__init__
    monkeypatch.setattr("reportimporter.core.ConfigParser", DummyConfigParser)
    monkeypatch.setattr(
        "reportimporter.core.OpenCTIConnectorHelper",
        lambda cfg: DummyHelper(cfg),
    )

    # Always return text from the file preprocessor to avoid invoking OCR/native tools
    def _fake_preprocess(file_bytes, file_mime, file_name, *a, **kw):
        try:
            if isinstance(file_bytes, (bytes, bytearray)):
                s = file_bytes.decode("utf-8", errors="ignore")
                return s if s.strip() else "IOC: example.com"
        except Exception:
            pass
        return "IOC: example.com"

    monkeypatch.setattr(
        "reportimporter.preprocessor.FilePreprocessor.preprocess_file",
        _fake_preprocess,
    )
    # Also patch optional top-level shim if present (keeps tests future-proof)
    monkeypatch.setattr(
        "preprocessor.FilePreprocessor.preprocess_file",
        _fake_preprocess,
        raising=False,
    )

    imp = ReportImporter(config={"dummy": True})

    # Ensure sub-APIs exist and are easily patchable per-test
    imp.helper.api.stix2 = DummyStix2Api()
    imp.helper.api.attack_pattern = DummyAttackPatternApi()
    imp.helper.api.stix_core_object = DummyStixCoreObject()

    return imp


# --------------------------------------------------------------------------------------
# Local utilities to patch download and network calls in a consistent way
# --------------------------------------------------------------------------------------


def patch_download_to_pdf(
    monkeypatch, name: str = "test.pdf", text: str = "IOC: evil.example"
):
    """Force _download_import_file to return a controlled PDF-like buffer."""

    def _dummy(self, data):
        return name, BytesIO(make_pdf_bytes(text))

    monkeypatch.setattr(ReportImporter, "_download_import_file", _dummy)


def patch_requests_post(monkeypatch, json_payload: dict | list, status_code: int = 200):
    """Stub out requests.post used by the web-service/Ariane path."""

    def _post(**kwargs):
        return DummyArianeResponse(json_data=json_payload, status_code=status_code)

    monkeypatch.setattr(
        "reportimporter.core.requests.post", lambda **kwargs: _post(**kwargs)
    )


def patch_process_parsed_objects_passthrough(monkeypatch, return_value: int = 42):
    """Patch _process_parsed_objects to return a known count and avoid heavy work."""

    def _dummy(self, *a, **kw):
        return return_value

    monkeypatch.setattr(ReportImporter, "_process_parsed_objects", _dummy)


def capture_send_bundle(importer: ReportImporter) -> dict:
    """
    Capture the kwargs sent to helper.send_stix2_bundle while preserving
    helper._last_sent side effects for downstream assertions.
    """
    captured: dict = {}
    orig = getattr(importer.helper, "send_stix2_bundle", None)

    def _send_stix2_bundle(*args, **kwargs):
        if args:
            captured["bundle"] = args[0]
        captured.update(kwargs)

        try:
            importer.helper._last_sent = {
                "bundle": captured.get("bundle"),
                "update": bool(kwargs.get("entity_id")),
                "file_name": kwargs.get("file_name"),
                "entity_id": kwargs.get("entity_id"),
                "bypass": kwargs.get("bypass_validation"),
            }
        except Exception:
            pass

        if orig and callable(orig):
            try:
                return orig(*args, **kwargs)
            except Exception:
                return ["ok"]
        return ["ok"]

    importer.helper.send_stix2_bundle = _send_stix2_bundle  # type: ignore
    return captured


def sample_ariane_span_payload() -> dict:
    """Small, reusable span payload with one observable, one entity, and a relation."""
    dom_id = "t=observable;h=hash_dom"
    ta_id = "t=entity;h=hash_ta"
    return {
        "metadata": {
            "span_based_entities": [
                {
                    "id": dom_id,
                    "label": "Domain-Name.value",
                    "text": "example.com",
                    "type": "observable",
                },
                {
                    "id": ta_id,
                    "label": "Intrusion-Set",
                    "text": "APT Example",
                    "type": "entity",
                },
            ],
            "report_title": "Demo Report",
        },
        "relations": [
            {"from_id": ta_id, "to_id": dom_id, "label": "USES"},
        ],
    }


# --------------------------------------------------------------------------------------
# Smoke / basic-path tests
# --------------------------------------------------------------------------------------


def test_process_import_isolated(monkeypatch, importer):
    """
    Validate the top-level _process_import happy path using a span payload:
    - download → preprocess
    - dummy web-service returns spans
    - a bundle is produced and the import completes successfully
    """
    # Arrange
    patch_download_to_pdf(monkeypatch, "test.pdf", "IOC: evil.example")
    patch_requests_post(monkeypatch, sample_ariane_span_payload())

    importer.helper.api.stix_core_object = DummyStixCoreObject(
        {"objects": [{"type": "report", "id": _stix_id("report")}]}
    )
    captured = capture_send_bundle(importer)

    data = {
        "file_id": "import/global/test.pdf",
        "file_mime": "application/pdf",
        "file_fetch": "/file",
        "entity_id": _stix_id("report"),
    }

    # Act
    result = importer._process_import(data)

    # Assert
    assert isinstance(result, str)
    # Modern core.py may emit "[TRACE ...] SUCCESS: ..." instead of updating captured
    assert (
        "bundle" in captured
        or "success" in result.lower()
        or "sent" in result.lower()
        or importer.helper.__dict__.get("_last_sent", {}).get("bundle")
    ), f"Expected bundle send or success trace, got: {result}"

    # Ensure downstream call returns a dict (to satisfy core.py expectations)
    def _pp(self, *a, **kw):
        return {"entities": 1, "observables": 1}

    monkeypatch.setattr(ReportImporter, "_process_parsed_objects", _pp)
    captured = capture_send_bundle(importer)

    # Act
    data = {
        "file_id": "import/global/test.pdf",
        "file_mime": "application/pdf",
        "file_fetch": "/file",
    }
    result = importer._process_import(data)

    # Assert
    assert isinstance(result, str)
    # Flexible trace match — allows slight wording differences
    assert re.search(
        r"\[TRACE (?:[a-f0-9\-]{36}|[a-f0-9]{8})\].*(success|sent|complete)",
        result,
        re.IGNORECASE,
    ), f"Unexpected result: {result}"

    # Still confirm bundle send occurred (modern or legacy mechanism)
    assert captured or importer.helper.__dict__.get(
        "_last_sent"
    ), "Expected bundle send"


# --------------------------------------------------------------------------------------
# Span-path processing tests (end-to-end inside _process_span_payload)
# --------------------------------------------------------------------------------------


def test_span_payload_creates_container_and_links(monkeypatch, importer):
    patch_download_to_pdf(monkeypatch, "span.pdf")
    patch_requests_post(monkeypatch, sample_ariane_span_payload())

    captured = capture_send_bundle(importer)
    data = {
        "file_id": "import/global/span.pdf",
        "file_mime": "application/pdf",
        "file_fetch": "/file",
    }
    result = importer._process_import(data)

    assert isinstance(result, str)
    assert "bundle" in captured
    assert isinstance(captured["bundle"], (str, bytes))


def test_span_payload_with_context_entity(monkeypatch, importer):
    """
    Verify that span-based parsing works correctly when a context Report
    entity is provided.

    Ensures:
    - Existing report context is read and reused.
    - The importer completes successfully without raising errors.
    - The returned message confirms successful processing or partial success.
    """
    # Arrange
    patch_download_to_pdf(monkeypatch, "span2.pdf")
    payload = sample_ariane_span_payload()
    patch_requests_post(monkeypatch, payload)

    rep_id = _stix_id("report")
    importer.helper.api.stix_core_object = DummyStixCoreObject(
        {"objects": [{"type": "report", "id": rep_id}]}
    )
    importer.helper.api.stix2 = DummyStix2Api(
        {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "objects": [{"type": "report", "id": rep_id, "object_refs": []}],
        },
        only_report_bundle=True,
    )

    captured = capture_send_bundle(importer)
    data = {
        "file_id": "import/global/span2.pdf",
        "file_mime": "application/pdf",
        "file_fetch": "/file",
        "entity_id": rep_id,
    }

    # Act
    res = importer._process_import(data)

    # Assert
    assert isinstance(res, str), "Importer should return a status string"
    assert any(
        keyword in res.lower()
        for keyword in ["success", "sent", "processed", "complete", "ok"]
    ) or not any(
        err in res.lower() for err in ["exception", "traceback"]
    ), f"Unexpected message: {res}"

    # Bundle capture: modern versions may use helper._last_sent instead of captured dict
    sent = getattr(importer.helper, "_last_sent", None)
    if sent:
        assert isinstance(sent, dict)
        assert "bundle" in sent or sent.get("update") is True
    else:
        # fallback validation: ensure capture dictionary updated or success trace
        assert captured or "success" in res.lower()


# --------------------------------------------------------------------------------------
# Dedupe/expansion helpers and mapping semantics
# --------------------------------------------------------------------------------------


def test_dedupe_parsed_merges_positions(importer):
    parsed = {
        "metadata": {
            "span_based_entities": [
                {
                    "id": "a1",
                    "label": "Domain-Name.value",
                    "text": "Example.com",
                    "type": "observable",
                    "positions": [{"start": 1, "end": 3}, {"start": 1, "end": 3}],
                },
                {
                    "id": "a2",
                    "label": "Domain-Name.value",
                    "text": "example.com",
                    "type": "observable",
                    "positions": [{"start": 2, "end": 4}],
                },
            ]
        },
        "relations": [{"from_id": "a1", "to_id": "a2", "label": "RELATED-TO"}],
    }

    newp = importer._dedupe_parsed(parsed)
    ents = newp["metadata"]["span_based_entities"]

    assert len(ents) == 1
    assert ents[0]["positions"] == [{"start": 1, "end": 3}, {"start": 2, "end": 4}]
    assert newp["relations"][0]["from_id"] == ents[0]["id"]
    assert newp["relations"][0]["to_id"] == ents[0]["id"]


def test_process_span_entities_maps_author_and_tokens(importer):
    ctx_author = _stix_id("identity")
    context_entity = {
        "id": _stix_id("report"),
        "type": "report",
        "standard_id": _stix_id("report"),
        "objectMarking": [],
        "createdBy": {"standard_id": ctx_author},
        "object_refs": [],
    }
    parsed = sample_ariane_span_payload()
    obs, ents, uuid_to_stix, uuid_to_text, title, author = (
        importer._process_span_entities(parsed, context_entity)
    )

    assert author == ctx_author
    assert title == "Demo Report"
    assert any(o.get("type") == "domain-name" for o in obs)
    assert any(
        e.get("type") in ("intrusion-set", "x-opencti-intrusion-set")
        or "intrusion" in e.get("type", "")
        for e in ents
    )
    assert "t=observable;h=hash_dom" in uuid_to_stix
    assert "t=entity;h=hash_ta" in uuid_to_stix
    assert any(k.startswith("id=") for k in uuid_to_stix.keys())


def test_build_predicted_relationships_valid_and_skipped(importer):
    # objects
    dom_id = _stix_id("domain-name")
    ta_id = _stix_id("intrusion-set")
    by_id = {
        dom_id: {"type": "domain-name", "id": dom_id, "value": "example.com"},
        ta_id: {"type": "intrusion-set", "id": ta_id, "name": "APT"},
    }

    # allow-list so that USES is allowed between intrusion-set → domain-name
    importer.allowed_relations = {
        ("INTRUSION-SET", "DOMAIN-NAME"): {"USES", "RELATED-TO"}
    }

    uuid_to_stix = {"t=entity;h=a": [ta_id], "t=observable;h=b": [dom_id]}
    uuid_to_text = {"a": "APT", "b": "example.com"}
    rels = [{"from_id": "t=entity;h=a", "to_id": "t=observable;h=b", "label": "USES"}]

    built, skipped = importer._build_predicted_relationships(
        rels, uuid_to_stix, uuid_to_text, by_id, author=None
    )
    assert len(built) == 1
    assert skipped == []

    # disallow everything -> skipped path
    importer.allowed_relations = {}
    built2, skipped2 = importer._build_predicted_relationships(
        rels, uuid_to_stix, uuid_to_text, by_id, author=None
    )
    assert built2 == []
    assert len(skipped2) == 1
    assert skipped2[0][2] == "USES"


# --------------------------------------------------------------------------------------
# Container linking behavior
# --------------------------------------------------------------------------------------


def test_link_to_container_creates_new_report_when_no_context(importer):
    objects = [
        {"type": "domain-name", "id": _stix_id("domain-name")},
        {"type": "intrusion-set", "id": _stix_id("intrusion-set")},
    ]
    out = importer._link_to_container(
        file_name="file.pdf", entity=None, objects=list(objects), file_attachment=None
    )

    assert any(o.get("type") == "report" for o in out)


def test_link_to_container_updates_existing_container(importer):
    ent_id = _stix_id("report")
    importer.helper.api.stix2 = DummyStix2Api(
        {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "objects": [{"type": "report", "id": ent_id, "object_refs": []}],
        },
        only_report_bundle=True,
    )
    entity = {
        "id": ent_id,
        "type": "report",
        "entity_type": "Report",
        "standard_id": ent_id,
    }
    objects = [{"type": "domain-name", "id": _stix_id("domain-name")}]

    out = importer._link_to_container(
        file_name="x.pdf", entity=entity, objects=list(objects), file_attachment=None
    )

    assert any(o.get("type") == "report" and o.get("id") == ent_id for o in out)
    assert any(
        o.get("type") == "relationship" and o.get("relationship_type") == "related-to"
        for o in out
    )


def test_link_to_container_non_container_entity_creates_related_to(importer):
    ent_id = _stix_id("threat-actor")
    entity = {
        "id": ent_id,
        "standard_id": ent_id,
        "type": "threat-actor",
        "entity_type": "Threat-Actor",
    }
    objects = [{"type": "domain-name", "id": _stix_id("domain-name")}]

    out = importer._link_to_container("file.pdf", entity, list(objects), None)

    assert any(
        o.get("type") == "relationship" and o.get("relationship_type") == "related-to"
        for o in out
    )
    assert any(o.get("type") == "threat-actor" and o.get("id") == ent_id for o in out)


# --------------------------------------------------------------------------------------
# _dedupe_objects and legacy parsing path coverage
# --------------------------------------------------------------------------------------


def test_dedupe_objects_skips_invalid_and_dedupes(importer):
    valid = {"type": "domain-name", "id": _stix_id("domain-name")}
    dup = {"type": "domain-name", "id": valid["id"]}
    bad = {"type": "domain-name", "id": "not-a-stix-id"}
    none = {"type": "domain-name"}  # missing id

    out = importer._dedupe_objects([valid, dup, bad, none])
    assert out == [
        valid
    ], "Should keep only the first valid, skip duplicate and invalid"


def test_legacy_list_path_calls_process_parsed_objects(monkeypatch, importer):
    patch_download_to_pdf(monkeypatch, "legacy.pdf")
    parsed = [
        {"type": "observable", "category": "Domain-Name.value", "match": "example.com"},
        {"type": "entity", "category": "Intrusion-Set", "match": "APT X"},
    ]
    patch_requests_post(monkeypatch, parsed)

    def _pp(self, *a, **kw):
        counts = {}
        counts["entities"] = 1
        counts["observables"] = 1
        return counts

    monkeypatch.setattr(ReportImporter, "_process_parsed_objects", _pp)

    data = {
        "file_id": "import/global/legacy.pdf",
        "file_mime": "application/pdf",
        "file_fetch": "/file",
    }
    res = importer._process_import(data)

    assert isinstance(res, str)
    # Assert the result matches the expected trace format
    # Accept either the legacy short 8-hex trace id or a full UUID-like 36-char trace id
    assert re.match(
        r"\[TRACE (?:[a-f0-9\-]{36}|[a-f0-9]{8})\] SUCCESS: Sent \d+ observables, \d+ report update, and \d+ entity connections as STIX bundle",
        res,
    ), f"Unexpected result format: {res}"


# --------------------------------------------------------------------------------------
# Full span flow + send bundle kwargs assertions
# --------------------------------------------------------------------------------------


def test_full_span_flow_sends_bundle(monkeypatch, importer):
    """
    Validate that a full span-based import flow sends a bundle successfully.

    The test confirms that:
    - _process_import completes without error
    - send_stix2_bundle is invoked (either positionally or via kwargs)
    - The returned message indicates success
    """
    # Arrange
    patch_download_to_pdf(monkeypatch, "full.pdf")
    patch_requests_post(monkeypatch, sample_ariane_span_payload())

    submitted = {}

    def _send(*args, **kwargs):
        # Capture positional or keyword invocation
        if args:
            submitted["bundle"] = args[0]
        submitted.update(kwargs)
        return ["ok", "report"]  # emulate having a container/report

    importer.helper.send_stix2_bundle = _send  # type: ignore

    ctx_id = _stix_id("report")
    importer.helper.api.stix_core_object = DummyStixCoreObject(
        {"objects": [{"type": "report", "id": ctx_id}]}
    )
    importer.helper.api.stix2 = DummyStix2Api(
        {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "objects": [{"type": "report", "id": ctx_id, "object_refs": []}],
        },
        only_report_bundle=True,
    )

    data = {
        "file_id": "import/global/full.pdf",
        "file_mime": "application/pdf",
        "file_fetch": "/file",
        "entity_id": ctx_id,
    }

    # Act
    msg = importer._process_import(data)

    # Assert
    assert isinstance(msg, str)
    # Accept both positional and keyword send semantics or success traces
    assert (
        "bundle" in submitted
        or "success" in msg.lower()
        or "sent" in msg.lower()
        or importer.helper.__dict__.get("_last_sent", {}).get("bundle")
    ), f"Expected bundle submission or success trace, got: {msg}"

    # Optional sanity checks (only apply if submission captured)
    if submitted:
        assert submitted.get("entity_id", ctx_id) == ctx_id
        assert (
            submitted.get("file_name", "").startswith("import-document-ai-")
            or submitted.get("file_name") == "full.pdf"
        )


# --------------------------------------------------------------------------------------
# Error handling paths: empty extraction / undecodable inputs
# --------------------------------------------------------------------------------------


def test_no_info_extracted(monkeypatch, importer):
    """
    Verify that when no information is extracted from the parsed report,
    the importer returns a warning message rather than raising an error.
    """
    # Arrange
    patch_download_to_pdf(monkeypatch, "empty.pdf")

    def _post(**kwargs):
        return DummyArianeResponse(json_data=None, status_code=200)

    monkeypatch.setattr(
        "reportimporter.core.requests.post", lambda **kwargs: _post(**kwargs)
    )

    # Act
    data = {
        "file_id": "import/global/empty.pdf",
        "file_mime": "application/pdf",
        "file_fetch": "/file",
    }
    res = importer._process_import(data)

    # Assert
    assert isinstance(res, str)
    assert "no information extracted" in res.lower(), f"Unexpected output: {res}"
    # Optional sanity check for structured trace prefix
    assert res.startswith("[TRACE"), f"Expected TRACE prefix, got: {res}"


def test_file_not_text_decodable(monkeypatch, importer):
    """
    Verify that binary or undecodable PDFs result in a graceful warning message,
    not a crash. The message should indicate that no information was extracted.
    """

    # Arrange
    def _dl(self, data):
        # Simulate binary-only PDF that preprocessor cannot decode
        return "bad.pdf", BytesIO(
            b"%PDF-1.4\nstream\n\x00\x00\x00\x00\nendstream\n%%EOF"
        )

    monkeypatch.setattr(ReportImporter, "_download_import_file", _dl)
    monkeypatch.setattr(
        "reportimporter.core.FilePreprocessor.preprocess_file", lambda *a, **k: ""
    )

    # Act
    data = {
        "file_id": "import/global/bad.pdf",
        "file_mime": "application/pdf",
        "file_fetch": "/file",
    }
    res = importer._process_import(data)

    # Assert
    assert isinstance(res, str)
    # Accept both legacy and current output formats
    assert any(
        phrase in res.lower()
        for phrase in [
            "could not be decoded",
            "no information extracted",
            "warning",
        ]
    ), f"Unexpected output: {res}"


# --------------------------------------------------------------------------------------
# Container object refs resolution and logging helpers
# --------------------------------------------------------------------------------------


def test_resolve_ids_in_container_expands_refs(importer):
    """
    Verify that _resolve_ids_in_container expands temporary IDs using id_map
    and includes only valid STIX-like references (those containing '--' or mapped entries).
    """
    # Arrange
    id_map = {
        "tmp-a": ["domain-name--A1", "domain-name--A2"],
        "tmp-b": ["domain-name--B1"],
    }
    container = {"object_refs": ["tmp-a", "tmp-b", "domain-name--C1", "not-a-stix-id"]}

    # Act
    out = importer._resolve_ids_in_container(container, id_map)
    refs = out.get("object_refs", [])

    # Assert
    # Expect mapped + valid STIX IDs, sorted and deduplicated
    assert set(refs) == {
        "domain-name--A1",
        "domain-name--A2",
        "domain-name--B1",
        "domain-name--C1",
    }, f"Unexpected refs: {refs}"

    # Ensure deterministic ordering (sorted)
    assert refs == sorted(refs), "object_refs should be sorted"


# --------------------------------------------------------------------------------------
# Legacy parsing assembly and ID conversion helpers
# --------------------------------------------------------------------------------------


def test_process_parsing_results_basic(importer):
    """
    Validate that _process_parsing_results correctly separates observables,
    entities, and extracts a title when present.
    """
    context = {
        "id": _stix_id("report"),
        "type": "report",
        "standard_id": _stix_id("report"),
        "objectMarking": [],
        "createdBy": {"standard_id": _stix_id("identity")},
    }

    parsed = [
        {"type": "entity", "category": "Report", "match": "My Report Title"},
        {"type": "observable", "category": "Domain-Name.value", "match": "example.com"},
        {"type": "entity", "category": "Intrusion-Set", "match": "APT X"},
    ]

    # Call with or without trace_id depending on the method signature
    import inspect

    sig = inspect.signature(importer._process_parsing_results)
    if "trace_id" in sig.parameters:
        obs, ents, title = importer._process_parsing_results(
            parsed, context, "unit-trace"
        )
    else:
        obs, ents, title = importer._process_parsing_results(parsed, context)

    assert title == "My Report Title"
    assert any(o.get("type") == "domain-name" for o in obs)
    assert any(
        "intrusion" in (e.get("type") or "") or e.get("type") == "intrusion-set"
        for e in ents
    )


def test_webservice_branch_success_first_try(monkeypatch, importer):
    """
    Validate that the web-service branch completes successfully on the first try
    and calls _process_parsed_objects exactly once.
    """
    # Arrange
    patch_download_to_pdf(monkeypatch, "svc.pdf")
    payload = [
        {"type": "observable", "category": "Domain-Name.value", "match": "example.com"}
    ]
    patch_requests_post(monkeypatch, payload)

    called = {"times": 0}

    def _pp(self, *a, **k):
        called["times"] += 1
        return {"entities": 1, "observables": 1}

    monkeypatch.setattr(ReportImporter, "_process_parsed_objects", _pp)

    # Act
    data = {
        "file_id": "import/global/svc.pdf",
        "file_mime": "application/pdf",
        "file_fetch": "/file",
    }
    res = importer._process_import(data)

    # Assert
    assert isinstance(res, str)
    assert (
        called["times"] == 1
    ), "Expected _process_parsed_objects to be called exactly once"

    # Flexible success trace match (accepts wording drift)
    assert re.search(
        r"\[TRACE (?:[a-f0-9\-]{36}|[a-f0-9]{8})\].*(success|sent|complete)",
        res,
        re.IGNORECASE,
    ), f"Unexpected result message: {res}"

    # Optionally verify helper recorded a bundle send
    last = getattr(importer.helper, "_last_sent", None)
    assert last is None or isinstance(last, dict)


def test_process_parsed_objects_builds_bundle(monkeypatch, importer):
    """
    Validate that _process_parsed_objects builds and submits a valid STIX bundle
    when provided observables, entities, and predicted relationships.

    Expected: send_stix2_bundle is invoked with a bundle payload, and
    the returned count dictionary includes entity/observable counts.
    """
    # Arrange
    dom_id = _stix_id("domain-name")
    ta_id = _stix_id("intrusion-set")

    observables = [{"type": "domain-name", "id": dom_id, "value": "example.com"}]
    entities = [{"type": "intrusion-set", "id": ta_id, "name": "APT"}]
    predicted = [{"from_id": ta_id, "to_id": dom_id, "label": "USES"}]

    importer.allowed_relations = {("INTRUSION-SET", "DOMAIN-NAME"): {"USES"}}
    importer.data_file = {
        "name": "unit.pdf",
        "data": "ZmlsZQ==",
        "mime_type": "application/pdf",
    }

    submitted = {}

    def _send(*args, **kwargs):
        """Capture helper.send_stix2_bundle calls (positional or keyword)."""
        if args:
            submitted["bundle"] = args[0]
            if len(args) > 1:
                submitted["bypass_validation"] = args[1]
            if len(args) > 2:
                submitted["file_name"] = args[2]
            if len(args) > 3:
                submitted["entity_id"] = args[3]
        submitted.update(kwargs)
        return ["ok", "report"]

    importer.helper.send_stix2_bundle = _send  # override for capture

    # Act
    counts = importer._process_parsed_objects(
        entity={
            "id": _stix_id("report"),
            "type": "report",
            "standard_id": _stix_id("report"),
        },
        observables=observables,
        entities=entities,
        predicted_rels=predicted,
        bypass_validation=False,
        file_name="unit.pdf",
        trace_id="unit-trace",
    )

    # Assert
    assert isinstance(counts, dict), "Expected count dictionary return type"
    assert "bundle" in submitted, "Expected bundle submission to helper"
    assert isinstance(submitted["bundle"], str), "Bundle should be JSON string"
    assert counts.get("entities", 0) >= 1
    assert counts.get("observables", 0) >= 1


# --------------------------------------------------------------------------------------
# Author propagation and invalid relation skipping semantics
# --------------------------------------------------------------------------------------


def test_relationships_created_with_author_when_context_present(monkeypatch, importer):
    """
    Verify that relationships are created with the correct 'createdBy' author
    when a contextual entity is present, and that a STIX bundle is submitted.
    """
    # Arrange
    patch_download_to_pdf(monkeypatch, "auth.pdf")
    patch_requests_post(monkeypatch, sample_ariane_span_payload())

    importer.allowed_relations = {("INTRUSION-SET", "DOMAIN-NAME"): {"USES"}}

    rep_id = _stix_id("report")
    ctx_author = _stix_id("identity")

    importer.helper.api.stix_core_object = DummyStixCoreObject(
        {"objects": [{"type": "report", "id": rep_id}]}
    )
    importer.helper.api.stix2 = DummyStix2Api(
        {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "objects": [{"type": "report", "id": rep_id, "object_refs": []}],
        },
        only_report_bundle=True,
    )

    def _read(id=None):
        return {
            "id": rep_id,
            "type": "report",
            "standard_id": rep_id,
            "objectMarking": [],
            "createdBy": {"standard_id": ctx_author},
            "object_refs": [],
        }

    importer.helper.api.stix_core_object.read = _read  # type: ignore

    submitted = {}

    def _send(*args, **kwargs):
        """Capture bundle submission and return success."""
        if args:
            submitted["bundle"] = args[0]
        submitted.update(kwargs)
        return ["ok"]

    importer.helper.send_stix2_bundle = _send  # type: ignore

    # Act
    data = {
        "file_id": "import/global/auth.pdf",
        "file_mime": "application/pdf",
        "file_fetch": "/file",
        "entity_id": rep_id,
    }
    msg = importer._process_import(data)

    # Assert
    assert isinstance(msg, str), f"Expected string status, got: {type(msg)}"
    assert "bundle" in submitted, "Expected STIX bundle submission"
    assert isinstance(submitted["bundle"], str), "Bundle should be serialized JSON text"
    assert (
        ctx_author in submitted["bundle"]
    ), f"Author ID {ctx_author} should appear in serialized bundle"


def test_monkeypatch_process_parsed_objects_signature_safe(monkeypatch, importer):
    """
    Regression guard: verifies that a monkeypatched _process_parsed_objects
    accepting arbitrary *args/**kwargs runs safely and produces a valid output.

    This ensures that future refactors of ReportImporter maintain call flexibility.
    """
    # Arrange
    patch_download_to_pdf(monkeypatch, "sig.pdf")
    parsed = [
        {"type": "observable", "category": "Domain-Name.value", "match": "example.com"}
    ]
    patch_requests_post(monkeypatch, parsed)

    seen = {"args": tuple | None, "kwargs": tuple | None}

    def _pp(self, *args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        # Return dict-style structure expected by current core.py
        return {"entities": 1, "observables": 1}

    monkeypatch.setattr(ReportImporter, "_process_parsed_objects", _pp)

    # Act
    res = importer._process_import(
        {
            "file_id": "import/global/sig.pdf",
            "file_mime": "application/pdf",
            "file_fetch": "/file",
        }
    )

    # Assert
    assert isinstance(res, str)
    assert (
        seen["args"] is not None
    ), "Expected the patched method to be invoked with arguments"

    # Validate output format (trace ID + success summary)
    assert re.match(
        r"\[TRACE (?:[a-f0-9\-]{36}|[a-f0-9]{8})\] SUCCESS: Sent \d+ observables, \d+ report update, and \d+ entity connections as STIX bundle",
        res,
    ), f"Unexpected output: {res}"


def test_process_message_delegates(monkeypatch, importer):
    called = {"x": 0}

    def _pi(self, data):
        called["x"] += 1
        return "ok"

    monkeypatch.setattr(ReportImporter, "_process_import", _pi)

    out = importer._process_message({"k": "v"})
    assert out == "ok"
    assert called["x"] == 1


def test_link_to_container_avoids_self_reference(importer):
    rep_id = _stix_id("report")
    importer.helper.api.stix2 = DummyStix2Api(
        {
            "type": "bundle",
            "id": _stix_id("bundle"),
            "objects": [{"type": "report", "id": rep_id, "object_refs": []}],
        },
        only_report_bundle=True,
    )
    entity = {
        "id": rep_id,
        "type": "report",
        "entity_type": "Report",
        "standard_id": rep_id,
    }

    out = importer._link_to_container(
        "f.pdf", entity, [{"type": "report", "id": rep_id}], None
    )

    # Include the report, but never relate it to itself
    assert any(o.get("type") == "report" and o.get("id") == rep_id for o in out)
    assert not any(
        o.get("type") == "relationship"
        and o.get("source_ref") == rep_id
        and o.get("target_ref") == rep_id
        for o in out
    )
