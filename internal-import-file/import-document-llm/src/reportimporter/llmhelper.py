"""
Helper class for interacting with LLM providers for parsing.

This implementation is fully synchronous and safe for single-threaded
OpenCTI connector execution.

Public methods:
    - count_tokens(text)
    - build_hints_and_chunks(source_text)
    - extract_relations(source_text)
"""

from __future__ import annotations

import json
import os
import random
import re
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import ijson
import tiktoken
from openai import AzureOpenAI
from openai import OpenAI as OpenAIClient
from reportimporter.regex_scanner import (
    OBSERVABLE_LABELS,
)
from reportimporter.regex_scanner import Span as RegexSpan
from reportimporter.regex_scanner import (
    _short_hash,
    build_hints_from_spans,
    normalize_stix_value,
    scan_structured_iocs,
)
from reportimporter.textnorm import (
    TransformMap,
    compact_whitespace,
    refang_targeted,
    unwrap_soft_wraps,
)

from ._nulls import _NullHelper

try:
    from ollama import Client as OllamaClient
except Exception:  # pragma: no cover - optional dependency at runtime
    OllamaClient = None

# Default to a null helper until set_helper() is called
_helper = _NullHelper()
_OBSERVABLE_LABELS_BY_CASEFOLD = {
    label.casefold(): label for label in OBSERVABLE_LABELS
}


def set_helper(helper):
    """Inject the real OpenCTI connector helper globally."""
    global _helper  # pylint: disable=global-statement
    _helper = helper


class TokenEncoder:
    """Deterministic token encoder wrapper.

    Uses tiktoken when available; otherwise a deterministic char-based fallback
    (fixed chars per token). The fallback returns string "tokens" (substrings).
    """

    def __init__(
        self,
        model: str,
        *,
        provider: str | None = None,
        chars_per_token: int = 3,
    ):
        self._chars = int(chars_per_token)
        self._type = "char"
        self._enc = None

        # Non-OpenAI model names (for example Ollama models like gemma4)
        # are not present in tiktoken's model registry. Use a stable base
        # encoding without surfacing this expected path as a warning.
        if str(provider or "").strip().lower() == "ollama":
            try:
                self._enc = tiktoken.get_encoding("cl100k_base")
                self._type = "tiktoken"
                _helper.connector_logger.debug(
                    f"Using cl100k_base tokenizer for Ollama model {model}"
                )
                return
            except Exception:
                self._type = "char"
                _helper.connector_logger.warning(
                    f"Failed to initialize tokenizer for Ollama model {model}; "
                    f"{self._chars}c/token char-fallback"
                )
                return

        try:
            enc = tiktoken.encoding_for_model(model)
            self._type = "tiktoken"
            self._enc = enc
        except Exception:
            # Map to base encodings by family
            base = None
            m = (model or "").lower()
            if any(k in m for k in ("gpt-4o", "o1", "o200k")):
                base = "o200k_base"
            else:
                base = "cl100k_base"
            try:
                enc = tiktoken.get_encoding(base)
                self._type = "tiktoken"
                self._enc = enc
                _helper.connector_logger.debug(
                    f"tiktoken.encoding_for_model({model}) failed; using {base}"
                )
            except Exception:
                # keep char fallback
                self._type = "char"
                _helper.connector_logger.warning(
                    f"Failed to initialize tiktoken for {model}; "
                    f"{self._chars}c/token char-fallback"
                )

    def encode(self, text: str):
        if self._type == "tiktoken" and self._enc is not None:
            return self._enc.encode(text)
        if not text:
            return []
        return [text[i : i + self._chars] for i in range(0, len(text), self._chars)]

    def decode(self, tokens: Sequence[Any]) -> str:
        if self._type == "tiktoken" and self._enc is not None:
            return self._enc.decode(tokens)
        return "".join(tokens)

    def count(self, text: str) -> int:
        if self._type == "tiktoken" and self._enc is not None:
            return len(self._enc.encode(text))
        return (len(text) + self._chars - 1) // self._chars  # ceil division

    def is_tiktoken(self) -> bool:
        return self._type == "tiktoken" and self._enc is not None

    def get_encoder(self):
        return self._enc if self._type == "tiktoken" else None


# Tunables
MAX_RETRIES: int = 3
BACKOFF_BASE: int = 2
SAFETY_MARGIN_RATIO = 0.05
CHUNK_OVERLAP_RATIO = 0.10
COMPLETION_RESERVE_RATIO = 0.20
MAX_CONTINUATIONS = 3
PREFERRED_RELATION_LABELS: tuple[str, ...] = (
    "USES",
    "TARGETS",
    "ATTRIBUTED-TO",
    "AUTHORED-BY",
    "ORIGINATES-FROM",
    "LOCATED-AT",
    "RESOLVES-TO",
    "BELONGS-TO",
    "COMMUNICATES-WITH",
    "CONSISTS-OF",
    "HOSTS",
    "RELATED-TO",
)


class LLMHelper:
    """
    Helper class for interacting with OpenAI/Azure OpenAI/Ollama for parsing.

    Public methods:
        - count_tokens(text)
        - build_hints_and_chunks(source_text)
        - extract_relations(source_text)
    """

    # Prompt location / cache
    _PROMPT_CACHE: dict[str, str] = {}
    _SYSTEM_PROMPT: Optional[str] = None
    _DEFAULT_PROMPT_PATH = (
        Path(__file__).resolve().parent / "prompts" / "system_prompt_relations.md"
    )
    _ENV_PROMPT_PATH = "REPORTIMPORTER_SYSTEM_PROMPT"
    _SUPPORTED_EXTS = (".md", ".markdown", ".json", ".txt")

    @staticmethod
    def _norm_label(lbl: str) -> str:
        """Normalize labels by stripping whitespace safely."""
        return str(lbl or "").strip()

    @classmethod
    def _load_prompt_from_disk(cls, path: Path) -> str:
        if not path.exists():
            raise FileNotFoundError(f"Prompt file not found: {path}")
        if path.suffix.lower() == ".json":
            with path.open(encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and "content" in data:
                content = data["content"]
                if isinstance(content, list):
                    return "\n".join(str(x) for x in content)
                return str(content)
            if isinstance(data, str):
                return data
            raise ValueError(f"Invalid JSON prompt format in {path}")
        return path.read_text(encoding="utf-8")

    @classmethod
    def _resolve_prompt_path(cls, prompt_path: Optional[str]) -> Path:
        if prompt_path:
            p = Path(prompt_path)
            return p if p.is_absolute() else Path.cwd() / p
        env_path = os.getenv(cls._ENV_PROMPT_PATH)
        if env_path:
            p = Path(env_path)
            return p if p.is_absolute() else Path.cwd() / p
        return cls._DEFAULT_PROMPT_PATH

    @classmethod
    def _ensure_system_prompt_loaded(cls, prompt_path: Optional[str] = None) -> str:
        if cls._SYSTEM_PROMPT is not None:
            return cls._SYSTEM_PROMPT
        path = cls._resolve_prompt_path(prompt_path)
        cache_key = str(path.resolve())
        if cache_key in cls._PROMPT_CACHE:
            cls._SYSTEM_PROMPT = cls._PROMPT_CACHE[cache_key]
            _helper.connector_logger.debug(
                f"Loaded system prompt from cache: {cache_key}"
            )
            return cls._SYSTEM_PROMPT
        try:
            prompt_text = cls._load_prompt_from_disk(path)
            cls._PROMPT_CACHE[cache_key] = prompt_text
            cls._SYSTEM_PROMPT = prompt_text
            _helper.connector_logger.info(f"Loaded system prompt: {cache_key}")
            return cls._SYSTEM_PROMPT
        except Exception as e:
            fallback = (
                "You are a cyber-threat intelligence extractor. Emit newline-delimited JSON lines for spans and relationships. "
                "Use the schema: span lines include id, type (entity|observable), label, value, start_offset, end_offset; "
                "relationship lines include type, label, from_id, to_id. "
                "Reuse hint ids/labels/types exactly. Only emit relations that are clearly supported by the text and allowed by OpenCTI. "
                "Observable-to-observable relations may be emitted when explicitly present in the text. "
                "Attack-Pattern IDs are usually the target of USES relations from threat actors, intrusion sets, campaigns, or incidents."
            )
            cls._SYSTEM_PROMPT = fallback
            _helper.connector_logger.error(
                f"Failed to load system prompt ({path}): {e}. Using fallback."
            )
            return cls._SYSTEM_PROMPT

    def __init__(
        self,
        config: Any,
        opencti_connector_helper: Optional[Any] = None,
        allowed_relations: Optional[dict[tuple[str, str], set[str]]] = None,
    ):
        self.config = config
        self.use_azure = bool(getattr(config, "is_azure_openai", False))
        self.use_ollama = bool(getattr(config, "is_ollama", False))
        self.api_key = getattr(config, "openai_key", None)
        self.endpoint = getattr(config, "openai_endpoint", None)
        self.deployment = getattr(config, "openai_deployment", None)
        self.api_version = getattr(config, "openai_api_version", None)
        self.provider = getattr(config, "ai_provider", None)
        self.model = getattr(config, "ai_model", "gpt-4o")
        self.ollama_host = getattr(config, "ollama_host", "http://localhost:11434")
        self.ollama_pull_on_start = bool(getattr(config, "ollama_pull_on_start", False))
        ollama_pull_timeout_s = getattr(config, "ollama_pull_timeout_s", 600)
        if ollama_pull_timeout_s is None:
            ollama_pull_timeout_s = 600
        self.ollama_pull_timeout_s = int(ollama_pull_timeout_s)
        self.model_input_ratio = getattr(config, "model_input_ratio", 0.3)
        self.trace_enabled = bool(getattr(config, "trace_enabled", False))
        self.allowed_relations = allowed_relations or {}

        self.max_model_tokens = getattr(config, "manual_context_window", None)
        self._fallback_max_model_tokens = getattr(config, "max_model_tokens", None)
        self.context_window_source = "unknown"

        # Clients
        if self.use_ollama:
            if OllamaClient is None:
                raise RuntimeError(
                    "Ollama provider selected but ollama package is not installed"
                )
            self.client = OllamaClient(host=self.ollama_host)
            self.model_name = self.model
            self._init_ollama_model()
        elif self.use_azure:
            self.client = AzureOpenAI(
                api_key=self.api_key,
                azure_endpoint=self.endpoint,
                api_version=self.api_version,
            )
            self.model_name = self.deployment
        else:
            self.client = OpenAIClient(api_key=self.api_key)
            self.model_name = self.model

        if self.max_model_tokens is not None:
            self.context_window_source = "manual"

        if self.max_model_tokens is None:
            discovered = self._discover_provider_context_window()
            if discovered:
                self.max_model_tokens = discovered
                self.context_window_source = "provider-discovery"

        if self.max_model_tokens is None:
            self.max_model_tokens = self._fallback_max_model_tokens
            if self.max_model_tokens is not None:
                self.context_window_source = "configured-fallback"

        if self.max_model_tokens is None:
            model_limits = {
                "gpt-4o": 16384,
                "gpt-4o-mini": 8192,
                "gpt-4": 8192,
                "gpt-4-32k": 32768,
                "gpt-3.5-turbo": 4096,
                "gpt-3.5-turbo-16k": 16384,
            }
            self.max_model_tokens = model_limits.get(self.model, 4096)
            self.context_window_source = "static-model-default"

        try:
            self.max_model_tokens = int(self.max_model_tokens)
        except Exception as err:
            raise ValueError(
                f"Invalid max_model_tokens value: {self.max_model_tokens}"
            ) from err
        if self.max_model_tokens < 512:
            raise ValueError(
                f"max_model_tokens too small ({self.max_model_tokens}); must be >= 512"
            )

        if opencti_connector_helper:
            set_helper(opencti_connector_helper)

        self.safety_margin = int(self.max_model_tokens * SAFETY_MARGIN_RATIO)
        _helper.connector_logger.debug(
            f"LLMHelper configured provider={self.provider}, "
            f"model={self.model}, deployment={self.deployment}, "
            f"use_azure={self.use_azure}, trace_enabled={self.trace_enabled}"
        )

        self._subchunk_counts: List[int] = []
        self._continuations_used: int = 0

        self.rpm: Optional[int] = getattr(
            config, "llm_rpm", getattr(config, "openai_rpm", None)
        )
        try:
            if isinstance(self.rpm, str):
                self.rpm = int(self.rpm)
        except Exception:
            self.rpm = None
        self._rpm_window: deque[float] = deque()

        # Prompt
        self.prompt_path = getattr(config, "prompt_path", None)
        self.system_prompt = self._ensure_system_prompt_loaded(self.prompt_path)
        self.relation_guidance = self._build_relation_guidance()

        # Tokenizer
        self.enc = TokenEncoder(self.model, provider=self.provider)

        # System token count (best-effort)
        try:
            self.system_tokens = self.count_tokens(self.system_prompt)
        except Exception:
            self.system_tokens = 0
            _helper.connector_logger.debug(
                "Could not count tokens for system prompt; defaulting to 0."
            )

        # Budgets
        self.max_token_budget = (
            self.max_model_tokens - self.system_tokens - self.safety_margin
        )
        if self.max_token_budget <= self.safety_margin:
            raise ValueError("System prompt too large for model capacity")
        self.chunk_token_limit = int(self.max_token_budget * self.model_input_ratio)
        if self.chunk_token_limit < 1:
            raise ValueError("Chunk token limit too small")
        _helper.connector_logger.info(
            "Token budgeting: "
            f"context_window={self.max_model_tokens} "
            f"source={self.context_window_source} "
            f"system_tokens={self.system_tokens} "
            f"safety_margin={self.safety_margin} "
            f"max_token_budget={self.max_token_budget} "
            f"chunk_token_limit={self.chunk_token_limit} "
            f"input_ratio={self.model_input_ratio}"
        )

    def _init_ollama_model(self) -> None:
        if not self.use_ollama:
            return
        if self.ollama_pull_on_start:
            _helper.connector_logger.info(
                f"Pulling Ollama model at startup: {self.model}"
            )
            result: dict[str, Any] = {}

            def _pull() -> None:
                try:
                    result["value"] = self.client.pull(self.model)
                except Exception as err:  # pragma: no cover - network/runtime dependent
                    result["error"] = err

            thread = threading.Thread(target=_pull, daemon=True)
            thread.start()
            thread.join(timeout=self.ollama_pull_timeout_s)
            if thread.is_alive():
                raise TimeoutError(
                    f"Timed out pulling Ollama model {self.model} after {self.ollama_pull_timeout_s}s"
                )
            if result.get("error"):
                raise RuntimeError(
                    f"Failed to pull Ollama model {self.model}: {result['error']}"
                )

    @staticmethod
    def _parse_ollama_parameters_ctx(parameters: Any) -> Optional[int]:
        """Extract num_ctx from Ollama `parameters`, which may be a dict or text."""
        if isinstance(parameters, dict):
            raw = parameters.get("num_ctx") or parameters.get("context_length")
            if raw:
                return int(raw)
            return None
        if isinstance(parameters, str):
            for pattern in (
                r"(?:^|\n)\s*num_ctx\s+(\d+)\b",
                r"(?:^|\n)\s*context_length\s+(\d+)\b",
            ):
                match = re.search(pattern, parameters, flags=re.IGNORECASE)
                if match:
                    return int(match.group(1))
        return None

    def _discover_provider_context_window(self) -> Optional[int]:
        if not self.use_ollama:
            return None
        try:
            info = self.client.show(self.model)
            raw_ctx = self._parse_ollama_parameters_ctx(info.get("parameters"))
            if raw_ctx:
                discovered = int(raw_ctx)
                _helper.connector_logger.info(
                    f"Detected Ollama context window from parameters: {discovered}"
                )
                return discovered

            model_info = info.get("model_info") or {}
            for key in (
                "llama.context_length",
                "context_length",
                "num_ctx",
                "max_context_length",
            ):
                raw = model_info.get(key)
                if raw:
                    discovered = int(raw)
                    _helper.connector_logger.info(
                        f"Detected Ollama context window from metadata: {discovered}"
                    )
                    return discovered
        except Exception as err:
            _helper.connector_logger.warning(
                f"Unable to discover Ollama context window for {self.model}: {err}"
            )
        return None

    def _build_relation_guidance(self) -> str:
        """Build compact relation guidance from the current OpenCTI schema mapping."""
        if not self.allowed_relations:
            return (
                "Prefer high-confidence OpenCTI relations such as USES, TARGETS, "
                "ATTRIBUTED-TO, AUTHORED-BY, ORIGINATES-FROM, LOCATED-AT, "
                "RESOLVES-TO, BELONGS-TO, COMMUNICATES-WITH, CONSISTS-OF, HOSTS, and RELATED-TO."
            )

        preferred_rels = set(PREFERRED_RELATION_LABELS)
        supported_types = {
            "ATTACK-PATTERN",
            "AUTONOMOUS-SYSTEM",
            "CAMPAIGN",
            "CITY",
            "COUNTRY",
            "DOMAIN-NAME",
            "EMAIL-ADDR",
            "FILE",
            "INCIDENT",
            "INDIVIDUAL",
            "INFRASTRUCTURE",
            "INTRUSION-SET",
            "IPV4-ADDR",
            "IPV6-ADDR",
            "LOCATION",
            "MALWARE",
            "ORGANIZATION",
            "REGION",
            "SECTOR",
            "THREAT-ACTOR",
            "THREAT-ACTOR-GROUP",
            "THREAT-ACTOR-INDIVIDUAL",
            "TOOL",
            "URL",
            "VULNERABILITY",
        }

        # Build compact examples for prompt efficiency.
        buckets: dict[str, list[str]] = {r: [] for r in preferred_rels}
        for (src, tgt), rels in sorted(self.allowed_relations.items()):
            if src not in supported_types or tgt not in supported_types:
                continue
            for rel in sorted(r for r in rels if r in preferred_rels):
                example = f"{src} -> {tgt}: {rel}"
                if len(buckets[rel]) < 1 and example not in buckets[rel]:
                    buckets[rel].append(example)

        examples: list[str] = []
        for rel in sorted(preferred_rels):
            if buckets[rel]:
                examples.append(buckets[rel][0])
            if len(examples) >= 12:
                break

        if not examples:
            return (
                "Prefer only relations that clearly map to the active OpenCTI schema. "
                "When uncertain, emit spans without a relation."
            )
        allowed_labels = sorted(rel for rel, vals in buckets.items() if vals)
        lines = ["Active OpenCTI relation labels: " + ", ".join(allowed_labels)]
        if examples:
            lines.append("Active OpenCTI relation examples:")
        lines.extend(f"- {example}" for example in examples)
        return "\n".join(lines)

    def count_tokens(self, text: str) -> int:
        return self.enc.count(text)

    @staticmethod
    def _coerce_source_text(source_text: Any) -> str:
        """Coerce a source payload into a best-effort text string."""
        if hasattr(source_text, "read"):
            try:
                data = source_text.read()
                if isinstance(data, bytes):
                    try:
                        return data.decode("utf-8")
                    except Exception:
                        return data.decode("latin-1", errors="ignore")
                return str(data)
            except Exception:
                return ""
        if isinstance(source_text, (bytes, bytearray)):
            try:
                return source_text.decode("utf-8")
            except Exception:
                return source_text.decode("latin-1", errors="ignore")
        return str(source_text or "")

    def regex_only_extract(self, source_text: Any) -> Dict[str, Any]:
        """Build a span-only payload directly from regex hints without any LLM call."""
        text = self._coerce_source_text(source_text)
        if not text:
            return {"metadata": {"span_based_entities": []}, "relations": []}
        cleaned, _, spans = self._preprocess_for_hints(text)
        hints = build_hints_from_spans(spans).get("hints", [])
        entities: list[dict[str, Any]] = []
        for hint in hints:
            entry = {
                "id": hint.get("id"),
                "text": str(hint.get("value") or "").strip(),
                "label": hint.get("category"),
                "type": hint.get("type"),
            }
            if hint.get("positions"):
                entry["positions"] = list(hint["positions"])
            entities.append(entry)
        return {
            "metadata": {
                "span_based_entities": entities,
                "regex_only": True,
                "cleaned_length": len(cleaned),
            },
            "relations": [],
        }

    def _cti_signal_score(self, text: str) -> int:
        lowered = (text or "").lower()
        keywords = (
            "apt",
            "threat actor",
            "intrusion set",
            "campaign",
            "malware",
            "ransomware",
            "phishing",
            "c2",
            "command and control",
            "infrastructure",
            "ioc",
            "indicator",
            "exploit",
            "vulnerability",
            "payload",
            "backdoor",
            "botnet",
            "victim",
            "targeted",
            "attributed",
            "observed",
            "ttp",
        )
        return sum(1 for kw in keywords if kw in lowered)

    def _looks_like_junk(self, text: str) -> bool:
        lowered = (text or "").lower()
        if not lowered.strip():
            return True
        junk_patterns = (
            r"\b(sign in|log in|login|password|forgot password|remember me)\b",
            r"\b(index of /|parent directory|last modified|directory listing)\b",
            r"\b(enable javascript|accept cookies|privacy policy|terms of service)\b",
            r"\b(404 not found|403 forbidden|access denied|internal server error)\b",
        )
        return any(re.search(pattern, lowered) for pattern in junk_patterns)

    def triage_document(
        self, source_text: Any, mime_type: str = "", file_name: str = ""
    ) -> Dict[str, Any]:
        """Cheap document triage to minimize unnecessary LLM calls."""
        text = self._coerce_source_text(source_text)
        cleaned, _, spans = self._preprocess_for_hints(text)
        hints = build_hints_from_spans(spans).get("hints", [])
        hint_count = len(hints)
        observable_hint_count = sum(
            1 for hint in hints if str(hint.get("type")) == "observable"
        )
        cleaned_len = len(cleaned.strip())
        cti_score = self._cti_signal_score(cleaned)
        looks_junk = self._looks_like_junk(cleaned)
        lower_mime = (mime_type or "").lower()
        lower_name = (file_name or "").lower()

        if (
            (lower_mime == "application/pdf" or lower_name.endswith(".pdf"))
            and getattr(self.config, "pdf_ocr_enabled", False)
            and cleaned_len < 120
            and hint_count == 0
        ):
            return {
                "mode": "OCR_THEN_RECHECK",
                "reason": "pdf-text-too-short",
                "hint_count": hint_count,
                "cti_score": cti_score,
            }

        if cleaned_len < 40 and hint_count == 0:
            return {
                "mode": "DROP",
                "reason": "document-too-short",
                "hint_count": hint_count,
                "cti_score": cti_score,
            }

        if looks_junk and hint_count < 3 and cti_score < 2:
            return {
                "mode": "DROP",
                "reason": "junk-page-heuristic",
                "hint_count": hint_count,
                "cti_score": cti_score,
            }

        if hint_count == 0 and cti_score >= 2 and cleaned_len >= 300:
            return {
                "mode": "LLM_EXTRACT",
                "reason": "narrative-report-signals",
                "hint_count": hint_count,
                "cti_score": cti_score,
            }

        if hint_count > 0 and observable_hint_count == hint_count and cti_score < 2:
            return {
                "mode": "REGEX_ONLY",
                "reason": "structured-observables-only",
                "hint_count": hint_count,
                "cti_score": cti_score,
            }

        if hint_count >= 4 or cti_score >= 2 or (hint_count >= 1 and cti_score >= 1):
            return {
                "mode": "LLM_EXTRACT",
                "reason": "cti-signals-present",
                "hint_count": hint_count,
                "cti_score": cti_score,
            }

        if hint_count > 0:
            return {
                "mode": "REGEX_ONLY",
                "reason": "low-context-structured-iocs",
                "hint_count": hint_count,
                "cti_score": cti_score,
            }

        return {
            "mode": "DROP",
            "reason": "insufficient-signal",
            "hint_count": hint_count,
            "cti_score": cti_score,
        }

    # ---------------- Hints + Spans (Regex pre-scan) -----------------
    def _preprocess_for_hints(
        self, source_text: str
    ) -> tuple[str, TransformMap, List[RegexSpan]]:
        unwrapped, tm1 = unwrap_soft_wraps(source_text)
        refanged, tm2 = refang_targeted(unwrapped, base_map=tm1)
        cleaned, tm3 = compact_whitespace(refanged, base_map=tm2)
        spans = scan_structured_iocs(cleaned)
        return cleaned, tm3, spans

    def _chunk_text_with_offsets(self, text: str) -> List[tuple[int, int, str]]:
        if self.enc and self.enc.is_tiktoken():
            enc = self.enc.get_encoder()  # type: ignore
            tokens = enc.encode(text)
            limit = self.chunk_token_limit
            overlap = max(0, int(limit * CHUNK_OVERLAP_RATIO))
            stride = max(1, limit - overlap)
            chunks: List[tuple[int, int, str]] = []
            start_tok = 0
            start_char = 0
            n = len(tokens)
            while start_tok < n:
                end_tok = min(n, start_tok + limit)
                frag = enc.decode(tokens[start_tok:end_tok])
                end_char = start_char + len(frag)
                if frag.strip():
                    chunks.append((start_char, end_char, frag))
                if end_tok >= n:
                    break
                adv_end = min(n, start_tok + stride)
                adv_text = enc.decode(tokens[start_tok:adv_end])
                start_char += len(adv_text)
                start_tok += stride
            return chunks

        # char fallback
        chunk_chars = self.chunk_token_limit * 3
        overlap = int(chunk_chars * CHUNK_OVERLAP_RATIO)
        stride = max(1, chunk_chars - overlap)
        chunks: List[tuple[int, int, str]] = []
        for start in range(0, max(1, len(text) - chunk_chars + 1), stride):
            frag = text[start : start + chunk_chars]
            if frag.strip():
                chunks.append((start, start + len(frag), frag))
        if len(text) % stride:
            frag = text[-chunk_chars:]
            if frag.strip():
                chunks.append((max(0, len(text) - chunk_chars), len(text), frag))
        return chunks

    def build_hints_and_chunks(self, source_text: str) -> List[Dict[str, Any]]:
        if not source_text:
            return []
        cleaned, _, spans = self._preprocess_for_hints(source_text)
        global_hints = build_hints_from_spans(spans).get("hints", [])

        # Budget params
        hard_limit = self.max_model_tokens - self.safety_margin
        reserve_for_completion = int(self.max_model_tokens * COMPLETION_RESERVE_RATIO)
        target_prompt_max = max(1, hard_limit - reserve_for_completion)

        # Tokenize cleaned for chunking
        enc = self.enc.get_encoder() if self.enc.is_tiktoken() else None
        tokens = enc.encode(cleaned) if enc else self.enc.encode(cleaned)
        n = len(tokens)
        limit = self.chunk_token_limit
        overlap = max(0, int(limit * CHUNK_OVERLAP_RATIO))

        start_tok = 0
        start_char = 0
        out: List[Dict[str, Any]] = []
        total_hints = 0

        def decode_slice(a: int, b: int) -> str:
            return enc.decode(tokens[a:b]) if enc else self.enc.decode(tokens[a:b])

        def count_for(
            hints_subset: List[dict], text_slice: str, abs_start: int, abs_end: int
        ) -> int:
            user = self._build_user_content(
                hints_subset, abs_start, abs_end, text_slice
            )
            return self._count_message_tokens(
                [
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": user},
                ]
            )

        def select_hints(chunk_start: int, chunk_end: int) -> List[Dict[str, Any]]:
            selected: List[Dict[str, Any]] = []
            for h in global_hints:
                poss = h.get("positions", []) or []
                rel_pos: List[Dict[str, int]] = []
                for p in poss:
                    ps = int(p.get("start", 0))
                    pe = int(p.get("end", 0))
                    if pe <= chunk_start or ps >= chunk_end:
                        continue
                    rs = max(0, ps - chunk_start)
                    re = max(0, min(pe, chunk_end) - chunk_start)
                    if re > rs:
                        rel_pos.append({"start": rs, "end": re})
                if not rel_pos:
                    continue
                selected.append(
                    {
                        "id": h["id"],
                        "type": h.get("type", "observable"),
                        "category": h.get("category"),
                        "value": h.get("value", ""),
                        "positions": sorted(rel_pos, key=lambda x: x["start"]),
                    }
                )
            selected.sort(key=lambda hh: hh["positions"][0]["start"])
            return selected

        while start_tok < n:
            end_tok = min(n, start_tok + limit)
            frag = decode_slice(start_tok, end_tok)
            end_char = start_char + len(frag)
            local = select_hints(start_char, end_char)

            used = count_for(local, frag, start_char, end_char)
            if used > target_prompt_max:
                lo_tok = start_tok + 1
                hi_tok = end_tok
                best_tok = None
                while lo_tok <= hi_tok:
                    mid_tok = (lo_tok + hi_tok) // 2
                    frag_mid = decode_slice(start_tok, mid_tok)
                    mid_end_char = start_char + len(frag_mid)
                    local_mid = select_hints(start_char, mid_end_char)
                    used_mid = count_for(local_mid, frag_mid, start_char, mid_end_char)
                    if used_mid <= target_prompt_max:
                        best_tok = (mid_tok, frag_mid, local_mid, mid_end_char)
                        lo_tok = mid_tok + 1
                    else:
                        hi_tok = mid_tok - 1
                if best_tok is not None:
                    end_tok, frag, local, end_char = best_tok
                else:
                    end_tok = min(n, start_tok + 1)
                    frag = decode_slice(start_tok, end_tok)
                    end_char = start_char + len(frag)
                    local = []

            out.append(
                {"text": frag, "start": start_char, "end": end_char, "hints": local}
            )
            total_hints += len(local)

            if end_tok >= n:
                break
            next_start_tok = min(n, end_tok - overlap)
            if next_start_tok <= start_tok:
                next_start_tok = min(n, start_tok + 1)
            adv_text = decode_slice(start_tok, next_start_tok)
            start_char += len(adv_text)
            start_tok = next_start_tok

        _helper.connector_logger.debug(
            f"Prepared {len(out)} chunks; total hints={total_hints}; "
            + ", ".join(
                f"chunk#{i+1}:hints={len(c.get('hints', []) or [])}"
                for i, c in enumerate(out)
            )
        )
        return out

    def _call_model_relations(self, chunk: Dict[str, Any], i: int) -> Dict[str, Any]:
        user_content = self._build_user_content(
            chunk.get("hints", []),
            chunk.get("start"),
            chunk.get("end"),
            chunk.get("text", ""),
        )
        chunk_text = chunk.get("text", "") or ""
        hint_list = chunk.get("hints", []) or []
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": user_content},
        ]
        try:
            prompt_tokens_est = self._count_message_tokens(messages)
        except Exception:
            prompt_tokens_est = "?"
        _helper.connector_logger.debug(
            f"Chunk {i} input stats: chars={len(chunk_text)} hints={len(hint_list)} "
            f"prompt_tokens_est={prompt_tokens_est} start={chunk.get('start')} end={chunk.get('end')}"
        )
        if self.trace_enabled:
            _helper.connector_logger.debug(f"Trace chunk {i} prompt:\n{user_content}")
            if hint_list:
                try:
                    _helper.connector_logger.debug(
                        f"Trace chunk {i} hints:\n{json.dumps(hint_list, ensure_ascii=False, indent=2)}"
                    )
                except Exception:
                    pass

        content = self.call_openai(messages, i + 1)
        if not content:
            return {"metadata": {"span_based_entities": []}, "relations": []}
        if self.trace_enabled:
            _helper.connector_logger.debug(f"Trace chunk {i} raw response:\n{content}")

        items = self._parse_ndjson_any(content)

        # --- reconcile mutated hints (LLM sometimes munges them) ---
        hints = chunk.get("hints", []) or []
        hint_lookup = {
            str(h.get("id")): h for h in hints if isinstance(h.get("id"), str)
        }
        restored = []
        for obj in items:
            obj_id = obj.get("id")
            if obj_id and obj_id in hint_lookup:
                hint = hint_lookup[obj_id]
                # restore authoritative fields from hint
                for key in ("type", "label", "value", "category"):
                    if key in hint:
                        obj[key] = hint[key]
            restored.append(obj)
        items = restored

        # Map from (category, normalized(value)) -> hint_id
        hint_map: dict[tuple[str, str], str] = {}
        for h in hints:
            try:
                cat = str(h.get("category", "")).strip()
                val = str(h.get("value", "")).strip()
                norm = normalize_stix_value(cat, val)
                hint_map[(cat, norm)] = str(h.get("id"))
            except Exception:
                continue

        spans_out: List[dict] = []
        relations_out: List[dict] = []
        base_start = int(chunk.get("start", 0) or 0)

        def _canonicalize_observable_label(label: str) -> str:
            return _OBSERVABLE_LABELS_BY_CASEFOLD.get(label.casefold(), label)

        def _infer_role(label: str) -> str:
            # Classify against the shared observable set so dotted *entity*
            # categories (e.g. Attack-Pattern.x_mitre_id, Vulnerability.name) are
            # not mistaken for observables the way a bare "." check would be.
            return (
                "observable"
                if (label or "").casefold() in _OBSERVABLE_LABELS_BY_CASEFOLD
                else "entity"
            )

        for obj in items:
            if not isinstance(obj, dict):
                continue

            # Relationship line
            try:
                rtype = str(obj.get("type") or "").strip()
                label = str(obj.get("label") or "").strip()
                fid = obj.get("from_id")
                tid = obj.get("to_id")
                if rtype.lower() == "relationship" and label and fid and tid:
                    relations_out.append(
                        {
                            "type": "relationship",
                            "label": label.upper(),
                            "from_id": fid,
                            "to_id": tid,
                        }
                    )
                    continue
            except Exception:
                pass

            # Span line (accept multiple key variants)
            label = str(obj.get("label") or obj.get("category") or "").strip()
            value = str(
                obj.get("value") or obj.get("text") or obj.get("match") or ""
            ).strip()
            if not label or not value:
                continue
            label = _canonicalize_observable_label(label)

            role = str(obj.get("type") or _infer_role(label)).strip()
            try:
                norm = normalize_stix_value(label, value)
            except Exception:
                norm = value
            hint_id = hint_map.get((label, norm))
            sid = str(
                obj.get("id") or hint_id or f"llm::{role}::{label}::{norm}".lower()
            )

            pos_list = []
            try:
                s0 = int(obj.get("start_offset"))
                e0 = int(obj.get("end_offset"))
                if e0 >= s0:
                    pos_list = [{"start": base_start + s0, "end": base_start + e0}]
            except Exception:
                pass

            span = {"id": sid, "text": value, "label": label, "type": role}
            if pos_list:
                span["positions"] = pos_list
            spans_out.append(span)

        return {
            "metadata": {"span_based_entities": spans_out},
            "relations": relations_out,
        }

    def openai_extract_relations(self, source_text: Any) -> Dict[str, Any]:
        source_text = self._coerce_source_text(source_text)

        self._subchunk_counts = []
        self._continuations_used = 0

        regex_payload = self.regex_only_extract(source_text)
        chunks = self.build_hints_and_chunks(source_text)
        if not chunks:
            return regex_payload

        pos_index: dict[str, set[tuple[int, int]]] = {}
        for span in regex_payload.get("metadata", {}).get("span_based_entities", []):
            sid = span.get("id")
            if not isinstance(sid, str):
                continue
            for p in span.get("positions", []) or []:
                try:
                    pos_index.setdefault(sid, set()).add(
                        (int(p.get("start", 0)), int(p.get("end", 0)))
                    )
                except Exception:
                    continue

        for ch in chunks:
            s0 = int(ch.get("start", 0) or 0)
            for h in ch.get("hints", []) or []:
                sid = h.get("id")
                if not isinstance(sid, str):
                    continue
                for p in h.get("positions", []) or []:
                    try:
                        hs = int(p.get("start", 0) or 0)
                        he = int(p.get("end", 0) or 0)
                        abs_s = max(0, s0 + hs)
                        abs_e = max(abs_s, s0 + he)
                        pos_index.setdefault(sid, set()).add((abs_s, abs_e))
                    except Exception:
                        continue

        results: List[Dict[str, Any]] = []
        for idx, chunk in enumerate(chunks):
            results.append(self._call_model_relations(chunk, idx))

        if self.trace_enabled:
            try:
                _helper.connector_logger.debug(
                    f"Trace raw chunk payloads:\n{json.dumps(results, ensure_ascii=False, indent=2)}"
                )
            except Exception:
                _helper.connector_logger.debug(
                    f"Trace raw chunk payloads (repr): {results!r}"
                )

        try:
            total_chunks = len(chunks)
            counts = sorted(self._subchunk_counts)
            p95 = counts[int(0.95 * (len(counts) - 1))] if counts else 0
            p99 = counts[int(0.99 * (len(counts) - 1))] if counts else 0
            _helper.connector_logger.info(
                f"Chunk summary: chunks={total_chunks}, subchunks_total={sum(counts)}, "
                f"subchunks_p95={p95}, subchunks_p99={p99}, continuations_used={self._continuations_used}"
            )
        except Exception:
            pass

        span_map: dict[tuple[str, str], dict] = {}
        relations: list[dict] = []

        def _merge_span(sp: dict) -> None:
            label = self._norm_label(sp.get("label"))
            text_val = str(sp.get("text", "")).strip()
            if not label or not text_val:
                return
            try:
                norm = normalize_stix_value(label, text_val)
            except Exception:
                norm = text_val
            key = (label, norm)
            sid = f"t={label.split('.', maxsplit=1)[0].lower()};h={_short_hash(norm)}"
            sid = str(sp.get("id") or sid)
            if key not in span_map:
                entry = {
                    "id": sid,
                    "text": text_val,
                    "label": label,
                    "type": self._norm_label(sp.get("type")) or label,
                }
                span_map[key] = entry
            else:
                entry = span_map[key]
                sid = str(entry.get("id") or sid)

            for p in sp.get("positions", []) or []:
                try:
                    pos_index.setdefault(sid, set()).add(
                        (int(p.get("start", 0)), int(p.get("end", 0)))
                    )
                except Exception:
                    continue
            if sid in pos_index:
                entry["positions"] = [
                    {"start": s, "end": e} for (s, e) in sorted(pos_index[sid])
                ]

        for sp in regex_payload.get("metadata", {}).get("span_based_entities", []):
            _merge_span(sp)

        for doc in results:
            meta = doc.get("metadata") or {}
            for sp in meta.get("span_based_entities") or []:
                _merge_span(sp)
            for rel in doc.get("relations") or []:
                label = self._norm_label(rel.get("label"))
                fid = rel.get("from_id")
                tid = rel.get("to_id")
                if not label or not fid or not tid or fid == tid:
                    continue
                relations.append(
                    {
                        "type": "relationship",
                        "label": label.upper(),
                        "from_id": fid,
                        "to_id": tid,
                    }
                )

        id_index = {v["id"]: v for v in span_map.values()}
        rel_out: list[dict] = []
        seen_rel = set()
        for r in relations:
            fid = r.get("from_id")
            tid = r.get("to_id")
            if fid in id_index and tid in id_index:
                key = (r["label"], fid, tid)
                if key not in seen_rel:
                    seen_rel.add(key)
                    rel_out.append(r)

        return {
            "metadata": {
                "span_based_entities": list(span_map.values()),
                **(
                    {"regex_only": True}
                    if not results
                    and regex_payload.get("metadata", {}).get("regex_only")
                    else {}
                ),
            },
            "relations": rel_out,
        }

    def extract_relations(self, source_text: Any) -> Dict[str, Any]:
        """Provider-neutral alias for relation extraction."""
        return self.openai_extract_relations(source_text)

    def _count_message_tokens(self, messages) -> int:
        """Count tokens following ChatML-ish rules using tiktoken when available."""
        try:
            if getattr(self.enc, "_type", "") == "tiktoken" and getattr(
                self.enc, "_enc", None
            ):
                model = (self.model_name or "").lower()
                if any(k in model for k in ("gpt-4o", "o1")):
                    tokens_per_message = 4
                    tokens_per_name = -1
                elif any(k in model for k in ("gpt-4", "gpt-3.5")):
                    tokens_per_message = 4
                    tokens_per_name = -1
                else:
                    tokens_per_message = 4
                    tokens_per_name = -1

                num_tokens = 0
                for m in messages:
                    num_tokens += tokens_per_message
                    content = m.get("content", "") or ""
                    num_tokens += len(self.enc._enc.encode(content))  # type: ignore[attr-defined]
                    if m.get("name"):
                        num_tokens += tokens_per_name
                num_tokens += 2
                return num_tokens
        except Exception:
            pass
        parts: List[str] = [
            f"{m.get('role','')}: {m.get('content','')}\n" for m in messages
        ]
        return len(self.enc.encode("".join(parts)))

    def _rate_limit(self) -> None:
        """Rate-limit provider calls based on configured RPM."""
        if not self.rpm or self.rpm <= 0:
            return
        while True:
            now = time.monotonic()
            while self._rpm_window and (now - self._rpm_window[0]) > 60.0:
                self._rpm_window.popleft()
            if len(self._rpm_window) < int(self.rpm):
                self._rpm_window.append(now)
                return
            wait_for = max(0.01, 60.0 - (now - self._rpm_window[0]))
            time.sleep(wait_for)

    def _filter_valid_json_lines(self, ndjson: str) -> str:
        cleaned = []
        for line_no, line in enumerate(ndjson.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                found = False
                for obj in ijson.items(line, "", multiple_values=True):
                    try:
                        serialized = json.dumps(
                            obj, sort_keys=True, separators=(",", ":")
                        )
                        cleaned.append(serialized)
                        found = True
                    except Exception:
                        _helper.connector_logger.debug(
                            f"Dropped unserializable object on line {line_no}: {repr(obj)[:200]}"
                        )
                if not found:
                    _helper.connector_logger.debug(
                        f"No JSON objects found on line {line_no}"
                    )
            except Exception:
                _helper.connector_logger.debug(
                    f"Dropped invalid JSON line {line_no}: {line[:80]}..."
                )
                continue
        return "\n".join(cleaned)

    def _parse_ndjson_any(self, ndjson: str) -> List[dict]:
        out: List[dict] = []
        if ndjson.lstrip().startswith("```"):
            lines = ndjson.lstrip().splitlines()
            if lines:
                lines = lines[1:]
            if lines and lines[-1].lstrip().startswith("```"):
                lines = lines[:-1]
        else:
            lines = ndjson.splitlines()
        for _line_no, line in enumerate(lines, start=1):
            s = line.strip()
            if not s:
                continue
            try:
                for obj in ijson.items(s, "", multiple_values=True):
                    if isinstance(obj, dict):
                        out.append(obj)
            except Exception:
                try:
                    a = s.find("{")
                    b = s.rfind("}")
                    if b > a >= 0:
                        obj = json.loads(s[a : b + 1])
                        if isinstance(obj, dict):
                            out.append(obj)
                except Exception:
                    continue
        return out

    def call_openai(
        self, messages: List[Dict[str, str]], chunk_index: int
    ) -> Optional[str]:
        """Synchronous provider call with retry/backoff handling."""

        def _invoke(messages, available):
            if self.use_ollama:
                return self.client.chat(
                    model=self.model_name,
                    messages=messages,
                    options={
                        "temperature": 0,
                        "top_p": 1,
                        "num_ctx": int(self.max_model_tokens),
                        "num_predict": available,
                    },
                )
            return self.client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                temperature=0,
                top_p=1,
                max_completion_tokens=available,
            )

        for attempt in range(MAX_RETRIES):
            try:
                accumulated = ""
                continuation = 0

                while True:
                    prompt_tokens = self._count_message_tokens(messages)
                    available = max(
                        1, self.max_model_tokens - prompt_tokens - self.safety_margin
                    )

                    _helper.connector_logger.debug(
                        f"LLM call chunk {chunk_index} attempt {attempt + 1} cont {continuation}: "
                        f"prompt_tokens={prompt_tokens} completion_budget={available}"
                    )

                    self._rate_limit()
                    completion = _invoke(messages, available)

                    usage = None
                    finish_reason = "stop"
                    content_piece = ""
                    if self.use_ollama:
                        message = completion.get("message") or {}
                        content_piece = str(message.get("content") or "")
                        finish_reason = str(
                            completion.get("done_reason")
                            or ("stop" if completion.get("done") else "length")
                        )
                    else:
                        completion = completion  # type: ChatCompletion
                        usage = getattr(completion, "usage", None)
                        finish_reason = completion.choices[0].finish_reason
                        content_piece = completion.choices[0].message.content or ""
                    accumulated += content_piece

                    if usage is not None:
                        pt = getattr(usage, "prompt_tokens", "?")
                        ct = getattr(usage, "completion_tokens", "?")
                        tt = getattr(usage, "total_tokens", "?")
                        try:
                            est = self._count_message_tokens(messages)
                        except Exception:
                            est = "?"
                        _helper.connector_logger.info(
                            f"LLM resp chunk {chunk_index}, attempt {attempt+1}, cont {continuation}: "
                            f"prompt={pt}, completion={ct}, available={available}, total={tt}, "
                            f"est_prompt={est}, finish_reason={finish_reason}"
                        )
                    else:
                        _helper.connector_logger.info(
                            f"LLM response chunk {chunk_index}, attempt {attempt+1}, "
                            f"cont {continuation}, finish_reason={finish_reason}"
                        )

                    if finish_reason != "length":
                        try:
                            self._continuations_used += continuation
                        except Exception:
                            pass
                        return accumulated

                    accumulated = self._filter_valid_json_lines(accumulated)

                    continuation += 1
                    if continuation >= MAX_CONTINUATIONS:
                        _helper.connector_logger.warning(
                            f"Max continuations reached for chunk {chunk_index}"
                        )
                        if self.trace_enabled:
                            try:
                                _helper.connector_logger.debug(
                                    f"prompt: {messages[1]['content']}"
                                )
                                _helper.connector_logger.debug(
                                    f"accumulated: {accumulated}"
                                )
                            except Exception:
                                pass
                        try:
                            self._continuations_used += continuation
                        except Exception:
                            pass
                        return accumulated

                    if self.enc:
                        tokens = self.enc.encode(accumulated)
                        keep = tokens[-500:]
                        short_context = self.enc.decode(keep)
                    else:
                        short_context = accumulated[-2000:]

                    messages = [
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": messages[1]["content"]},
                        {"role": "assistant", "content": short_context},
                        {
                            "role": "user",
                            "content": (
                                "Continue extracting where you left off. "
                                "Do not repeat earlier results. Stop if no new items remain."
                            ),
                        },
                    ]

            except Exception as e:
                _helper.connector_logger.error(
                    f"LLM error (attempt {attempt+1}) on chunk {chunk_index}: {e}"
                )
                if attempt < MAX_RETRIES - 1:
                    delay = BACKOFF_BASE**attempt + random.uniform(0, 1)
                    _helper.connector_logger.debug(
                        f"Retrying chunk {chunk_index} after {delay:.2f}s backoff"
                    )
                    time.sleep(delay)
                else:
                    raise
        return None

    def _build_user_content(
        self, hints: List[dict], start: int, end: int, text: str
    ) -> str:
        hints_json = json.dumps(
            {"hints": hints or [], "start": int(start or 0), "end": int(end or 0)},
            separators=(",", ":"),
        )
        return (
            "You are extracting threat intel spans and relations.\n"
            "Emit NDJSON (one JSON object per line) using this schema:\n"
            '  Span line: {"id":"<id>","type":"entity|observable","label":'
            '"<STIX category>","value":"<raw text>","start_offset":<int>,'
            '"end_offset":<int>}\n  Relationship line: {"type":"relationship",'
            '"label":"<relationship_type>","from_id":"<span id>","to_id":'
            '"<span id>"}\n- HINTS are authoritative candidates. When a hint '
            "applies, reuse its id and copy its label (category) and type "
            "exactly.\n- HINTS.hints contains objects: {id, type (observable|"
            "entity), category (STIX label), value (raw), positions:[{start,"
            "end}]}; positions are CHUNK-RELATIVE to the provided TEXT slice."
            "\n- Only emit IDs that exist in HINTS or that you also include "
            "in span lines.\n- City spans should be formatted as 'City, "
            "Country' using ISO 3166-1 English short country names.\n"
            "- Country spans must be official ISO 3166-1 short names (no "
            "abbreviations). Sector spans must come from the STIX "
            "industry-sector-ov vocabulary (lowercase, dash-separated). "
            "Allowed sector values: agriculture, aerospace, automotive, "
            "chemical, commercial, communications, construction, defense, "
            "education, energy, entertainment, financial-services, "
            "government, emergency-services, government-local, "
            "government-national, government-public-services, "
            "government-regional, healthcare, hospitality-leisure, "
            "infrastructure, dams, nuclear, water, insurance, legal, "
            "manufacturing, mining, non-profit, pharmaceuticals, retail, "
            "technology, telecommunications, transportation, utilities.\n"
            "- Only emit relationships that are clearly supported by the text "
            "and compatible with the active OpenCTI schema.\n"
            f"- {self.relation_guidance}\n"
            "- Observable relations are allowed when the text explicitly states "
            "them and they match the active schema. Examples include "
            "RESOLVES-TO, BELONGS-TO, COMMUNICATES-WITH, CONSISTS-OF, HOSTS, or RELATED-TO.\n"
            "- Attack-Pattern.x_mitre_id usually appears as the target of USES "
            "from Threat-Actor-Group, Threat-Actor-Individual, Intrusion-Set, Campaign, or Incident.\n"
            "- When uncertain about a relationship, omit the relationship and still emit the spans.\n"
            "- No markdown, no explanations, JSON only.\n\n"
            f"HINTS: {hints_json}\n\nTEXT:\n{text}"
        )
