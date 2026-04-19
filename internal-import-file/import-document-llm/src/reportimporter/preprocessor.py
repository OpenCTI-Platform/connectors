"""
Preprocessor for file content extraction and conversion to markdown.

Supports:
- Plain text, Markdown, HTML, CSV
- PDF (native text + OCR via EasyOCR/PyMuPDF)
- DOCX (converted to Markdown)
"""

import csv
import platform
import re
import threading
from dataclasses import dataclass
from io import BytesIO, StringIO
from pathlib import Path
from typing import Optional

import docx
import easyocr
import fitz  # PyMuPDF
import numpy as np
import torch
from markdownify import markdownify as md
from PIL import Image

from ._nulls import _NullHelper

# Default to a null helper until set_helper() is called
_helper = _NullHelper()


def set_helper(helper) -> None:
    """Inject the real OpenCTI connector helper globally."""
    global _helper  # pylint: disable=global-statement
    _helper = helper


# ---------------------------------------------------------------------------
# PDF OCR configuration
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PdfOcrConfig:
    languages: tuple[str, ...] = ("en",)
    gpu: bool = torch.cuda.is_available()
    serialize_gpu: bool = gpu
    min_img_area: int = 40_000
    page_raster_dpi: int = 300

    @classmethod
    def from_opencti(cls, parser) -> "PdfOcrConfig":
        try:
            requested = tuple(getattr(parser, "pdf_ocr_langs", ("en",)))
            langs = tuple(
                str(x).strip().lower() for x in requested if str(x).strip()
            ) or ("en",)
            return cls(
                languages=langs,
                gpu=bool(getattr(parser, "pdf_ocr_gpu", True)),
                serialize_gpu=bool(getattr(parser, "pdf_ocr_serialize_gpu", True)),
                min_img_area=int(getattr(parser, "pdf_ocr_min_img_area", 40_000)),
                page_raster_dpi=int(getattr(parser, "pdf_ocr_page_dpi", 300)),
            )
        except Exception as e:
            _helper.connector_logger.warning(
                f"Falling back to default PdfOcrConfig: {e}"
            )
            return cls()


# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
_READER_CACHE: dict[tuple[tuple[str, ...], bool], easyocr.Reader] = {}
_GPU_OCR_SEMAPHORE = threading.Semaphore(1)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _unfold_cert_blocks(text: str) -> str:
    text = re.sub(r"(Issuer:\s*[^\n]+)\n\s+([A-Z]+=)", r"\1 \2", text)
    text = re.sub(
        r"(Serial Number:\s*[0-9A-Fa-f: -]+)\n\s*([0-9A-Fa-f: -]+)", r"\1\2", text
    )
    return text


def _pixmap_to_np(pix: fitz.Pixmap) -> np.ndarray:
    if pix.n - pix.alpha not in (1, 3):
        pix = fitz.Pixmap(fitz.csRGB, pix)
    return np.array(Image.open(BytesIO(pix.tobytes("png"))).convert("RGB"))


def _easyocr_reader(langs: tuple[str, ...], cache, gpu: bool):
    valid = tuple(x.strip().lower() for x in langs if x.strip()) or ("en",)
    key = (valid, gpu)

    if cache and key in cache:
        return cache[key]

    try:
        r = easyocr.Reader(list(valid), gpu=gpu)
        if cache is not None:
            cache[key] = r
        return r
    except Exception as e:
        _helper.connector_logger.warning(
            f"EasyOCR init failed for {valid} (gpu={gpu}): {e}. Falling back to en/no-gpu."
        )
        try:
            r = easyocr.Reader(["en"], gpu=False)
            if cache is not None:
                cache[(("en",), False)] = r
            return r
        except Exception as e2:
            _helper.connector_logger.error(
                f"EasyOCR fallback failed: {e2}. OCR disabled."
            )
            return None


def _ocr_np_image(reader, img_np) -> str:
    if reader is None:
        return ""
    try:
        parts = reader.readtext(img_np, detail=0)
        return " ".join(p.strip() for p in parts if p and p.strip())
    except Exception as e:
        _helper.connector_logger.warning(f"OCR failed: {e}")
        return ""


def _ocr_with_lock(reader, img_np, use_lock: bool) -> str:
    if use_lock:
        with _GPU_OCR_SEMAPHORE:
            return _ocr_np_image(reader, img_np)
    return _ocr_np_image(reader, img_np)


def _extract_text_and_ocr_images_from_page(
    doc: fitz.Document,
    page_index: int,
    reader_cache: dict,
    *,
    config: PdfOcrConfig,
) -> str:
    page = doc.load_page(page_index)
    text = (page.get_text() or "").strip()

    ocr_chunks: list[str] = []
    for img in page.get_images(full=True):
        xref, _, w, h, *_ = img
        if w * h < config.min_img_area:
            continue
        try:
            _helper.connector_logger.debug(
                f"Page {page_index+1}: OCR candidate image {xref} ({w}x{h})"
            )
            pix = fitz.Pixmap(doc, xref)
            reader = _easyocr_reader(config.languages, reader_cache, gpu=config.gpu)
            if reader:
                t = _ocr_with_lock(
                    reader,
                    _pixmap_to_np(pix),
                    use_lock=config.gpu and config.serialize_gpu,
                )
                if t:
                    ocr_chunks.append(t)
            del pix
        except Exception as e:
            _helper.connector_logger.warning(
                f"Page {page_index+1}: OCR failed for xref={xref}: {e}"
            )

    if not text:
        zoom = config.page_raster_dpi / 72.0
        pix = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
        reader = _easyocr_reader(config.languages, reader_cache, gpu=config.gpu)
        text = (
            _ocr_with_lock(
                reader, _pixmap_to_np(pix), use_lock=config.gpu and config.serialize_gpu
            )
            if reader
            else ""
        )
        del pix

    if ocr_chunks and text:
        return f"{text}\n\n[Image OCR]\n" + "\n".join(ocr_chunks)
    return text or "\n".join(ocr_chunks)


# ---------------------------------------------------------------------------
# Main Preprocessor
# ---------------------------------------------------------------------------
class FilePreprocessor:
    @staticmethod
    def preprocess_file(
        file_bytes: bytes,
        file_mime: str,
        file_name: Optional[str],
        pdf_ocr_enabled: bool = True,
        pdf_ocr_config: Optional[PdfOcrConfig] = None,
    ) -> Optional[str]:
        try:
            result = FilePreprocessor._preprocess_file_int(
                file_bytes,
                file_mime,
                file_name,
                pdf_ocr_enabled=pdf_ocr_enabled,
                pdf_ocr_config=pdf_ocr_config,
            )
            if result:
                safe_name = Path(file_name).name if file_name else "<unknown>"
                _helper.connector_logger.info(
                    f"Preprocessed {safe_name}: {len(result)} chars extracted"
                )
                return _unfold_cert_blocks(result)
            return None
        except Exception as e:
            _helper.connector_logger.error(f"File preprocessing failed: {e}")
            return None

    @staticmethod
    def _preprocess_file_int(
        file_bytes: bytes,
        file_mime: str,
        file_name: Optional[str],
        pdf_ocr_enabled: bool = True,
        pdf_ocr_config: Optional[PdfOcrConfig] = None,
    ) -> Optional[str]:
        safe_name = Path(file_name).name if file_name else None

        # Markdown
        if file_mime == "text/markdown" or (
            safe_name and safe_name.lower().endswith(".md")
        ):
            return _try_decode(file_bytes)

        # HTML
        if file_mime == "text/html" or (
            safe_name and safe_name.lower().endswith((".html", ".htm"))
        ):
            html = _try_decode(file_bytes)
            return md(html) if html else None

        # CSV
        if file_mime == "text/csv" or (
            safe_name and safe_name.lower().endswith(".csv")
        ):
            text = _try_decode(file_bytes)
            if text:
                try:
                    rows = list(csv.reader(StringIO(text)))
                    if rows:
                        return "\n".join(
                            "| " + " | ".join(row) + " |" for row in rows[1:]
                        )
                except Exception as e:
                    _helper.connector_logger.error(f"CSV parse failed: {e}")

        # Plain text
        if file_mime in ("text/plain", "application/octet-stream") or (
            safe_name and safe_name.lower().endswith((".txt", ".log"))
        ):
            return _try_decode(file_bytes)

        # PDF
        if file_mime == "application/pdf" or (
            safe_name and safe_name.lower().endswith(".pdf")
        ):
            return _process_pdf(file_bytes, pdf_ocr_enabled, pdf_ocr_config)

        # DOCX
        if file_mime in (
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/msword",
        ) or (safe_name and safe_name.lower().endswith(".docx")):
            return _process_docx(file_bytes)

        # Fallback
        return _try_decode(file_bytes)


# ---------------------------------------------------------------------------
# Type-specific helpers
# ---------------------------------------------------------------------------
def _try_decode(data: bytes) -> Optional[str]:
    for encoding in ("utf-8", "latin-1"):
        try:
            return data.decode(encoding)
        except Exception:
            continue
    return None


def _process_pdf(
    file_bytes: bytes, pdf_ocr_enabled: bool, pdf_ocr_config: Optional[PdfOcrConfig]
) -> Optional[str]:
    try:
        doc = fitz.open(stream=file_bytes, filetype="pdf")
    except Exception as e:
        _helper.connector_logger.error(f"PDF open failed: {e}")
        return None

    if pdf_ocr_enabled:
        cfg = (
            pdf_ocr_config
            if isinstance(pdf_ocr_config, PdfOcrConfig)
            else PdfOcrConfig(gpu=(platform.system() != "Windows"), serialize_gpu=True)
        )
        reader_cache = _READER_CACHE
        _helper.connector_logger.debug(f"PDF OCR config: {cfg}")
    else:
        cfg, reader_cache = None, None
        _helper.connector_logger.info(
            "PDF OCR disabled. Native text will still be extracted."
        )

    pages_out, pages_native, pages_raster, images_ocrd = [], 0, 0, 0
    try:
        for i in range(doc.page_count):
            page = doc.load_page(i)
            native = (page.get_text() or "").strip()
            if native:
                pages_native += 1

            if pdf_ocr_enabled and cfg:
                page_txt = _extract_text_and_ocr_images_from_page(
                    doc, i, reader_cache, config=cfg
                )
                if not native and page_txt.strip():
                    pages_raster += 1
                images_ocrd += sum(
                    1
                    for im in page.get_images(full=True)
                    if (im[2] * im[3]) >= cfg.min_img_area
                )
            else:
                page_txt = native

            if page_txt.strip():
                pages_out.append(f"## Page {i+1}\n\n{page_txt}")
            else:
                _helper.connector_logger.warning(f"No text from PDF page {i+1}")
    finally:
        doc.close()

    if not pages_out:
        _helper.connector_logger.error("No text extracted from PDF.")
        return None

    if cfg:
        _helper.connector_logger.info(
            f"PDF OCR report: pages={len(pages_out)}, native={pages_native}, rasterized={pages_raster}, "
            f"images_ocrd~={images_ocrd}, langs={cfg.languages}, gpu={cfg.gpu}, serialize_gpu={cfg.serialize_gpu}"
        )
    else:
        _helper.connector_logger.info(
            f"PDF text extraction: pages={len(pages_out)}, native={pages_native}"
        )

    return "\n\n".join(pages_out)


def _process_docx(file_bytes: bytes) -> Optional[str]:
    try:
        doc = docx.Document(BytesIO(file_bytes))
        lines: list[str] = []
        for para in doc.paragraphs:
            text = para.text.strip()
            if not text:
                continue
            style = para.style.name.lower() if hasattr(para.style, "name") else ""
            if "heading" in style:
                level = "".join(filter(str.isdigit, style))
                lines.append(f"{'#' * int(level or 1)} {text}")
            elif style in ("list bullet", "list paragraph") or text.startswith(
                ("-", "*")
            ):
                lines.append(f"- {text.lstrip('-* ')}")
            else:
                lines.append(text)
        return "\n".join(lines) if lines else None
    except Exception as e:
        _helper.connector_logger.error(f"DOCX parse failed: {e}")
        return None
