FROM python:3.12-slim

ENV CONNECTOR_TYPE=INTERNAL_IMPORT_FILE
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1


WORKDIR /opt/opencti-connector-import-document-ai
ENV HOME=/opt/opencti-connector-import-document-ai

COPY src /opt/opencti-connector-import-document-ai
COPY --chmod=0555 entrypoint.sh /opt/opencti-connector-import-document-ai/entrypoint.sh

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    rustc \
    cargo \
    libmagic1 \
    tesseract-ocr \
    tesseract-ocr-eng \
    poppler-utils \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python -m pip install --no-cache-dir torch torchvision \
    --index-url https://download.pytorch.org/whl/cpu \
    && python -m pip install --no-cache-dir -r requirements.txt -c constraints.txt \
    && apt-get remove -y --purge build-essential rustc cargo libmagic1 tesseract-ocr tesseract-ocr-eng poppler-utils \
    && apt-get autoremove -y && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /root/.cache/pip

# Pre-download EasyOCR weights (CPU path is fine for caching)
# You can override at build-time:  --build-arg EASYOCR_LANGS="en,es"
ARG EASYOCR_LANGS="en"
RUN python - <<'__PY__'
import os, easyocr
langs = [l.strip() for l in os.environ.get("EASYOCR_LANGS","en").split(",") if l.strip()]
# This line downloads and caches the models into ~/.EasyOCR
easyocr.Reader(langs, gpu=False)
print("[Docker build] EasyOCR weights cached for:", langs)
__PY__

ENTRYPOINT ["/opt/opencti-connector-import-document-ai/entrypoint.sh"]