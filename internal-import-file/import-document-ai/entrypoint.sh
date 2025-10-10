#!/bin/sh

# Go to the right directory
cd /opt/opencti-connector-import-document-ai

python3 - <<'__PY__'
import os, yaml, easyocr, pathlib
cfg_path = pathlib.Path('config.yml')
langs = ['en']
if cfg_path.exists():
    cfg = yaml.safe_load(cfg_path.read_text(encoding='utf-8')) or {}
    vals = cfg.get('import_document', {}).get('pdf_ocr_langs', 'en')
    if isinstance(vals, str):
        langs = [s.strip() for s in vals.split(',') if s.strip()]
    else:
        langs = [str(s).strip() for s in vals if str(s).strip()]
easyocr.Reader(langs, gpu=False)
print("[Startup] EasyOCR weights ready for:", langs)
__PY__

# Launch the worker
exec python3 main.py