FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_EXPORT_FILE

# Copy the worker
COPY src /opt/opencti-connector-export-report-pdf

# Install Python modules.
# The Pillow wheels bundle Brotli 1.2.0 (CVE-2026-111497) for FreeType: in the
# same layer, replace the bundled libbrotlidec with a link to the system one
# (brotli-libs, fixed) and remove the bundled libbrotlicommon, which only it
# loads (#8091).
# The link keeps the bundled name (libbrotlidec-<hash>.so.1.2.0), the one
# FreeType loads, but resolves to the system version.
# hadolint ignore=DL3003
RUN apk --no-cache upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev zlib-dev tiff-dev jpeg-dev openjpeg-dev zlib-dev \
    freetype-dev lcms2-dev libwebp-dev tcl-dev tk-dev harfbuzz-dev fribidi-dev libimagequant-dev \
    libxcb-dev libpng-dev pango weasyprint brotli-libs && \
    cd /opt/opencti-connector-export-report-pdf && \
    pip3 install --no-cache-dir -r requirements.txt && \
    cd /usr/local/lib/python3*/site-packages/pillow.libs && \
    rm libbrotlicommon-* && \
    ln -sf /usr/lib/libbrotlidec.so.1 libbrotlidec-* && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
