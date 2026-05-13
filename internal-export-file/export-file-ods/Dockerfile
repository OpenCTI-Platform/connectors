FROM python:3.12-slim
ENV CONNECTOR_TYPE=INTERNAL_EXPORT_FILE \
    DEBIAN_FRONTEND=noninteractive

# LibreOffice (and its Python UNO bridge) is required by ``unogenerator`` to
# render the ODS document. It is only available on glibc-based distributions,
# which is why this connector uses ``python:3.12-slim`` instead of the
# ``python:3.12-alpine`` image used by the other export connectors.
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        default-jre-headless \
        libcups2 \
        libdbus-1-3 \
        libreoffice-core \
        libreoffice-calc \
        libreoffice-script-provider-python \
        libx11-xcb1 \
        libxinerama1 \
        python3-uno && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# ``python3-uno`` installs the UNO bridge under the system Python's
# ``dist-packages`` directory. The container's runtime Python lives in
# ``/usr/local`` and does not see those packages by default, so we expose the
# two required modules with symlinks. The Python version is discovered at
# build-time to avoid hard-coding it.
RUN PY_MAJOR_MINOR="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')" && \
    install -d "/usr/local/lib/python${PY_MAJOR_MINOR}/site-packages" && \
    ln -sf /usr/lib/python3/dist-packages/uno.py \
           "/usr/local/lib/python${PY_MAJOR_MINOR}/site-packages/uno.py" && \
    ln -sf /usr/lib/python3/dist-packages/unohelper.py \
           "/usr/local/lib/python${PY_MAJOR_MINOR}/site-packages/unohelper.py"

# Copy the worker
COPY src /opt/opencti-connector-export-file-ods
WORKDIR /opt/opencti-connector-export-file-ods
RUN pip3 install --no-cache-dir -r requirements.txt && \
    mkdir -p /opt/opencti-connector-export-file-ods/tmp

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
