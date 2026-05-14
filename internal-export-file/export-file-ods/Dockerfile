FROM debian:bookworm-slim

ENV CONNECTOR_TYPE=INTERNAL_EXPORT_FILE \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# LibreOffice and its Python UNO bridge are required by ``unogenerator`` to
# render the ODS document. ``python3-uno`` ships a compiled ``pyuno`` extension
# built against the *system* Python (Python 3.11 on Debian Bookworm); the
# runtime Python therefore has to be the same system interpreter, which is
# why this connector uses ``debian:bookworm-slim`` instead of the
# ``python:3.x-slim`` images used by the other export connectors (those ship
# a second Python under ``/usr/local`` that cannot import ``pyuno``).
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
        python3 \
        python3-pip \
        python3-uno \
        python3-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# ``--system-site-packages`` lets the virtual environment see the apt-installed
# ``python3-uno`` (``uno`` / ``unohelper`` / ``pyuno``) modules while still
# being writable by ``pip``, which keeps PEP 668 happy.
RUN python3 -m venv --system-site-packages /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

COPY src /opt/opencti-connector-export-file-ods
WORKDIR /opt/opencti-connector-export-file-ods
RUN pip install --no-cache-dir -r requirements.txt && \
    mkdir -p /opt/opencti-connector-export-file-ods/tmp

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
