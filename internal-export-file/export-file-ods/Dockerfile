FROM debian:bookworm-slim

ENV CONNECTOR_TYPE=INTERNAL_EXPORT_FILE \
    DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1

# LibreOffice and its Python UNO bridge are required by ``unogenerator`` to
# render the ODS document. ``python3-uno`` ships a compiled ``pyuno`` extension
# built against the *system* Python (Python 3.11 on Debian Bookworm); the
# runtime Python therefore has to be the same system interpreter, which is
# why this connector uses ``debian:bookworm-slim`` instead of the
# ``python:3.12-alpine`` image used by the other internal-export connectors
# (``export-file-csv``, ``export-file-stix``, ``export-file-txt``,
# ``export-file-yara``, ``export-report-pdf``). Alpine is not an option
# because LibreOffice / ``python3-uno`` are not packaged for ``musl``;
# the official ``python:3.x-slim`` images are not an option either because
# their ``/usr/local`` Python cannot import the system ``pyuno`` C
# extension (ABI mismatch).
#
# ``git`` is required because the CircleCI rolling/prerelease build rewrites
# the ``pycti==<version>`` line in ``requirements.txt`` to a
# ``pycti @ git+https://github.com/OpenCTI-Platform/opencti.git@<ref>...``
# requirement, which pip can only resolve when ``git`` is on ``PATH``. It is
# purged again at the end of the install layer so it does not bloat the
# runtime image.
#
# ``PIP_BREAK_SYSTEM_PACKAGES=1`` is set above so ``pip`` is allowed to
# install into the system Python on Debian Bookworm (PEP 668). This is the
# same interpreter that ``python3-uno`` is built against, so installing
# ``pycti`` and ``unogenerator`` alongside it is what makes the UNO bridge
# importable from the connector process without any path tricks.
# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        default-jre-headless \
        git \
        libcups2 \
        libdbus-1-3 \
        libreoffice-core \
        libreoffice-calc \
        libreoffice-script-provider-python \
        libx11-xcb1 \
        libxinerama1 \
        python3 \
        python3-pip \
        python3-uno && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY src /opt/opencti-connector-export-file-ods
WORKDIR /opt/opencti-connector-export-file-ods
RUN pip3 install --no-cache-dir -r requirements.txt && \
    mkdir -p /opt/opencti-connector-export-file-ods/tmp && \
    apt-get purge -y --auto-remove git && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
