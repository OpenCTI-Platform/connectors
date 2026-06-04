FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

WORKDIR /opt/opencti-connector-ransomware-live

# Install Python modules. ``--virtual .build-deps`` groups the
# build-time toolchain so it can be dropped in the same ``RUN`` after
# ``pip install`` to keep the final image small; only ``libmagic`` /
# ``libxslt`` / ``libxml2`` runtimes stay. The explicit
# ``pip install --upgrade pycti`` the earlier draft carried is removed:
# the version is already pinned in ``requirements.txt`` and upgrading
# it standalone produced non-reproducible builds whenever the upstream
# pycti release stream moved.
COPY src/requirements.txt .
RUN apk --no-cache add libmagic libxslt libxml2 && \
    apk --no-cache add --virtual .build-deps git build-base libffi-dev libxslt-dev libxml2-dev && \
    pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

# Expose and entrypoint
COPY src ./src
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh
ENTRYPOINT ["/bin/sh", "entrypoint.sh"]
