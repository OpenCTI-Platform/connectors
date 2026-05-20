FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-sigmahq

# Install Python modules. Runtime deps stay in the image (``libmagic``);
# build-only deps (``git``, ``build-base``, ``libffi-dev``, ``libxml2-dev``,
# ``libxslt-dev``) are grouped under a single ``--virtual .build-deps`` tag
# so we can drop the whole group right after ``pip install`` and keep the
# final image small. ``--no-cache`` avoids leaving the apk cache around.
# ``apk upgrade`` is intentionally NOT used — it makes the build
# non-reproducible (upgrades vary day-to-day with whatever the alpine
# mirror happens to ship) and diverges from the rest of the repo's
# connector images.
# hadolint ignore=DL3003
RUN apk --no-cache add libmagic && \
    apk --no-cache add --virtual .build-deps \
        git build-base libffi-dev libxml2-dev libxslt-dev && \
    cd /opt/opencti-connector-sigmahq && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del .build-deps

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
