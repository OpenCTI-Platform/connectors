FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-portspoof

# Install system + Python dependencies. ``libmagic`` is required at
# runtime by ``pycti``; ``git`` + ``build-base`` are required *at
# install time* because the repository's CircleCI dynamic templates
# rewrite the pinned ``pycti==X.Y.Z`` line to ``pycti @ git+https://...``
# for rolling / prerelease builds (see ``.circleci/templates/dynamic.yml.j2``),
# and pip needs the ``git`` binary on ``PATH`` to install VCS
# dependencies plus a C toolchain for any wheels that have to build
# from source. The build deps are removed in the same layer so the
# final image stays small.
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-portspoof && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
