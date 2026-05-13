# OpenCTI Matrix external-import connector image.
#
# This Dockerfile uses a two-stage build:
#   1. a "builder" stage that compiles libolm (needed by ``matrix-nio[e2e]``
#      for end-to-end encryption support) and installs the Python
#      dependencies into ``/python-libs``;
#   2. a slim runtime stage that copies the compiled libolm and the
#      installed Python packages over.
#
# Build it from this directory:
#
#     docker build -t opencti/connector-matrix:latest .
#
# There are two optional build arguments:
#
#     docker build --build-arg PYTHON_VERSION=3.12 --build-arg LIBOLM_VERSION=3.2.16 .

ARG PYTHON_VERSION=3.12
ARG LIBOLM_VERSION=3.2.16

# ---------------------------------------------------------------------------
# Builder stage
# ---------------------------------------------------------------------------
FROM docker.io/python:${PYTHON_VERSION}-alpine AS builder

ARG LIBOLM_VERSION

# hadolint ignore=DL3018
RUN apk add --no-cache \
        cmake \
        g++ \
        gcc \
        git \
        libffi-dev \
        make \
        python3-dev

COPY build_and_install_libolm.sh /scripts/
RUN chmod u+x /scripts/build_and_install_libolm.sh && \
    /scripts/build_and_install_libolm.sh "${LIBOLM_VERSION}" /python-libs

# Install the connector's Python dependencies into ``/python-libs`` so they
# can be copied over to the runtime stage without dragging the build
# toolchain along.
COPY src/requirements.txt /tmp/requirements.txt
RUN pip install --prefix=/python-libs --no-warn-script-location --no-cache-dir \
        -r /tmp/requirements.txt

# ---------------------------------------------------------------------------
# Runtime stage
# ---------------------------------------------------------------------------
FROM docker.io/python:${PYTHON_VERSION}-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Bring in the compiled libolm + python bindings from the builder stage.
COPY --from=builder /python-libs /usr/local
COPY --from=builder /usr/local/lib/libolm* /usr/local/lib/

# Runtime native dependencies. ``libstdc++`` is required by libolm and
# ``libmagic`` is required by the OpenCTI helper.
# hadolint ignore=DL3018
RUN apk add --no-cache \
        libmagic \
        libstdc++

# Copy the connector source.
COPY src /opt/opencti-connector-matrix
WORKDIR /opt/opencti-connector-matrix

# Expose and entrypoint.
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
