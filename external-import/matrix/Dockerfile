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

# Apply the legacy CMake-policy minimum to every CMake invocation in this
# stage. libolm's ``CMakeLists.txt`` declares a ``cmake_minimum_required``
# value older than 3.5, and CMake 4.x (shipped by the ``python:3.12-alpine``
# image since the 4.x release) removed compatibility with CMake < 3.5,
# causing both the system libolm install below and ``python-olm``'s
# bundled libolm build (triggered transitively by ``matrix-nio[e2e]``
# during the ``pip install`` step further down) to fail with:
# "Compatibility with CMake < 3.5 has been removed from CMake".
# The ``CMAKE_POLICY_VERSION_MINIMUM`` CMake variable can also be
# initialised from an environment variable, so setting it here covers
# every nested ``cmake`` call without having to patch each one.
ENV CMAKE_POLICY_VERSION_MINIMUM=3.5

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
    /scripts/build_and_install_libolm.sh "${LIBOLM_VERSION}"

# Install the connector's Python dependencies into ``/python-libs`` so they
# can be copied over to the runtime stage without dragging the build
# toolchain along. ``matrix-nio[e2e]`` pulls in ``python-olm`` from PyPI
# which is then compiled against the libolm headers / shared library
# installed by ``build_and_install_libolm.sh`` above, so the resulting
# ``olm`` Python package lands in the same
# ``/python-libs/lib/python3.12/site-packages/`` layout as the rest of
# the dependencies — ready to be copied over to ``/usr/local`` in the
# runtime stage.
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
