#!/usr/bin/env sh
#
# Build and install the libolm C library used by ``matrix-nio[e2e]`` for
# end-to-end-encryption support.
#
# This script intentionally does **not** build / install the ``olm``
# Python bindings: ``matrix-nio[e2e]`` already lists ``python-olm~=3.2``
# as a transitive dependency on PyPI, and ``python-olm`` is built and
# installed by pip (against the libolm headers / shared library this
# script puts in place) when the Dockerfile runs
# ``pip install --prefix=/python-libs -r requirements.txt``. Doing the
# Python install here in addition would (1) be redundant and (2) place
# the resulting ``olm`` package at a path that is **not** on the runtime
# image's ``sys.path``: the upstream ``python/Makefile``'s
# ``install-python3`` target runs
# ``python3 setup.py install --skip-build -O1 --root=$(DESTDIR)``, with
# Python's default install prefix (``/usr/local`` on the
# ``python:3.12-alpine`` builder image), so files would land at
# ``${DESTDIR}/usr/local/lib/python3.12/site-packages/olm/`` — and the
# Dockerfile's ``COPY --from=builder /python-libs /usr/local`` would
# then map them to ``/usr/local/usr/local/lib/.../site-packages/olm/``,
# which is silently ignored by the runtime Python.
#
# Usage:
#
#     ./build_and_install_libolm.sh <libolm version>
#
# Example:
#
#     ./build_and_install_libolm.sh 3.2.16

set -eu

LIBOLM_VERSION="${1:?missing libolm version}"

# Download the specified version of libolm.
git clone --depth=1 -b "${LIBOLM_VERSION}" \
    https://gitlab.matrix.org/matrix-org/olm.git /tmp/olm

cd /tmp/olm

# Build and install libolm itself (headers + shared library). ``cmake``'s
# default install prefix is ``/usr/local``, so the headers land in
# ``/usr/local/include/olm/`` and the shared library in
# ``/usr/local/lib/libolm.so*``. ``python-olm`` (pulled in by pip via
# ``matrix-nio[e2e]``) compiles its C extension against those headers,
# and the resulting Python package is installed into the same prefix
# layout pip uses for every other dependency.
cmake . -Bbuild
cmake --build build
make install
