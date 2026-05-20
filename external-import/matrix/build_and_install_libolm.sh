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
#
# We use ``cmake --install build`` (and not ``make install``) because
# this is an out-of-source build: ``cmake . -Bbuild`` generates the
# ``Makefile`` under ``./build/``, not in the source root, so a bare
# ``make install`` from ``/tmp/olm`` would fail with
# ``No rule to make target 'install'``. ``cmake --install build`` is
# also the canonical mate to ``cmake --build build`` and works
# identically with any generator CMake picks.
#
# ``-DCMAKE_POLICY_VERSION_MINIMUM=3.5`` is required because libolm's
# ``CMakeLists.txt`` declares a ``cmake_minimum_required`` value older
# than 3.5, and CMake 4.x (shipped by recent ``python:3.12-alpine``
# images) removed compatibility with CMake < 3.5. Without this flag,
# configuration fails with "Compatibility with CMake < 3.5 has been
# removed from CMake". The override is safe: libolm builds cleanly
# with the 3.5 policy set.
cmake . -Bbuild -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build build
cmake --install build
