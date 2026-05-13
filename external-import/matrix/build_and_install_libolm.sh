#!/usr/bin/env sh
#
# Build and install libolm together with its Python 3 bindings.
#
# Usage:
#
#     ./build_and_install_libolm.sh <libolm version> [<python bindings install dir>]
#
# Example:
#
#     ./build_and_install_libolm.sh 3.2.16 /python-libs

set -eu

LIBOLM_VERSION="${1:?missing libolm version}"
PYTHON_PREFIX="${2:-}"

# Download the specified version of libolm.
git clone --depth=1 -b "${LIBOLM_VERSION}" \
    https://gitlab.matrix.org/matrix-org/olm.git /tmp/olm

cd /tmp/olm

# Build and install libolm itself.
cmake . -Bbuild
cmake --build build
make install

# Build and install the Python 3 bindings.
cd python && make olm-python3
if [ -n "${PYTHON_PREFIX}" ]; then
    mkdir -p "${PYTHON_PREFIX}"
    DESTDIR="${PYTHON_PREFIX}" make install-python3
else
    make install-python3
fi
