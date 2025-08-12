#!/bin/bash
set -euo pipefail

for TEST_REQUIREMENTS_FILE in "$@"
do
# Assume the test-requirements.txt sits inside the connector root or its tests dir.
# Use dirname to be path-agnostic.
REQ_DIR="$(dirname "$TEST_REQUIREMENTS_FILE")"

# If your tests live under "$REQ_DIR/tests", keep it; otherwise, just run at $REQ_DIR.
# (Adjust this to your repo layout as needed.)
CONNECTOR_DIR="$REQ_DIR"

# Per-connector outputs
OUT_DIR="test_outputs/$(echo "$CONNECTOR_DIR" | tr '/ ' '__')"
mkdir -p "$OUT_DIR"

VENV_PATH=".temp_venv"  # could also be "$OUT_DIR/.venv" if you later decide to cache it

echo "Running tests for: $CONNECTOR_DIR"
echo "Using requirements: $TEST_REQUIREMENTS_FILE"
echo "Output dir: $OUT_DIR"

python -m venv "$VENV_PATH"
# shellcheck disable=SC1091
source "$VENV_PATH/bin/activate"

python -m pip install --upgrade pip wheel
python -m pip install -r "$TEST_REQUIREMENTS_FILE"

# JUnit + coverage (optional) + verbose failure info
# Remove coverage bits if you don't need them.
pytest \
  "$CONNECTOR_DIR" \
  --junitxml="$OUT_DIR/junit.xml" \
  -q -rA

# Save a plain log too (handy for debugging)
# pytest "$CONNECTOR_DIR" -q -rA | tee "$OUT_DIR/pytest.log"

deactivate || true
rm -rf "$VENV_PATH"

echo "Tests completed for: $CONNECTOR_DIR"
echo "Outputs saved to: $OUT_DIR"
echo "----------------------------------------"
done